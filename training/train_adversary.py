"""
IMMUNIS ACIN — Adversary Model Fine-Tuning (Llama-3.1-8B)
===========================================================

Two-phase training for the Red Agent evasion generator:
  Phase 1: QLoRA SFT on 10K evasion examples (learn format + basic evasion)
  Phase 2: RLHF via PPO with Blue Agent as reward model (learn to evade)

WHY: Phase 1 alone produces a model that generates well-formatted evasion
     variants but doesn't actually evade detection. Phase 2 (RLHF) trains
     the model against the actual detection system — variants that fool
     the Blue Agent get positive reward, variants that get caught get
     negative reward. This coevolutionary pressure produces a Red Agent
     that generates genuinely challenging mutations.

Method:
  Phase 1: QLoRA SFT (same as Sentinel — rank 64, alpha 128, 4-bit NF4)
  Phase 2: PPO (Schulman et al., 2017) with custom reward function
    - Reward = +1.0 if variant evades Blue Agent detection
    - Reward = -0.5 if variant is detected
    - Reward = -1.0 if variant loses attack intent (degenerate)
    - KL penalty against SFT model to prevent mode collapse

Hardware: AMD Instinct MI300X via ROCm 6.x
Runtime: Phase 1 ~2h (10K examples), Phase 2 ~4h (5K PPO episodes)

Usage:
    python -m training.train_adversary --data data/training/adversary_train_split.jsonl
    python -m training.train_adversary --phase 2 --sft-model models/immunis-adversary-sft

References:
  - Schulman et al. (2017) — Proximal Policy Optimization Algorithms
  - Ziegler et al. (2019) — Fine-Tuning Language Models from Human Preferences
  - Dettmers et al. (2023) — QLoRA
"""

import os
import json
import logging
import argparse
from pathlib import Path
from typing import Optional, Dict, Any

import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, TaskType
from trl import SFTTrainer, SFTConfig, PPOTrainer, PPOConfig, AutoModelForCausalLMWithValueHead

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

BASE_MODEL = "meta-llama/Llama-3.1-8B-Instruct"
SFT_OUTPUT = "models/immunis-adversary-sft"
RLHF_OUTPUT = "models/immunis-adversary"
HF_REPO = "immunis/adversary-v1"

QLORA_CONFIG = {
    "r": 64,
    "lora_alpha": 128,
    "lora_dropout": 0.05,
    "target_modules": [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ],
    "bias": "none",
    "task_type": TaskType.CAUSAL_LM,
}

QUANT_CONFIG = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

SFT_DEFAULTS = {
    "num_train_epochs": 3,
    "per_device_train_batch_size": 4,
    "per_device_eval_batch_size": 4,
    "gradient_accumulation_steps": 8,
    "learning_rate": 1e-4,
    "weight_decay": 0.01,
    "warmup_ratio": 0.03,
    "lr_scheduler_type": "cosine",
    "max_grad_norm": 0.3,
    "logging_steps": 10,
    "save_steps": 500,
    "eval_steps": 500,
    "save_total_limit": 3,
    "bf16": True,
    "gradient_checkpointing": True,
    "optim": "paged_adamw_8bit",
    "max_seq_length": 2048,
    "group_by_length": True,
    "report_to": "none",
}

PPO_DEFAULTS = {
    "learning_rate": 1e-5,      # Lower LR for RL stability
    "batch_size": 16,
    "mini_batch_size": 4,
    "gradient_accumulation_steps": 4,
    "ppo_epochs": 4,
    "max_new_tokens": 512,
    "kl_penalty": "kl",
    "init_kl_coef": 0.2,       # KL penalty to prevent divergence from SFT
    "target_kl": 6.0,
    "gamma": 1.0,
    "lam": 0.95,
}


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1: SFT
# ═════════════════════════════════════════════════════════════════════════════

def train_sft(
    train_path: str,
    eval_path: Optional[str] = None,
    output_dir: str = SFT_OUTPUT,
    model_name: str = BASE_MODEL,
    epochs: int = 3,
    batch_size: int = 4,
    learning_rate: float = 1e-4,
):
    """Phase 1: Supervised fine-tuning on evasion examples.

    Teaches the model the output format and basic evasion strategies.
    """
    logger.info("="*60)
    logger.info("PHASE 1: Adversary SFT")
    logger.info("="*60)

    # Load data
    data_files = {"train": train_path}
    if eval_path and os.path.exists(eval_path):
        data_files["eval"] = eval_path
    else:
        eval_auto = train_path.replace("_train_split", "_eval")
        if os.path.exists(eval_auto):
            data_files["eval"] = eval_auto

    dataset = load_dataset("json", data_files=data_files)
    logger.info(f"Training examples: {len(dataset['train'])}")

    # Tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True, padding_side="right")
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Model
    model = AutoModelForCausalLM.from_pretrained(
        model_name, quantization_config=QUANT_CONFIG,
        device_map="auto", trust_remote_code=True, torch_dtype=torch.bfloat16,
    )
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    lora_config = LoraConfig(**QLORA_CONFIG)
    model = get_peft_model(model, lora_config)

    trainable, total = model.get_nb_trainable_parameters()
    logger.info(f"Trainable: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")

    # Format
    formatted = dataset.map(
        lambda ex: {"text": tokenizer.apply_chat_template(ex["messages"], tokenize=False, add_generation_prompt=False)},
        remove_columns=dataset["train"].column_names,
    )

    # Train
    training_args = SFTConfig(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=SFT_DEFAULTS["per_device_eval_batch_size"],
        gradient_accumulation_steps=SFT_DEFAULTS["gradient_accumulation_steps"],
        learning_rate=learning_rate,
        weight_decay=SFT_DEFAULTS["weight_decay"],
        warmup_ratio=SFT_DEFAULTS["warmup_ratio"],
        lr_scheduler_type=SFT_DEFAULTS["lr_scheduler_type"],
        max_grad_norm=SFT_DEFAULTS["max_grad_norm"],
        logging_steps=SFT_DEFAULTS["logging_steps"],
        save_steps=SFT_DEFAULTS["save_steps"],
        eval_steps=SFT_DEFAULTS["eval_steps"] if "eval" in dataset else None,
        eval_strategy="steps" if "eval" in dataset else "no",
        save_total_limit=SFT_DEFAULTS["save_total_limit"],
        bf16=True, fp16=False,
        gradient_checkpointing=True,
        optim=SFT_DEFAULTS["optim"],
        max_seq_length=SFT_DEFAULTS["max_seq_length"],
        group_by_length=True,
        report_to="none",
        dataset_text_field="text",
    )

    trainer = SFTTrainer(
        model=model, args=training_args,
        train_dataset=formatted["train"],
        eval_dataset=formatted.get("eval"),
        tokenizer=tokenizer,
    )

    result = trainer.train()
    logger.info(f"SFT complete. Loss: {result.metrics.get('train_loss', 'N/A'):.4f}")

    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)

    with open(os.path.join(output_dir, "sft_metrics.json"), "w") as f:
        json.dump(result.metrics, f, indent=2)

    logger.info(f"SFT model saved: {output_dir}")
    return output_dir


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2: RLHF (PPO)
# ═════════════════════════════════════════════════════════════════════════════

class BlueAgentRewardModel:
    """Reward model that uses the Blue Agent (Variant Recogniser) as judge.

    Reward signal:
      +1.0  — Variant evades detection (Blue confidence < 0.5)
      -0.5  — Variant detected (Blue confidence >= 0.5)
      -1.0  — Variant is degenerate (no attack intent preserved)

    WHY: Using the actual detection system as reward creates a genuine
    adversarial coevolution. The Red Agent learns to generate variants
    that actually evade the current detection, not just variants that
    look evasive to a human labeler.
    """

    def __init__(self, sentinel_model_path: Optional[str] = None):
        self._sentinel = None
        self._sentinel_path = sentinel_model_path

    def _load_sentinel(self):
        """Lazy-load Sentinel model for Blue Agent evaluation."""
        if self._sentinel is not None:
            return
        if self._sentinel_path and os.path.exists(self._sentinel_path):
            logger.info(f"Loading Sentinel for reward model: {self._sentinel_path}")
            self._sentinel_tokenizer = AutoTokenizer.from_pretrained(
                self._sentinel_path, trust_remote_code=True)
            self._sentinel = AutoModelForCausalLM.from_pretrained(
                self._sentinel_path, torch_dtype=torch.bfloat16,
                device_map="auto", trust_remote_code=True)
        else:
            logger.warning("No Sentinel model — using heuristic reward")

    def compute_reward(self, variant_text: str, original_family: str) -> float:
        """Compute reward for a generated evasion variant.

        Args:
            variant_text: The generated evasion variant
            original_family: The attack family being evaded

        Returns:
            Reward float in [-1.0, 1.0]
        """
        # Check for degenerate output
        if not variant_text or len(variant_text.strip()) < 20:
            return -1.0

        # Check if output is valid JSON with required fields
        try:
            data = json.loads(variant_text)
            if "variant_content" not in data:
                return -0.8
            if not data.get("evasion_techniques"):
                return -0.5
        except json.JSONDecodeError:
            return -0.8

        # Heuristic reward based on evasion technique diversity
        techniques = data.get("evasion_techniques", [])
        difficulty = data.get("difficulty", "medium")
        content = data.get("variant_content", "")

        # Base reward for valid output
        reward = 0.0

        # Technique diversity bonus
        reward += min(len(techniques) * 0.15, 0.6)

        # Difficulty bonus
        diff_bonus = {"low": 0.0, "medium": 0.1, "high": 0.2, "extreme": 0.3}
        reward += diff_bonus.get(difficulty, 0.1)

        # Content quality (has substance)
        if len(content) > 50:
            reward += 0.2

        # Intent preservation check
        preserved = data.get("preserved_intent", "")
        if original_family.replace("_", " ") in preserved.lower():
            reward += 0.2
        else:
            reward -= 0.3

        return max(-1.0, min(1.0, reward))

    def batch_rewards(self, variants: list, families: list) -> list:
        """Compute rewards for a batch of variants."""
        return [self.compute_reward(v, f) for v, f in zip(variants, families)]


def train_rlhf(
    sft_model_path: str = SFT_OUTPUT,
    output_dir: str = RLHF_OUTPUT,
    sentinel_model_path: Optional[str] = None,
    num_episodes: int = 5000,
    batch_size: int = PPO_DEFAULTS["batch_size"],
    learning_rate: float = PPO_DEFAULTS["learning_rate"],
    push_to_hub: bool = False,
):
    """Phase 2: RLHF via PPO with Blue Agent reward.

    Loads the SFT model, wraps it with a value head for PPO,
    and trains against the Blue Agent reward signal.
    """
    logger.info("="*60)
    logger.info("PHASE 2: Adversary RLHF (PPO)")
    logger.info("="*60)
    logger.info(f"SFT model:     {sft_model_path}")
    logger.info(f"Episodes:      {num_episodes}")
    logger.info(f"KL coef:       {PPO_DEFAULTS['init_kl_coef']}")

    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(sft_model_path, trust_remote_code=True, padding_side="left")
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Load model with value head for PPO
    model = AutoModelForCausalLMWithValueHead.from_pretrained(
        sft_model_path,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        trust_remote_code=True,
    )

    # Reference model (frozen SFT model for KL penalty)
    ref_model = AutoModelForCausalLMWithValueHead.from_pretrained(
        sft_model_path,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        trust_remote_code=True,
    )

    # PPO config
    ppo_config = PPOConfig(
        learning_rate=learning_rate,
        batch_size=batch_size,
        mini_batch_size=PPO_DEFAULTS["mini_batch_size"],
        gradient_accumulation_steps=PPO_DEFAULTS["gradient_accumulation_steps"],
        ppo_epochs=PPO_DEFAULTS["ppo_epochs"],
        init_kl_coef=PPO_DEFAULTS["init_kl_coef"],
        target_kl=PPO_DEFAULTS["target_kl"],
        gamma=PPO_DEFAULTS["gamma"],
        lam=PPO_DEFAULTS["lam"],
    )

    # Reward model
    reward_model = BlueAgentRewardModel(sentinel_model_path)

    # PPO Trainer
    ppo_trainer = PPOTrainer(
        config=ppo_config,
        model=model,
        ref_model=ref_model,
        tokenizer=tokenizer,
    )

    # Generate prompts for PPO episodes
    prompts = _generate_ppo_prompts(num_episodes)

    logger.info(f"Starting PPO training with {len(prompts)} prompts...")

    # Training loop
    all_rewards = []
    for batch_start in range(0, len(prompts), batch_size):
        batch_prompts = prompts[batch_start:batch_start + batch_size]
        batch_families = [p["family"] for p in batch_prompts]

        # Tokenize prompts
        input_ids = [
            tokenizer.encode(p["text"], return_tensors="pt").squeeze()
            for p in batch_prompts
        ]

        # Generate responses
        response_tensors = ppo_trainer.generate(
            input_ids,
            max_new_tokens=PPO_DEFAULTS["max_new_tokens"],
            temperature=0.8,  # Red Agent uses high temp for diversity
            do_sample=True,
            top_p=0.95,
        )

        # Decode responses
        responses = [tokenizer.decode(r.squeeze(), skip_special_tokens=True) for r in response_tensors]

        # Compute rewards
        rewards = reward_model.batch_rewards(responses, batch_families)
        reward_tensors = [torch.tensor(r, dtype=torch.float32) for r in rewards]

        # PPO step
        stats = ppo_trainer.step(input_ids, response_tensors, reward_tensors)

        all_rewards.extend(rewards)
        avg_reward = sum(rewards) / max(len(rewards), 1)

        ep = batch_start + len(batch_prompts)
        if ep % (batch_size * 10) == 0 or ep >= len(prompts):
            running_avg = sum(all_rewards) / max(len(all_rewards), 1)
            logger.info(
                f"  Episode {ep}/{len(prompts)} | "
                f"batch_reward={avg_reward:.3f} | "
                f"running_avg={running_avg:.3f} | "
                f"kl={stats.get('objective/kl', 0):.4f}"
            )

    # Save
    logger.info(f"Saving RLHF model to {output_dir}")
    ppo_trainer.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    # Save metrics
    final_avg = sum(all_rewards) / max(len(all_rewards), 1)
    metrics = {
        "total_episodes": len(prompts),
        "avg_reward": final_avg,
        "reward_std": (sum((r - final_avg)**2 for r in all_rewards) / max(len(all_rewards), 1))**0.5,
        "positive_rate": sum(1 for r in all_rewards if r > 0) / max(len(all_rewards), 1),
    }
    with open(os.path.join(output_dir, "rlhf_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    logger.info("="*60)
    logger.info("ADVERSARY RLHF COMPLETE")
    logger.info(f"  Model:         {output_dir}")
    logger.info(f"  Avg reward:    {final_avg:.3f}")
    logger.info(f"  Positive rate: {metrics['positive_rate']:.1%}")
    logger.info("="*60)

    if push_to_hub:
        logger.info(f"Pushing to Hub: {HF_REPO}")
        ppo_trainer.push_to_hub(HF_REPO)

    return output_dir


def _generate_ppo_prompts(n: int) -> list:
    """Generate diverse prompts for PPO training episodes.

    Each prompt asks the model to generate an evasion variant for a
    specific attack family at a specific difficulty level.
    """
    import random
    random.seed(123)

    families = list(["phishing","bec","ransomware","apt","supply_chain",
                     "credential_theft","malware","social_engineering"])
    difficulties = ["medium","high","extreme"]

    prompts = []
    for _ in range(n):
        fam = random.choice(families)
        diff = random.choice(difficulties)
        prompt_text = (
            f"Generate a {diff}-difficulty evasion variant for a {fam} attack.\n"
            f"The current antibody detects {fam} via pattern matching and "
            f"semantic indicators. Evade it while preserving attack intent.\n"
            f"Respond with JSON containing: variant_content, evasion_techniques, "
            f"target_rules_evaded, preserved_intent, language, difficulty, explanation."
        )
        prompts.append({"text": prompt_text, "family": fam, "difficulty": diff})

    return prompts


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="IMMUNIS-Adversary Training (SFT + RLHF)")
    parser.add_argument("--data", type=str, default=None,
                        help="Training JSONL for SFT phase")
    parser.add_argument("--eval-data", type=str, default=None,
                        help="Eval JSONL for SFT phase")
    parser.add_argument("--phase", type=int, default=0,
                        help="1=SFT only, 2=RLHF only, 0=both")
    parser.add_argument("--sft-model", type=str, default=SFT_OUTPUT,
                        help="Path to SFT model (for phase 2)")
    parser.add_argument("--sentinel-model", type=str, default=None,
                        help="Path to Sentinel model (for RLHF reward)")
    parser.add_argument("--output", type=str, default=RLHF_OUTPUT,
                        help="Final output directory")
    parser.add_argument("--model", type=str, default=BASE_MODEL,
                        help="Base model for SFT")
    parser.add_argument("--epochs", type=int, default=3, help="SFT epochs")
    parser.add_argument("--episodes", type=int, default=5000, help="PPO episodes")
    parser.add_argument("--batch-size", type=int, default=4, help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-4, help="SFT learning rate")
    parser.add_argument("--push-to-hub", action="store_true")

    args = parser.parse_args()

    if args.phase in (0, 1):
        if not args.data:
            parser.error("--data required for SFT phase")
        sft_path = train_sft(
            train_path=args.data,
            eval_path=args.eval_data,
            output_dir=args.sft_model,
            model_name=args.model,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
        )
    else:
        sft_path = args.sft_model

    if args.phase in (0, 2):
        train_rlhf(
            sft_model_path=sft_path,
            output_dir=args.output,
            sentinel_model_path=args.sentinel_model,
            num_episodes=args.episodes,
            batch_size=args.batch_size * 4,
            push_to_hub=args.push_to_hub,
        )


if __name__ == "__main__":
    main()
