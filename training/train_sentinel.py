"""
IMMUNIS ACIN — Sentinel Model Fine-Tuning (Qwen2.5-7B)
========================================================

QLoRA fine-tuning of Qwen2.5-7B-Instruct for threat fingerprinting
and antibody synthesis on AMD MI300X GPUs via ROCm.

WHY: The base Qwen2.5-7B is a general-purpose model. Fine-tuning on
     50K task-specific examples teaches it to output the exact JSON
     schema our pipeline expects, detect threats in 15 languages,
     and classify across 11 attack families with F1 >= 0.92.

Method: QLoRA (Dettmers et al., 2023)
  - 4-bit NF4 quantisation for base weights
  - LoRA rank 64, alpha 128 (alpha/rank = 2x scaling)
  - Target modules: q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj
  - Gradient checkpointing for memory efficiency
  - bf16 mixed precision (MI300X native)

Hardware: AMD Instinct MI300X (192GB HBM3) via ROCm 6.x
Runtime: ~4-6 hours for 50K examples, 3 epochs

Usage:
    python -m training.train_sentinel --data data/training/sentinel_train_split.jsonl
    python -m training.train_sentinel --data data/training/sentinel_train_split.jsonl --epochs 5 --lr 2e-4

References:
  - Dettmers et al. (2023) — QLoRA: Efficient Finetuning of Quantized LLMs
  - Hu et al. (2021) — LoRA: Low-Rank Adaptation of Large Language Models
"""

import os
import json
import logging
import argparse
from pathlib import Path
from typing import Optional

import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, TaskType
from trl import SFTTrainer, SFTConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

BASE_MODEL = "Qwen/Qwen2.5-7B-Instruct"
OUTPUT_DIR = "models/immunis-sentinel"
HF_REPO = "immunis/sentinel-v1"

# QLoRA hyperparameters (Dettmers et al., 2023 recommendations for 7B models)
QLORA_CONFIG = {
    "r": 64,                    # LoRA rank — higher = more capacity, more VRAM
    "lora_alpha": 128,          # Scaling factor — alpha/r = 2x is optimal sweet spot
    "lora_dropout": 0.05,       # Regularisation — low for large datasets
    "target_modules": [         # All linear layers in transformer block
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ],
    "bias": "none",
    "task_type": TaskType.CAUSAL_LM,
}

# 4-bit quantisation config
QUANT_CONFIG = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",          # NormalFloat4 — better than FP4 for LLMs
    bnb_4bit_compute_dtype=torch.bfloat16,  # MI300X native bf16
    bnb_4bit_use_double_quant=True,     # Quantise the quantisation constants
)

# Training hyperparameters
TRAINING_DEFAULTS = {
    "num_train_epochs": 3,
    "per_device_train_batch_size": 4,
    "per_device_eval_batch_size": 4,
    "gradient_accumulation_steps": 8,   # Effective batch = 4 * 8 = 32
    "learning_rate": 1e-4,
    "weight_decay": 0.01,
    "warmup_ratio": 0.03,
    "lr_scheduler_type": "cosine",
    "max_grad_norm": 0.3,              # Gradient clipping for stability
    "logging_steps": 10,
    "save_steps": 500,
    "eval_steps": 500,
    "save_total_limit": 3,
    "bf16": True,                       # MI300X native
    "fp16": False,
    "gradient_checkpointing": True,     # Trade compute for memory
    "optim": "paged_adamw_8bit",        # Memory-efficient optimiser
    "max_seq_length": 2048,             # Covers all our training examples
    "group_by_length": True,            # Batch similar-length sequences
    "report_to": "none",                # Set to "wandb" for experiment tracking
}


# ═════════════════════════════════════════════════════════════════════════════
# DATA LOADING
# ═════════════════════════════════════════════════════════════════════════════

def load_training_data(train_path: str, eval_path: Optional[str] = None):
    """Load JSONL training data into HuggingFace Dataset.

    Expected format per line:
    {"messages": [{"role":"system","content":"..."},{"role":"user","content":"..."},{"role":"assistant","content":"..."}]}
    """
    data_files = {"train": train_path}
    if eval_path and os.path.exists(eval_path):
        data_files["eval"] = eval_path
    elif train_path.endswith("_split.jsonl"):
        # Auto-discover eval split
        eval_auto = train_path.replace("_train_split", "_eval")
        if os.path.exists(eval_auto):
            data_files["eval"] = eval_auto
            logger.info(f"Auto-discovered eval split: {eval_auto}")

    dataset = load_dataset("json", data_files=data_files)

    logger.info(f"Training examples: {len(dataset['train'])}")
    if "eval" in dataset:
        logger.info(f"Eval examples:     {len(dataset['eval'])}")

    return dataset


def format_chat(example, tokenizer):
    """Format a single example using the model's chat template.

    Converts our messages array into the model's expected format:
     """
    text = tokenizer.apply_chat_template(
        example["messages"],
        tokenize=False,
        add_generation_prompt=False,
    )
    return {"text": text}


# ═════════════════════════════════════════════════════════════════════════════
# MODEL SETUP
# ═════════════════════════════════════════════════════════════════════════════

def setup_model_and_tokenizer(model_name: str = BASE_MODEL):
    """Load base model with 4-bit quantisation and prepare for QLoRA.

    Steps:
    1. Load tokenizer with chat template support
    2. Load model in 4-bit NF4 quantisation
    3. Prepare model for k-bit training (freeze base, enable grad for LoRA)
    4. Apply LoRA adapters to target modules
    """
    logger.info(f"Loading base model: {model_name}")

    # Tokenizer
    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        trust_remote_code=True,
        padding_side="right",
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Model with 4-bit quantisation
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=QUANT_CONFIG,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=torch.bfloat16,
        attn_implementation="flash_attention_2",  # If available on ROCm
    )

    # Prepare for QLoRA training
    model = prepare_model_for_kbit_training(
        model,
        use_gradient_checkpointing=True,
    )

    # Apply LoRA
    lora_config = LoraConfig(**QLORA_CONFIG)
    model = get_peft_model(model, lora_config)

    # Log trainable parameters
    trainable, total = model.get_nb_trainable_parameters()
    logger.info(f"Trainable parameters: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")

    return model, tokenizer


# ═════════════════════════════════════════════════════════════════════════════
# TRAINING
# ═════════════════════════════════════════════════════════════════════════════

def train(
    train_path: str,
    eval_path: Optional[str] = None,
    output_dir: str = OUTPUT_DIR,
    model_name: str = BASE_MODEL,
    epochs: int = TRAINING_DEFAULTS["num_train_epochs"],
    batch_size: int = TRAINING_DEFAULTS["per_device_train_batch_size"],
    learning_rate: float = TRAINING_DEFAULTS["learning_rate"],
    max_seq_length: int = TRAINING_DEFAULTS["max_seq_length"],
    push_to_hub: bool = False,
    hub_repo: str = HF_REPO,
):
    """Run QLoRA fine-tuning.

    Args:
        train_path: Path to training JSONL
        eval_path: Optional path to eval JSONL
        output_dir: Where to save the fine-tuned model
        model_name: Base model to fine-tune
        epochs: Number of training epochs
        batch_size: Per-device batch size
        learning_rate: Peak learning rate
        max_seq_length: Maximum sequence length
        push_to_hub: Whether to push to HuggingFace Hub
        hub_repo: HuggingFace repo ID
    """
    logger.info("="*60)
    logger.info("IMMUNIS-Sentinel Fine-Tuning")
    logger.info("="*60)
    logger.info(f"Base model:   {model_name}")
    logger.info(f"Train data:   {train_path}")
    logger.info(f"Output:       {output_dir}")
    logger.info(f"Epochs:       {epochs}")
    logger.info(f"Batch size:   {batch_size} (effective: {batch_size * TRAINING_DEFAULTS['gradient_accumulation_steps']})")
    logger.info(f"LR:           {learning_rate}")
    logger.info(f"Max seq len:  {max_seq_length}")
    logger.info(f"QLoRA:        rank={QLORA_CONFIG['r']}, alpha={QLORA_CONFIG['lora_alpha']}")
    logger.info(f"Quant:        4-bit NF4, double quant, bf16 compute")
    logger.info(f"Device:       {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}")
    logger.info("="*60)

    # Load data
    dataset = load_training_data(train_path, eval_path)

    # Load model + tokenizer
    model, tokenizer = setup_model_and_tokenizer(model_name)

    # Format dataset with chat template
    formatted = dataset.map(
        lambda ex: format_chat(ex, tokenizer),
        remove_columns=dataset["train"].column_names,
    )

    # Training arguments
    training_args = SFTConfig(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=TRAINING_DEFAULTS["per_device_eval_batch_size"],
        gradient_accumulation_steps=TRAINING_DEFAULTS["gradient_accumulation_steps"],
        learning_rate=learning_rate,
        weight_decay=TRAINING_DEFAULTS["weight_decay"],
        warmup_ratio=TRAINING_DEFAULTS["warmup_ratio"],
        lr_scheduler_type=TRAINING_DEFAULTS["lr_scheduler_type"],
        max_grad_norm=TRAINING_DEFAULTS["max_grad_norm"],
        logging_steps=TRAINING_DEFAULTS["logging_steps"],
        save_steps=TRAINING_DEFAULTS["save_steps"],
        eval_steps=TRAINING_DEFAULTS["eval_steps"] if "eval" in dataset else None,
        eval_strategy="steps" if "eval" in dataset else "no",
        save_total_limit=TRAINING_DEFAULTS["save_total_limit"],
        bf16=TRAINING_DEFAULTS["bf16"],
        fp16=TRAINING_DEFAULTS["fp16"],
        gradient_checkpointing=TRAINING_DEFAULTS["gradient_checkpointing"],
        optim=TRAINING_DEFAULTS["optim"],
        max_seq_length=max_seq_length,
        group_by_length=TRAINING_DEFAULTS["group_by_length"],
        report_to=TRAINING_DEFAULTS["report_to"],
        push_to_hub=push_to_hub,
        hub_model_id=hub_repo if push_to_hub else None,
        load_best_model_at_end="eval" in dataset,
        metric_for_best_model="eval_loss" if "eval" in dataset else None,
        dataset_text_field="text",
    )

    # Trainer
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=formatted["train"],
        eval_dataset=formatted.get("eval"),
        tokenizer=tokenizer,
    )

    # Train
    logger.info("Starting training...")
    train_result = trainer.train()

    # Log metrics
    metrics = train_result.metrics
    logger.info(f"Training complete. Loss: {metrics.get('train_loss', 'N/A'):.4f}")
    logger.info(f"Runtime: {metrics.get('train_runtime', 0):.0f}s")
    logger.info(f"Samples/sec: {metrics.get('train_samples_per_second', 0):.1f}")

    # Save
    logger.info(f"Saving model to {output_dir}")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)

    # Save training metrics
    metrics_path = os.path.join(output_dir, "train_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    # Merge LoRA weights if requested (for deployment)
    merged_dir = output_dir + "-merged"
    merge_and_save(model, tokenizer, merged_dir)

    # Push to hub
    if push_to_hub:
        logger.info(f"Pushing to HuggingFace Hub: {hub_repo}")
        trainer.push_to_hub()

    logger.info("="*60)
    logger.info("SENTINEL TRAINING COMPLETE")
    logger.info(f"  Adapter:  {output_dir}")
    logger.info(f"  Merged:   {merged_dir}")
    logger.info(f"  Metrics:  {metrics_path}")
    logger.info("="*60)

    return output_dir


def merge_and_save(model, tokenizer, output_dir: str):
    """Merge LoRA adapters into base model and save for vLLM deployment.

    WHY: vLLM serves full models, not adapters. Merging produces a single
    model directory that vLLM can load directly with:
        vllm serve models/immunis-sentinel-merged --device rocm
    """
    logger.info(f"Merging LoRA weights into base model → {output_dir}")
    try:
        merged_model = model.merge_and_unload()
        merged_model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)
        logger.info(f"Merged model saved: {output_dir}")
    except Exception as e:
        logger.warning(f"Merge failed (can merge manually later): {e}")


# ═════════════════════════════════════════════════════════════════════════════
# vLLM DEPLOYMENT HELPER
# ═════════════════════════════════════════════════════════════════════════════

def print_vllm_command(model_dir: str, port: int = 8080):
    """Print the vLLM launch command for AMD MI300X deployment."""
    cmd = (
        f"vllm serve {model_dir} "
        f"--host 0.0.0.0 --port {port} "
        f"--tensor-parallel-size 1 "
        f"--dtype bfloat16 "
        f"--max-model-len 4096 "
        f"--gpu-memory-utilization 0.90 "
        f"--device rocm"
    )
    logger.info("vLLM deployment command:")
    logger.info(f"  {cmd}")
    return cmd


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="IMMUNIS-Sentinel QLoRA Fine-Tuning")
    parser.add_argument("--data", type=str, required=True,
                        help="Path to training JSONL file")
    parser.add_argument("--eval-data", type=str, default=None,
                        help="Path to eval JSONL (auto-discovered if not set)")
    parser.add_argument("--output", type=str, default=OUTPUT_DIR,
                        help="Output directory for fine-tuned model")
    parser.add_argument("--model", type=str, default=BASE_MODEL,
                        help="Base model to fine-tune")
    parser.add_argument("--epochs", type=int, default=3,
                        help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=4,
                        help="Per-device batch size")
    parser.add_argument("--lr", type=float, default=1e-4,
                        help="Learning rate")
    parser.add_argument("--max-seq-len", type=int, default=2048,
                        help="Maximum sequence length")
    parser.add_argument("--push-to-hub", action="store_true",
                        help="Push model to HuggingFace Hub")
    parser.add_argument("--hub-repo", type=str, default=HF_REPO,
                        help="HuggingFace Hub repository ID")

    args = parser.parse_args()

    output = train(
        train_path=args.data,
        eval_path=args.eval_data,
        output_dir=args.output,
        model_name=args.model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        max_seq_length=args.max_seq_len,
        push_to_hub=args.push_to_hub,
        hub_repo=args.hub_repo,
    )

    print_vllm_command(output + "-merged")


if __name__ == "__main__":
    main()
