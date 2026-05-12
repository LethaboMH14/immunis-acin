"""
IMMUNIS ACIN — Vision Model Fine-Tuning (Qwen2-VL-7B)
=======================================================

QLoRA fine-tuning of Qwen2-VL-7B-Instruct for visual threat detection:
  - QR code phishing (malicious URLs in QR codes)
  - Deepfake detection (GAN artifacts, EXIF anomalies)
  - Document forgery (ELA inconsistencies, font mismatches)
  - Steganography (LSB distribution anomalies)
  - Screenshot phishing (brand impersonation, credential harvesting)

WHY: The base Qwen2-VL is a general-purpose vision-language model.
     Fine-tuning on 20K visual threat examples teaches it to identify
     security-specific visual indicators that the base model overlooks:
     FFT frequency artifacts, ELA variance, chi-squared LSB anomalies,
     and brand-specific phishing patterns in South African context.

Method: QLoRA on vision-language adapter
  - 4-bit NF4 quantisation on language backbone
  - LoRA rank 64, alpha 128 on language layers
  - Vision encoder frozen (ViT features transfer well)
  - bf16 mixed precision

Hardware: AMD Instinct MI300X via ROCm 6.x
Runtime: ~3-4 hours for 20K examples, 3 epochs

Usage:
    python -m training.train_vision --data data/training/vision_train_split.jsonl
    python -m training.train_vision --data data/training/vision_train_split.jsonl --epochs 5

References:
  - Wang et al. (2024) — Qwen2-VL: Enhancing Vision-Language Model
  - Dettmers et al. (2023) — QLoRA
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
    AutoProcessor,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, TaskType
from trl import SFTTrainer, SFTConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

BASE_MODEL = "Qwen/Qwen2-VL-7B-Instruct"
OUTPUT_DIR = "models/immunis-vision"
HF_REPO = "immunis/vision-v1"

QLORA_CONFIG = {
    "r": 64,
    "lora_alpha": 128,
    "lora_dropout": 0.05,
    "target_modules": [
        # Language model layers only — vision encoder is frozen
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

TRAINING_DEFAULTS = {
    "num_train_epochs": 3,
    "per_device_train_batch_size": 2,       # Smaller batch for vision (more VRAM)
    "per_device_eval_batch_size": 2,
    "gradient_accumulation_steps": 16,      # Effective batch = 2 * 16 = 32
    "learning_rate": 5e-5,                  # Lower LR for vision-language
    "weight_decay": 0.01,
    "warmup_ratio": 0.05,
    "lr_scheduler_type": "cosine",
    "max_grad_norm": 0.3,
    "logging_steps": 10,
    "save_steps": 500,
    "eval_steps": 500,
    "save_total_limit": 3,
    "bf16": True,
    "fp16": False,
    "gradient_checkpointing": True,
    "optim": "paged_adamw_8bit",
    "max_seq_length": 2048,
    "group_by_length": True,
    "report_to": "none",
}


# ═════════════════════════════════════════════════════════════════════════════
# DATA LOADING
# ═════════════════════════════════════════════════════════════════════════════

def load_vision_data(train_path: str, eval_path: Optional[str] = None):
    """Load vision training data.

    Vision training uses text descriptions of images rather than actual images
    during the text-only fine-tuning phase. This teaches the model the output
    schema and threat classification logic. For full multimodal training,
    pair with actual threat images in a second phase.

    Format per line:
    {"messages": [{"role":"system","content":"..."},{"role":"user","content":"..."},{"role":"assistant","content":"..."}]}
    """
    data_files = {"train": train_path}
    if eval_path and os.path.exists(eval_path):
        data_files["eval"] = eval_path
    else:
        eval_auto = train_path.replace("_train_split", "_eval")
        if os.path.exists(eval_auto):
            data_files["eval"] = eval_auto
            logger.info(f"Auto-discovered eval: {eval_auto}")

    dataset = load_dataset("json", data_files=data_files)
    logger.info(f"Training: {len(dataset['train'])} examples")
    if "eval" in dataset:
        logger.info(f"Eval:     {len(dataset['eval'])} examples")

    return dataset


# ═════════════════════════════════════════════════════════════════════════════
# MODEL SETUP
# ═════════════════════════════════════════════════════════════════════════════

def setup_model(model_name: str = BASE_MODEL):
    """Load Qwen2-VL with QLoRA for vision-language fine-tuning.

    Architecture considerations:
    - Vision encoder (ViT): FROZEN — visual features transfer well and
      the encoder is large. Training it would require much more VRAM.
    - Language model: QLoRA adapters on all linear layers.
    - Cross-attention: Included in LoRA targets via q/k/v_proj.

    This means we're fine-tuning the model's ability to INTERPRET visual
    features for security threats, not its ability to SEE.
    """
    logger.info(f"Loading vision model: {model_name}")

    # Try loading as vision-language model, fall back to standard causal LM
    try:
        from transformers import Qwen2VLForConditionalGeneration
        model = Qwen2VLForConditionalGeneration.from_pretrained(
            model_name,
            quantization_config=QUANT_CONFIG,
            device_map="auto",
            trust_remote_code=True,
            torch_dtype=torch.bfloat16,
        )
        processor = AutoProcessor.from_pretrained(model_name, trust_remote_code=True)
        tokenizer = processor.tokenizer
        logger.info("Loaded as Qwen2-VL (full vision-language)")
    except (ImportError, Exception) as e:
        logger.warning(f"Qwen2-VL specific loader unavailable ({e}), using standard CausalLM")
        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            quantization_config=QUANT_CONFIG,
            device_map="auto",
            trust_remote_code=True,
            torch_dtype=torch.bfloat16,
        )
        tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
        processor = None

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Freeze vision encoder if accessible
    if hasattr(model, "visual"):
        for param in model.visual.parameters():
            param.requires_grad = False
        logger.info("Vision encoder frozen")
    elif hasattr(model, "vision_tower"):
        for param in model.vision_tower.parameters():
            param.requires_grad = False
        logger.info("Vision tower frozen")

    # Prepare for QLoRA
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    lora_config = LoraConfig(**QLORA_CONFIG)
    model = get_peft_model(model, lora_config)

    trainable, total = model.get_nb_trainable_parameters()
    logger.info(f"Trainable: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")

    return model, tokenizer, processor


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
    """Run QLoRA fine-tuning for visual threat detection."""
    logger.info("="*60)
    logger.info("IMMUNIS-Vision Fine-Tuning")
    logger.info("="*60)
    logger.info(f"Base model:   {model_name}")
    logger.info(f"Train data:   {train_path}")
    logger.info(f"Output:       {output_dir}")
    logger.info(f"Epochs:       {epochs}")
    logger.info(f"Batch size:   {batch_size} (effective: {batch_size * TRAINING_DEFAULTS['gradient_accumulation_steps']})")
    logger.info(f"LR:           {learning_rate}")
    logger.info(f"Strategy:     Vision encoder FROZEN, language QLoRA")
    logger.info(f"Device:       {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}")
    logger.info("="*60)

    # Load data
    dataset = load_vision_data(train_path, eval_path)

    # Load model
    model, tokenizer, processor = setup_model(model_name)

    # Format dataset
    formatted = dataset.map(
        lambda ex: {"text": tokenizer.apply_chat_template(
            ex["messages"], tokenize=False, add_generation_prompt=False)},
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
        bf16=True, fp16=False,
        gradient_checkpointing=True,
        optim=TRAINING_DEFAULTS["optim"],
        max_seq_length=max_seq_length,
        group_by_length=True,
        report_to="none",
        push_to_hub=push_to_hub,
        hub_model_id=hub_repo if push_to_hub else None,
        load_best_model_at_end="eval" in dataset,
        dataset_text_field="text",
    )

    # Train
    trainer = SFTTrainer(
        model=model, args=training_args,
        train_dataset=formatted["train"],
        eval_dataset=formatted.get("eval"),
        tokenizer=tokenizer,
    )

    logger.info("Starting vision model training...")
    result = trainer.train()

    metrics = result.metrics
    logger.info(f"Training complete. Loss: {metrics.get('train_loss', 'N/A'):.4f}")
    logger.info(f"Runtime: {metrics.get('train_runtime', 0):.0f}s")

    # Save
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    if processor:
        processor.save_pretrained(output_dir)

    with open(os.path.join(output_dir, "train_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    # Merge for deployment
    merged_dir = output_dir + "-merged"
    try:
        merged = model.merge_and_unload()
        merged.save_pretrained(merged_dir)
        tokenizer.save_pretrained(merged_dir)
        if processor:
            processor.save_pretrained(merged_dir)
        logger.info(f"Merged model: {merged_dir}")
    except Exception as e:
        logger.warning(f"Merge failed: {e}")

    if push_to_hub:
        trainer.push_to_hub()

    logger.info("="*60)
    logger.info("VISION TRAINING COMPLETE")
    logger.info(f"  Adapter:  {output_dir}")
    logger.info(f"  Merged:   {merged_dir}")
    logger.info("="*60)

    # Print vLLM command
    logger.info("vLLM deployment:")
    logger.info(f"  vllm serve {merged_dir} --host 0.0.0.0 --port 8082 "
                f"--dtype bfloat16 --max-model-len 4096 --device rocm")

    return output_dir


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="IMMUNIS-Vision QLoRA Fine-Tuning")
    parser.add_argument("--data", type=str, required=True,
                        help="Path to training JSONL")
    parser.add_argument("--eval-data", type=str, default=None,
                        help="Path to eval JSONL")
    parser.add_argument("--output", type=str, default=OUTPUT_DIR,
                        help="Output directory")
    parser.add_argument("--model", type=str, default=BASE_MODEL,
                        help="Base model")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--lr", type=float, default=5e-5)
    parser.add_argument("--max-seq-len", type=int, default=2048)
    parser.add_argument("--push-to-hub", action="store_true")
    parser.add_argument("--hub-repo", type=str, default=HF_REPO)

    args = parser.parse_args()

    train(
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


if __name__ == "__main__":
    main()
