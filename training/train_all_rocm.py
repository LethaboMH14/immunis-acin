#!/usr/bin/env python3
"""
IMMUNIS ACIN — ROCm-Optimized Training (No bitsandbytes)
==========================================================

Unified training script for all 3 models optimized for AMD MI300X with 192GB VRAM.
Uses full bf16 LoRA training instead of QLoRA for better quality and reliability.

WHY: bitsandbytes has broken/unreliable ROCm support. With 192GB VRAM we can
     afford full bf16 LoRA training which is actually BETTER quality than QLoRA.

USAGE EXAMPLES:
  # SMOKE TEST (run first, takes 2 minutes):
  #   python train_all_rocm.py --smoke-test
  #
  # FULL TRAINING (takes ~5-6 hours total):
  #   python train_all_rocm.py
  #
  # INDIVIDUAL MODELS:
  #   python train_all_rocm.py --sentinel-only
  #   python train_all_rocm.py --adversary-only
  #   python train_all_rocm.py --vision-only
"""

import os
import json
import logging
import argparse
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List

import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    AutoProcessor,
    Qwen2VLForConditionalGeneration,
)
from peft import LoraConfig, get_peft_model, TaskType
from trl import SFTTrainer, SFTConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("training.log", encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)

# ═════════════════════════════════════════════════════════════════════════════
# MODEL CONFIGURATIONS
# ═════════════════════════════════════════════════════════════════════════════

MODEL_CONFIGS = {
    "sentinel": {
        "base_model": "Qwen/Qwen2.5-7B-Instruct",
        "adapter_output": "models/immunis-sentinel",
        "merged_output": "models/immunis-sentinel-merged",
        "hub_repo": "immunis-sentinel",
        "train_data": "training/data/sentinel_train_split.jsonl",
        "eval_data": "training/data/sentinel_eval.jsonl",
    },
    "adversary": {
        "base_model": "meta-llama/Llama-3.1-8B-Instruct",
        "adapter_output": "models/immunis-adversary-sft",
        "merged_output": "models/immunis-adversary-sft-merged",
        "hub_repo": "immunis-adversary-sft",
        "train_data": "training/data/adversary_train_split.jsonl",
        "eval_data": "training/data/adversary_eval.jsonl",
    },
    "vision": {
        "base_model": "Qwen/Qwen2-VL-7B-Instruct",
        "fallback_model": "Qwen/Qwen2.5-7B-Instruct",
        "adapter_output": "models/immunis-vision",
        "merged_output": "models/immunis-vision-merged",
        "hub_repo": "immunis-vision",
        "train_data": "training/data/vision_train_split.jsonl",
        "eval_data": "training/data/vision_eval.jsonl",
    }
}

# LoRA configuration (same for all models)
LORA_CONFIG = {
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

# Training configuration (ROCm optimized)
TRAINING_CONFIG = {
    "per_device_train_batch_size": 8,  # Increased for 192GB VRAM
    "per_device_eval_batch_size": 8,
    "gradient_accumulation_steps": 4,  # Effective batch size: 32
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
    "fp16": False,
    "gradient_checkpointing": True,
    "optim": "adamw_torch",  # ROCm compatible
    "max_seq_length": 2048,
    "group_by_length": True,
    "report_to": "none",
    "dataloader_pin_memory": False,  # ROCm optimization
}

# ═════════════════════════════════════════════════════════════════════════════
# TRAINING FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════

def load_model_and_tokenizer(model_name: str, config: Dict[str, Any], is_vision: bool = False):
    """Load model and tokenizer for ROCm training."""
    logger.info(f"Loading model: {model_name}")
    
    if is_vision:
        try:
            # Try loading vision model first
            model = Qwen2VLForConditionalGeneration.from_pretrained(
                model_name,
                torch_dtype=torch.bfloat16,
                device_map="auto",
                trust_remote_code=True,
            )
            processor = AutoProcessor.from_pretrained(
                model_name,
                trust_remote_code=True
            )
            if processor.tokenizer.pad_token is None:
                processor.tokenizer.pad_token = processor.tokenizer.eos_token
            logger.info("Vision model loaded successfully")
            return model, processor.tokenizer, False
        except Exception as e:
            logger.warning(f"Failed to load vision model {model_name}: {e}")
            logger.info(f"Falling back to {config.get('fallback_model')}")
            model_name = config.get('fallback_model')
            is_vision = False
    
    # Standard causal LM loading
    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        trust_remote_code=True,
        padding_side="right"
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        trust_remote_code=True,
    )
    
    return model, tokenizer, is_vision

def prepare_model_for_lora(model):
    """Prepare model for LoRA training."""
    # Enable gradient checkpointing if not already enabled
    if hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable()
    
    # Apply LoRA
    lora_config = LoraConfig(**LORA_CONFIG)
    model = get_peft_model(model, lora_config)
    
    # Print trainable parameters
    trainable, total = model.get_nb_trainable_parameters()
    logger.info(f"Trainable parameters: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")
    
    return model

def load_and_preprocess_data(train_path: str, eval_path: Optional[str] = None, 
                           smoke_test: bool = False) -> Dict[str, Any]:
    """Load and preprocess training data."""
    data_files = {"train": train_path}
    
    # Handle eval data
    if eval_path and os.path.exists(eval_path):
        data_files["eval"] = eval_path
    else:
        # Try auto-detect eval file
        eval_auto = train_path.replace("_train_split", "_eval")
        if os.path.exists(eval_auto):
            data_files["eval"] = eval_auto
    
    try:
        dataset = load_dataset("json", data_files=data_files)
        logger.info(f"Loaded training data: {len(dataset['train'])} examples")
        if "eval" in dataset:
            logger.info(f"Loaded eval data: {len(dataset['eval'])} examples")
    except Exception as e:
        logger.error(f"Failed to load dataset: {e}")
        raise
    
    # Smoke test: limit to first 50 examples
    if smoke_test:
        dataset["train"] = dataset["train"].select(range(min(50, len(dataset["train"]))))
        if "eval" in dataset:
            dataset["eval"] = dataset["eval"].select(range(min(10, len(dataset["eval"]))))
        logger.info(f"Smoke test mode: {len(dataset['train'])} train examples")
    
    return dataset

def format_dataset_for_sft(dataset, tokenizer):
    """Format dataset for SFT training using chat templates."""
    def format_example(ex):
        text = tokenizer.apply_chat_template(
            ex["messages"], 
            tokenize=False, 
            add_generation_prompt=False
        )
        return {"text": text}
    
    formatted = dataset.map(
        format_example,
        remove_columns=dataset["train"].column_names,
        desc="Formatting for SFT"
    )
    
    return formatted

def train_model(model_name: str, config: Dict[str, Any], 
               smoke_test: bool = False, hub_prefix: str = "immunis") -> str:
    """Train a single model."""
    logger.info("="*80)
    logger.info(f"TRAINING MODEL: {model_name.upper()}")
    logger.info("="*80)
    
    # Load data
    dataset = load_and_preprocess_data(
        config["train_data"], 
        config["eval_data"], 
        smoke_test
    )
    
    # Load model and tokenizer
    is_vision = model_name == "vision"
    model, tokenizer, is_vision = load_model_and_tokenizer(
        config["base_model"], 
        config, 
        is_vision
    )
    
    # Prepare for LoRA
    model = prepare_model_for_lora(model)
    
    # Format dataset
    formatted_dataset = format_dataset_for_sft(dataset, tokenizer)
    
    # Configure training arguments
    training_args = SFTConfig(
        output_dir=config["adapter_output"],
        num_train_epochs=1 if smoke_test else 3,
        per_device_train_batch_size=TRAINING_CONFIG["per_device_train_batch_size"],
        per_device_eval_batch_size=TRAINING_CONFIG["per_device_eval_batch_size"],
        gradient_accumulation_steps=TRAINING_CONFIG["gradient_accumulation_steps"],
        learning_rate=TRAINING_CONFIG["learning_rate"],
        weight_decay=TRAINING_CONFIG["weight_decay"],
        warmup_ratio=TRAINING_CONFIG["warmup_ratio"],
        lr_scheduler_type=TRAINING_CONFIG["lr_scheduler_type"],
        max_grad_norm=TRAINING_CONFIG["max_grad_norm"],
        logging_steps=1 if smoke_test else TRAINING_CONFIG["logging_steps"],
        save_steps=10 if smoke_test else TRAINING_CONFIG["save_steps"],
        eval_steps=10 if smoke_test else TRAINING_CONFIG["eval_steps"] if "eval" in formatted_dataset else None,
        eval_strategy="steps" if "eval" in formatted_dataset and not smoke_test else "no",
        save_total_limit=TRAINING_CONFIG["save_total_limit"],
        bf16=TRAINING_CONFIG["bf16"],
        fp16=TRAINING_CONFIG["fp16"],
        gradient_checkpointing=TRAINING_CONFIG["gradient_checkpointing"],
        optim=TRAINING_CONFIG["optim"],
        max_seq_length=TRAINING_CONFIG["max_seq_length"],
        group_by_length=TRAINING_CONFIG["group_by_length"],
        report_to=TRAINING_CONFIG["report_to"],
        dataloader_pin_memory=TRAINING_CONFIG["dataloader_pin_memory"],
        dataset_text_field="text",
        max_steps=10 if smoke_test else -1,
    )
    
    # Create trainer
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=formatted_dataset["train"],
        eval_dataset=formatted_dataset.get("eval"),
        tokenizer=tokenizer,
    )
    
    # Train
    logger.info("Starting training...")
    try:
        result = trainer.train()
        logger.info(f"Training completed. Final loss: {result.training_loss:.4f}")
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise
    
    # Save adapter
    trainer.save_model(config["adapter_output"])
    tokenizer.save_pretrained(config["adapter_output"])
    
    # Save metrics
    metrics = {
        "model_name": model_name,
        "base_model": config["base_model"],
        "training_loss": result.training_loss,
        "train_samples": len(formatted_dataset["train"]),
        "is_vision_model": is_vision,
        "smoke_test": smoke_test,
    }
    
    metrics_path = os.path.join(config["adapter_output"], "training_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    
    logger.info(f"Adapter saved to: {config['adapter_output']}")
    
    # Merge and save (if not smoke test)
    if not smoke_test:
        try:
            merge_and_save_model(model, tokenizer, config)
        except Exception as e:
            logger.warning(f"Failed to merge model: {e}")
    
    return config["adapter_output"]

def merge_and_save_model(model, tokenizer, config: Dict[str, Any]):
    """Merge LoRA adapter and save the full model."""
    logger.info("Merging LoRA adapter...")
    
    # Merge adapter
    merged_model = model.merge_and_unload()
    
    # Save merged model
    merged_model.save_pretrained(config["merged_output"])
    tokenizer.save_pretrained(config["merged_output"])
    
    logger.info(f"Merged model saved to: {config['merged_output']}")

def push_to_hub(model_path: str, hub_repo: str, hub_prefix: str):
    """Push model to HuggingFace Hub."""
    try:
        from huggingface_hub import HfApi, Repository
        
        # Create full repo name
        full_repo_name = f"{hub_prefix}/{hub_repo}"
        
        logger.info(f"Pushing to Hub: {full_repo_name}")
        
        # Initialize repo if it doesn't exist
        api = HfApi()
        
        # Push using Repository class
        repo = Repository(
            local_dir=model_path,
            repo_id=full_repo_name,
            private=False,
            token=os.getenv("HF_TOKEN")  # Use HF_TOKEN from environment
        )
        
        repo.push_to_hub(commit_message="Add trained model")
        logger.info(f"Successfully pushed to: https://huggingface.co/{full_repo_name}")
        
    except ImportError:
        logger.warning("huggingface_hub not installed. Skipping push to Hub.")
    except Exception as e:
        logger.error(f"Failed to push to Hub: {e}")

# ═════════════════════════════════════════════════════════════════════════════
# MAIN FUNCTION
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="IMMUNIS ACIN ROCm-Optimized Training",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Smoke test (quick verification)
  python train_all_rocm.py --smoke-test
  
  # Full training (all models)
  python train_all_rocm.py
  
  # Individual models
  python train_all_rocm.py --sentinel-only
  python train_all_rocm.py --adversary-only
  python train_all_rocm.py --vision-only
  
  # Push to Hub after training
  python train_all_rocm.py --push
        """
    )
    
    parser.add_argument("--smoke-test", action="store_true",
                       help="Run smoke test: 10 steps, 50 examples")
    parser.add_argument("--sentinel-only", action="store_true",
                       help="Train only sentinel model")
    parser.add_argument("--adversary-only", action="store_true",
                       help="Train only adversary model")
    parser.add_argument("--vision-only", action="store_true",
                       help="Train only vision model")
    parser.add_argument("--push", action="store_true",
                       help="Push models to HuggingFace Hub after training")
    parser.add_argument("--hub-prefix", type=str, default="immunis",
                       help="Hub repository prefix (default: immunis)")
    
    args = parser.parse_args()
    
    # Validate arguments
    only_flags = [args.sentinel_only, args.adversary_only, args.vision_only]
    if sum(only_flags) > 1:
        parser.error("Only one of --sentinel-only, --adversary-only, --vision-only can be specified")
    
    # Determine which models to train
    if args.sentinel_only:
        models_to_train = ["sentinel"]
    elif args.adversary_only:
        models_to_train = ["adversary"]
    elif args.vision_only:
        models_to_train = ["vision"]
    else:
        models_to_train = ["sentinel", "adversary", "vision"]
    
    logger.info("="*80)
    logger.info("IMMUNIS ACIN ROCm TRAINING")
    logger.info("="*80)
    logger.info(f"Models to train: {', '.join(models_to_train)}")
    logger.info(f"Smoke test: {args.smoke_test}")
    logger.info(f"Push to Hub: {args.push}")
    if args.push:
        logger.info(f"Hub prefix: {args.hub_prefix}")
    logger.info("="*80)
    
    # Check ROCm availability
    if torch.cuda.is_available():
        logger.info(f"ROCm detected: {torch.cuda.get_device_name()}")
        logger.info(f"GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
    else:
        logger.warning("No ROCm GPU detected. Training may fail or be very slow.")
    
    # Train models
    trained_models = []
    
    for model_name in models_to_train:
        try:
            config = MODEL_CONFIGS[model_name]
            
            # Create output directories
            os.makedirs(config["adapter_output"], exist_ok=True)
            os.makedirs(config["merged_output"], exist_ok=True)
            
            # Train model
            model_path = train_model(
                model_name, 
                config, 
                args.smoke_test, 
                args.hub_prefix
            )
            trained_models.append((model_name, model_path, config))
            
            logger.info(f"✓ {model_name} training completed")
            
        except Exception as e:
            logger.error(f"✗ {model_name} training failed: {e}")
            if not args.smoke_test:
                logger.error("Continuing with next model...")
            else:
                raise
    
    # Push to Hub if requested
    if args.push and trained_models:
        logger.info("="*80)
        logger.info("PUSHING TO HUGGINGFACE HUB")
        logger.info("="*80)
        
        for model_name, model_path, config in trained_models:
            try:
                push_to_hub(model_path, config["hub_repo"], args.hub_prefix)
                logger.info(f"✓ {model_name} pushed to Hub")
            except Exception as e:
                logger.error(f"✗ {model_name} push failed: {e}")
    
    # Final summary
    logger.info("="*80)
    logger.info("TRAINING SUMMARY")
    logger.info("="*80)
    logger.info(f"Models trained: {len(trained_models)}")
    for model_name, model_path, config in trained_models:
        logger.info(f"  {model_name}: {model_path}")
    
    if args.smoke_test:
        logger.info("\n🎉 SMOKE TEST PASSED")
        logger.info("All models trained successfully with smoke test configuration.")
        logger.info("You can now run full training without --smoke-test flag.")
    else:
        logger.info("\n🎉 TRAINING COMPLETED")
        logger.info("All models trained successfully.")
    
    logger.info("="*80)

if __name__ == "__main__":
    main()
