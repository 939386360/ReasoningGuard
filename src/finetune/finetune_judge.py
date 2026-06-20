import json
import os
from typing import Optional

"""
Fine-tune Qwen2.5-7B-Instruct as the RTV constrained judge model.

Usage:
    # 1. Build dataset
    python -m src.finetune.judge_dataset

    # 2. Fine-tune (requires 1+ GPU with >=16GB VRAM)
    python -m src.finetune.finetune_judge \
        --data_dir data/judge_finetune \
        --output_dir models/judge_qwen2.5-7b \
        --num_train_epochs 3 \
        --per_device_train_batch_size 4 \
        --gradient_accumulation_steps 4 \
        --learning_rate 2e-5 \
        --max_seq_length 1024 \
        --lora_r 16 \
        --lora_alpha 32

    # 3. Inference with fine-tuned model
    The fine-tuned LoRA adapter is saved to output_dir.
    Use it with:
        from src.judge import LLMJudgeInterface
        judge = LLMJudgeInterface(provider="vllm", model=output_dir)
"""


def finetune_judge(
    data_dir: str = "data/judge_finetune",
    output_dir: str = "models/judge_qwen2.5-7b",
    base_model: str = "Qwen/Qwen2.5-7B-Instruct",
    num_train_epochs: int = 3,
    per_device_train_batch_size: int = 4,
    gradient_accumulation_steps: int = 4,
    learning_rate: float = 2e-5,
    max_seq_length: int = 1024,
    lora_r: int = 16,
    lora_alpha: int = 32,
    lora_dropout: float = 0.05,
    warmup_ratio: float = 0.1,
    weight_decay: float = 0.01,
    logging_steps: int = 10,
    save_steps: int = 100,
    eval_steps: int = 100,
    fp16: bool = True,
    seed: int = 42,
):
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
        from peft import LoraConfig, get_peft_model, TaskType
        from trl import SFTTrainer
    except ImportError as e:
        print(f"Missing dependencies for fine-tuning: {e}")
        print("Install with: pip install torch transformers peft trl datasets accelerate")
        return

    train_path = os.path.join(data_dir, "train.jsonl")
    val_path = os.path.join(data_dir, "val.jsonl")

    if not os.path.exists(train_path):
        print(f"Training data not found at {train_path}")
        print("Run: python -m src.finetune.judge_dataset")
        return

    tokenizer = AutoTokenizer.from_pretrained(
        base_model, trust_remote_code=True, padding_side="right"
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )

    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        bias="none",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    from datasets import Dataset

    def load_jsonl(path):
        with open(path) as f:
            return [json.loads(line) for line in f]

    train_raw = load_jsonl(train_path)
    val_raw = load_jsonl(val_path) if os.path.exists(val_path) else None

    def format_example(example):
        messages = example["messages"]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
        return {"text": text}

    train_dataset = Dataset.from_list(train_raw).map(format_example)
    val_dataset = Dataset.from_list(val_raw).map(format_example) if val_raw else None

    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=num_train_epochs,
        per_device_train_batch_size=per_device_train_batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        learning_rate=learning_rate,
        warmup_ratio=warmup_ratio,
        weight_decay=weight_decay,
        logging_steps=logging_steps,
        save_steps=save_steps,
        eval_strategy="steps" if val_dataset else "no",
        eval_steps=eval_steps if val_dataset else None,
        fp16=fp16,
        gradient_checkpointing=True,
        optim="adamw_torch",
        report_to="none",
        seed=seed,
        remove_unused_columns=False,
    )

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        max_seq_length=max_seq_length,
        tokenizer=tokenizer,
    )

    print(f"Starting fine-tuning: {base_model}")
    print(f"  Train: {len(train_dataset)} samples")
    if val_dataset:
        print(f"  Val: {len(val_dataset)} samples")
    print(f"  LoRA: r={lora_r}, alpha={lora_alpha}, dropout={lora_dropout}")
    print(f"  Epochs: {num_train_epochs}, LR: {learning_rate}")

    trainer.train()

    trainer.save_model(os.path.join(output_dir, "final"))
    tokenizer.save_pretrained(os.path.join(output_dir, "final"))

    if val_dataset:
        metrics = trainer.evaluate()
        print(f"\nEval metrics: {metrics}")
        with open(os.path.join(output_dir, "eval_metrics.json"), "w") as f:
            json.dump(metrics, f, indent=2)

    print(f"\nFine-tuned model saved to {output_dir}/final")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", default="data/judge_finetune")
    parser.add_argument("--output_dir", default="models/judge_qwen2.5-7b")
    parser.add_argument("--base_model", default="Qwen/Qwen2.5-7B-Instruct")
    parser.add_argument("--num_train_epochs", type=int, default=3)
    parser.add_argument("--per_device_train_batch_size", type=int, default=4)
    parser.add_argument("--gradient_accumulation_steps", type=int, default=4)
    parser.add_argument("--learning_rate", type=float, default=2e-5)
    parser.add_argument("--lora_r", type=int, default=16)
    parser.add_argument("--lora_alpha", type=int, default=32)
    args = parser.parse_args()
    finetune_judge(**vars(args))