#!/bin/bash

#SBATCH --job-name=table1
#SBATCH --output=/home/liuenguang24/ReasoningGuard/experiments/slurm_log/table1_info_%j.txt
#SBATCH --error=/home/liuenguang24/ReasoningGuard/experiments/slurm_log/table1_errors_%j.txt
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=16G
#SBATCH --time=24:00:00
#SBATCH --partition=a800
#SBATCH --nodelist=aias-compute-6
#SBATCH --qos=a800
# 申请 1 个 GPU; 例如使用--gres=gpu:1 来申请两个或者更多 GPU
#SBATCH --gres=gpu:1

export TRANSFORMERS_OFFLINE=1
export LLM_API_KEY='sk-SOUUDaXFECoK4psw4WC1Zm3hZcUuPX2oNjmP0Lp9ZgThnbl0'

cd /home/liuenguang24/ReasoningGuard

# 回退，不抛异常
srun python experiments/run_quick_benchmark_by_category.py \
  --benchmark mcptox \
  --per_category 5 \
  --max_scenarios 200 \
  --runs 3 \
  --seed 42 \
  --data_dir data/mcptox \
  --model GPT-4o \
  --agent_backend proxy \
  --agent_base_url "https://llm-api.net/v1/chat/completions" \
  --agent_api_style chat \
  --agent_api_key_env LLM_API_KEY \
  --agent_model_map '{"GPT-4o":"gpt-4o"}' \
  --agent_timeout 60 \
  --judge_mode llm \
  --judge_provider vllm \
  --judge_model qwen2.5-7B-Instruct \
  --judge_base_url "http://aias-compute-2:14545/v1/chat/completions" \
  --judge_failure_policy inherit \
  --llamaguard_model "/home/liuenguang24/models/Llama-Guard-3-8B" \
  --llamaguard_device auto \
  --llamaguard_fail_fast \
  --benign_ratio 0.30 \
  --audit_log "results/0624_run2_5case/table1_gpt4o_qwen_judge_audit.jsonl" \
  --output "results/0624_run2_5case/table1_gpt4o_qwen_judge_results.json" \
  --tex_output "results/0624_run2_5case/table1_gpt4o_qwen_judge.tex" \
  --records_output "results/0624_run2_5case/table1_gpt4o_qwen_judge_records.json"