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
export PTG_EMBEDDING_MODEL="/home/liuenguang24/models/paraphrase-multilingual-MiniLM-L12-v2"
export PTG_EMBEDDING_THRESHOLD="0.45"
export LLM_API_KEY='sk-SOUUDaXFECoK4psw4WC1Zm3hZcUuPX2oNjmP0Lp9ZgThnbl0'

: "${LLM_API_KEY:?Set LLM_API_KEY in the job environment}"

echo "PTG embedding model: ${PTG_EMBEDDING_MODEL}"
echo "PTG embedding threshold: ${PTG_EMBEDDING_THRESHOLD}"
echo "WARNING: PTG_EMBEDDING_THRESHOLD=0.45 is provisional; this run is for smoke/diagnostic use until the threshold is independently calibrated." >&2

EFFECT_ARGS=()
if [[ -n "${MALICIOUS_EFFECT_SIDECAR:-}" ]]; then
  EFFECT_ARGS+=(--effect_sidecar "${MALICIOUS_EFFECT_SIDECAR}")
  echo "Effect source: reviewed sidecar (${MALICIOUS_EFFECT_SIDECAR})"
else
  echo "Effect source: derived from curated benign/malicious calls"
fi

RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
OUTPUT_DIR="results/table1_${RUN_ID}"
if [[ -e "${OUTPUT_DIR}" ]]; then
  echo "Refusing to overwrite existing output directory: ${OUTPUT_DIR}" >&2
  exit 1
fi
mkdir -p "${OUTPUT_DIR}"

cd /home/liuenguang24/ReasoningGuard

python experiments/run_quick_benchmark_by_category.py \
  --benchmark mcptox \
  --official \
  --official_variant curated \
  --categories 'tool_description_poisoning,parameter_injection,response_manipulation,capability_escalation' \
  --per_category 55 \
  --max_scenarios 200 \
  --runs 3 \
  --seed 42 \
  --data_dir data/mcptox \
  --model GPT-4o \
  --agent_backend proxy \
  --agent_base_url https://llm-api.net/v1/chat/completions \
  --agent_api_style chat \
  --agent_api_key_env LLM_API_KEY \
  --agent_model_map '{"GPT-4o":"gpt-4o"}' \
  --agent_timeout 60 \
  --judge_mode llm \
  --judge_provider vllm \
  --judge_model qwen2.5-7B-Instruct \
  --judge_base_url http://aias-compute-2:14545/v1/chat/completions \
  --llamaguard_model /home/liuenguang24/models/Llama-Guard-3-8B \
  --llamaguard_device auto \
  --llamaguard_fail_fast \
  --ptg_embedding_model "${PTG_EMBEDDING_MODEL}" \
  --ptg_embedding_device auto \
  --ptg_embedding_threshold "${PTG_EMBEDDING_THRESHOLD}" \
  --ptg_embedding_fail_fast \
  "${EFFECT_ARGS[@]}" \
  --strict_runtime \
  --judge_failure_policy record_invalid \
  --benign_ratio 0.30 \
  --audit_log "${OUTPUT_DIR}/table1_gpt4o_qwen_judge_audit.jsonl" \
  --output "${OUTPUT_DIR}/table1_gpt4o_qwen_judge_results.json" \
  --tex_output "${OUTPUT_DIR}/table1_gpt4o_qwen_judge.tex" \
  --records_output "${OUTPUT_DIR}/table1_gpt4o_qwen_judge_records.json"

# # 回退，不抛异常
# srun python experiments/run_quick_benchmark_by_category.py \
#   --benchmark mcptox \
#   --per_category 5 \
#   --max_scenarios 200 \
#   --runs 3 \
#   --seed 42 \
#   --data_dir data/mcptox \
#   --model GPT-4o \
#   --agent_backend proxy \
#   --agent_base_url "https://llm-api.net/v1/chat/completions" \
#   --agent_api_style chat \
#   --agent_api_key_env LLM_API_KEY \
#   --agent_model_map '{"GPT-4o":"gpt-4o"}' \
#   --agent_timeout 60 \
#   --judge_mode llm \
#   --judge_provider vllm \
#   --judge_model qwen2.5-7B-Instruct \
#   --judge_base_url "http://aias-compute-2:14545/v1/chat/completions" \
#   --judge_failure_policy record_invalid \
#   --llamaguard_model "/home/liuenguang24/models/Llama-Guard-3-8B" \
#   --llamaguard_device auto \
#   --llamaguard_fail_fast \
#   --benign_ratio 0.30 \
#   --audit_log "results/0624_run2_5case/table1_gpt4o_qwen_judge_audit.jsonl" \
#   --output "results/0624_run2_5case/table1_gpt4o_qwen_judge_results.json" \
#   --tex_output "results/0624_run2_5case/table1_gpt4o_qwen_judge.tex" \
#   --records_output "results/0624_run2_5case/table1_gpt4o_qwen_judge_records.json"
