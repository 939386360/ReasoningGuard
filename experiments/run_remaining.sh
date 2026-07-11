#!/bin/bash
set -e
cd /data/lab/ReasoningGuard-main
export LLM_API_KEY="sk-9ZuUA9MWpglHgMJhKyBsPUDnGDm95ygy9yN4YqVoLc7GsRp0"
export LLM_API_BASE_URL="https://api.chatanywhere.tech/v1/chat/completions"

echo "=== GPT-4o-mini Table 1 at $(date) ==="
python3 -u experiments/run_quick_benchmark_by_category.py \
  --benchmark mcptox --per_category 55 --categories "" --max_scenarios 200 --runs 3 --seed 42 \
  --data_dir data/mcptox --model GPT-4o-mini --agent_backend proxy \
  --agent_base_url "$LLM_API_BASE_URL" --agent_api_style chat --agent_api_key_env LLM_API_KEY \
  --agent_model_map '{"GPT-4o-mini":"gpt-4o-mini"}' --agent_timeout 120 \
  --judge_mode heuristic --llamaguard_mock --benign_ratio 0.30 \
  --output results/table1_gpt4o_mini_heuristic_results.json \
  --tex_output results/table1_gpt4o_mini_heuristic.tex \
  --records_output results/table1_gpt4o_mini_heuristic_records.json 2>&1
echo "=== GPT-4o-mini DONE at $(date) ==="

echo "=== Qwen3.5-397B-A17B Table 1 at $(date) ==="
python3 -u experiments/run_quick_benchmark_by_category.py \
  --benchmark mcptox --per_category 55 --categories "" --max_scenarios 200 --runs 3 --seed 42 \
  --data_dir data/mcptox --model Qwen3.5-397B-A17B --agent_backend proxy \
  --agent_base_url "$LLM_API_BASE_URL" --agent_api_style chat --agent_api_key_env LLM_API_KEY \
  --agent_model_map '{"Qwen3.5-397B-A17B":"qwen3.5-397b-a17b"}' --agent_timeout 120 \
  --judge_mode heuristic --llamaguard_mock --benign_ratio 0.30 \
  --output results/table1_qwen35_397b_heuristic_results.json \
  --tex_output results/table1_qwen35_397b_heuristic.tex \
  --records_output results/table1_qwen35_397b_heuristic_records.json 2>&1
echo "=== Qwen3.5 DONE at $(date) ==="

git add results/table1_* 2>/dev/null || true
git commit -m "Add final Table 1 (GPT-4o-mini, Qwen3.5) at $(date -u)" 2>/dev/null || true
git push -u origin main 2>&1 || true
echo "=== PUSH DONE ==="
