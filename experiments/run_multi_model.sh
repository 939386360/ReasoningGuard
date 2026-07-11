#!/bin/bash
# Multi-model Table 1 experiment runner
# Runs each model in sequence, collects results, pushes to GitHub

set -e
cd /data/lab/ReasoningGuard-main

export LLM_API_KEY="sk-9ZuUA9MWpglHgMJhKyBsPUDnGDm95ygy9yN4YqVoLc7GsRp0"
export LLM_API_BASE_URL="https://api.chatanywhere.tech/v1/chat/completions"
export LD_LIBRARY_PATH="/usr/local/cuda-12.8/lib64:$LD_LIBRARY_PATH"

echo "=== Multi-Model Table 1 ==="
echo "Started at $(date)"

# Model configurations: display_name|api_id|max_tokens
MODELS=(
  "Claude-Sonnet-5|claude-sonnet-5|2048"
  "DeepSeek-V3.2|deepseek-v3.2|1024"
  "Gemini-2.5-Flash|gemini-2.5-flash|1024"
  "DeepSeek-R1|deepseek-r1|1024"
  "GPT-4o-mini|gpt-4o-mini|1024"
)

for model_config in "${MODELS[@]}"; do
  IFS='|' read -r DISPLAY_NAME API_ID MAX_TOKENS <<< "$model_config"
  OUTPUT="results/table1_${DISPLAY_NAME,,//-/_}_heuristic_results.json"
  
  echo ""
  echo "================================================"
  echo "  $DISPLAY_NAME ($API_ID, max_tokens=$MAX_TOKENS)"
  echo "================================================"

  python3 -u experiments/run_quick_benchmark_by_category.py \
    --benchmark mcptox \
    --per_category 55 \
    --categories "" \
    --max_scenarios 200 \
    --runs 3 \
    --seed 42 \
    --data_dir data/mcptox \
    --model "$DISPLAY_NAME" \
    --agent_backend proxy \
    --agent_base_url "$LLM_API_BASE_URL" \
    --agent_api_style chat \
    --agent_api_key_env LLM_API_KEY \
    --agent_model_map "{\"$DISPLAY_NAME\":\"$API_ID\"}" \
    --agent_timeout 120 \
    --judge_mode heuristic \
    --llamaguard_mock \
    --benign_ratio 0.30 \
    --output "$OUTPUT" \
    --tex_output "${OUTPUT%.json}.tex" \
    --records_output "${OUTPUT%.json}_records.json" \
    2>&1 || echo "WARNING: $DISPLAY_NAME had errors, continuing..."

  echo "=== $DISPLAY_NAME DONE at $(date) ==="
done

echo ""
echo "=== ALL MODELS DONE at $(date) ==="

# Push to GitHub
git add results/table1_*_heuristic_* 2>/dev/null || true
git commit -m "Add multi-model Table 1 results ($(date -u '+%Y-%m-%d %H:%M UTC'))" 2>/dev/null || echo "No changes to commit"
git push -u origin main 2>&1 || echo "Push failed (will retry later)"
echo "=== PUSH DONE ==="
