#!/bin/bash
set -e
cd /data/lab/ReasoningGuard-main
export LLM_API_KEY="sk-9ZuUA9MWpglHgMJhKyBsPUDnGDm95ygy9yN4YqVoLc7GsRp0"
export LLM_API_BASE_URL="https://api.chatanywhere.tech/v1/chat/completions"
export LD_LIBRARY_PATH="/usr/local/cuda-12.8/lib64:$LD_LIBRARY_PATH"

echo "=== Running multi-model Table 1 experiments ==="
echo "Started at $(date)"

for model_pair in \
  "Claude-Sonnet-5:claude-sonnet-5" \
  "DeepSeek-V3.2:deepseek-v3.2" \
  "Gemini-2.5-Flash:gemini-2.5-flash" \
  "DeepSeek-R1:deepseek-r1"; do

  DISPLAY_NAME="${model_pair%%:*}"
  API_ID="${model_pair##*:}"
  OUTPUT="results/table1_${DISPLAY_NAME,,}_heuristic_results.json"
  
  echo ""
  echo "=== $DISPLAY_NAME ($API_ID) ==="

  python3 experiments/run_quick_benchmark_by_category.py \
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
    --strict_runtime 2>&1 || echo "FAILED: $DISPLAY_NAME"
  
  echo "=== $DISPLAY_NAME DONE at $(date) ==="
done

echo ""
echo "=== ALL MODELS DONE at $(date) ==="

# Push results to GitHub
git add results/table1_*_heuristic_* 2>/dev/null || true
git commit -m "Add multi-model Table 1 results (Claude, DeepSeek, Gemini) at $(date -u '+%Y-%m-%d %H:%M UTC')" 2>/dev/null || echo "No changes"
git push -u origin main 2>&1 || echo "Push failed"
echo "=== PUSH DONE ==="
