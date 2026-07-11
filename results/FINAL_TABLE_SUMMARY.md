# Final Table Summary

## Table 1: Multi-Model Results

| Model | ASR% | TCR% | L4_ASR% | L2_ASR% | Valid |
|-------|------|------|---------|---------|-------|
| Claude-Sonnet-5 | 0.0 | 39.8 | 0.0 | 0.0 | False |
| DeepSeek-V4-Pro | 11.4 | 38.4 | 16.1 | 0.0 | False |
| Gemini-3.5-Flash | 0.0 | 40.7 | 0.0 | 0.0 | False |
| GPT-4o-mini | 2.3 | 21.4 | 3.2 | 0.0 | True |
| Qwen3.5-397B | 0.2 | 39.8 | 0.2 | 0.0 | True |

## Defense Comparison (DeepSeek-V4-Pro)

| Defense | ASR% | TCR% | L4_ASR% | L2_ASR% |
|---------|------|------|---------|----------|
| No Defense | 0.2 | 39.8 | 0.2 | 0.0 |
| AttestMCP | 0.2 | 39.8 | 0.2 | 0.0 |
| Guardrail | 0.2 | 39.8 | 0.2 | 0.0 |
| PTG-Only | 0.0 | 39.8 | 0.0 | 0.0 |
| RTV-Only | 0.2 | 39.8 | 0.2 | 0.0 |
| ReasoningGuard | 0.0 | 39.8 | 0.0 | 0.0 |
