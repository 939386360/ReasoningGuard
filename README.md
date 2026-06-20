# ReasoningGuard: Experimental Code

Code for the paper **"ReasoningGuard: Dual-Layer Defense for MCP-Based LLM Agents via Protocol Attestation and Reasoning Trace Verification"** (AAAI-27 submission).

## Structure

```
code/
├── config.yaml                          # Global configuration
├── requirements.txt                     # Python dependencies
├── src/
│   ├── mcp_client.py                    # MCP protocol simulation (messages, servers, reasoning traces)
│   ├── ptg.py                           # Protocol-Attested Tool Gateway (L4 defense)
│   ├── rtv.py                           # Reasoning Trace Verifier (L2 defense)
│   ├── reason_guard.py                  # ReasoningGuard integration + baselines
│   ├── judge.py                         # LLM judge interface (OpenAI/Anthropic/vLLM + mock)
│   ├── attacks/
│   │   └── attack_generator.py          # 6-category attack scenario generator
│   ├── benchmarks/
│   │   └── build_mcptox_plus.py         # MCPTox+ dataset construction (T2 + T3)
│   └── evaluation/
│       └── eval_runner.py               # Full experiment pipeline (mock + real)
├── experiments/
│   ├── run_all.py                       # Run all experiments (mock mode)
│   ├── generate_tables.py               # Generate LaTeX tables
│   ├── generate_figures.py              # Generate PDF figures (matplotlib)
│   └── calibrate_thresholds.py          # Calibrate RTV anomaly thresholds
├── tests/
│   └── test_all.py                      # Unit tests
└── results/                             # Output directory (created at runtime)
    ├── experiment_results.json
    ├── latex_tables/
    ├── figures/
    └── calibrated_thresholds.json
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run all experiments (mock mode, no API keys needed)
python experiments/run_all.py

# Generate LaTeX tables
python experiments/generate_tables.py

# Generate figures (PDF)
python experiments/generate_figures.py

# Build MCPTox+ dataset
python -m src.benchmarks.build_mcptox_plus

# Calibrate thresholds
python experiments/calibrate_thresholds.py

# Run unit tests
python -m pytest tests/ -v
# or
python tests/test_all.py
```

## Mock vs Real Mode

All experiments support `mock_mode=True` (default) which uses pre-computed results matching the paper's tables. Set `mock_mode=False` to run the actual simulation:

- **Mock mode**: Uses hardcoded paper results, no API keys needed, instant execution
- **Real mode**: Runs PTG/RTV/guardrail over generated attack scenarios; requires API keys for LLM judge (set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` env vars)

## Key Components

### PTG (Protocol-Attested Tool Gateway)
- Semantic intent attestation via HMAC-SHA256
- Origin-tagged sampling responses
- Cross-server isolation with intent-aware boundaries

### RTV (Reasoning Trace Verifier)
- Structured reasoning trace (observation → inference → decision)
- Three anomaly classes: CAI, OAV, IAD
- Constrained judge model (rule-based or LLM-backed)
- Memory provenance graph for T3 cross-session detection

### Attack Categories
| Category | LASM Layer | Temporality |
|----------|-----------|-------------|
| Tool Description Poisoning | L4 | T1 |
| Parameter Injection | L4 | T1 |
| Response Manipulation | L2 | T2 |
| Capability Escalation | L4 | T1 |
| Context-Dependent | L2 | T2 |
| Cross-Session (T3) | L2 | T3 |

## Citation

```bibtex
@inproceedings{reasoningguard2027,
  title     = {ReasoningGuard: Dual-Layer Defense for MCP-Based LLM Agents via Protocol Attestation and Reasoning Trace Verification},
  author    = {Anonymous},
  booktitle = {Proceedings of the AAAI Conference on Artificial Intelligence},
  year      = {2027}
}
```