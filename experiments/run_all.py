import json
import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.evaluation.eval_runner import (
    run_mcptox_experiment,
    run_multi_model_experiment,
    run_t3_experiment,
    run_ablation_experiment,
    run_per_category_experiment,
)


def main():
    results = {}

    print("=" * 60)
    print("ReasoningGuard Experiment Suite (Mock Mode)")
    print("=" * 60)

    print("\n[1/5] Running MCPTox main experiment...")
    results["mcptox_main"] = run_mcptox_experiment(mock_mode=True)
    _print_table("MCPTox Main Results (GPT-4o)", results["mcptox_main"],
                 ["ASR", "TCR", "Latency_ms"])

    print("\n[2/5] Running multi-model experiment...")
    results["multi_model"] = run_multi_model_experiment(mock_mode=True)
    for model, defenses in results["multi_model"].items():
        _print_table(f"  {model}", defenses, ["ASR", "TCR", "Latency_ms"])

    print("\n[3/5] Running T3 cross-session experiment...")
    results["t3"] = run_t3_experiment(mock_mode=True)
    _print_table("MCPTox+ T3 vs T1", results["t3"], ["T3_ASR", "T1_ASR"])

    print("\n[4/5] Running ablation study...")
    results["ablation"] = run_ablation_experiment(mock_mode=True)
    _print_table("Ablation Study", results["ablation"], ["ASR", "T3_ASR", "TCR"])

    print("\n[5/5] Running per-category breakdown...")
    results["per_category"] = run_per_category_experiment(mock_mode=True)
    for cat, defenses in results["per_category"].items():
        print(f"  {cat}: " + ", ".join(f"{k}={v}" for k, v in defenses.items()))

    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "results", "experiment_results.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


def _print_table(title: str, data: Dict[str, Dict[str, float]], cols: list):
    print(f"\n  {title}")
    header = f"  {'Defense':<20}" + "".join(f"{c:>12}" for c in cols)
    print(header)
    print("  " + "-" * len(header))
    for dname, metrics in data.items():
        row = f"  {dname:<20}" + "".join(f"{metrics.get(c, 'N/A'):>12}" for c in cols)
        print(row)


if __name__ == "__main__":
    main()