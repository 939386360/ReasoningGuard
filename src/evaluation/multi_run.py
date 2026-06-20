import math
from typing import Any, Callable, Dict, List, Optional, Tuple


def compute_ci(values: List[float], confidence: float = 0.95) -> Dict[str, float]:
    n = len(values)
    if n < 2:
        return {"mean": values[0] if values else 0.0, "std": 0.0, "ci_half": 0.0, "ci_lo": values[0] if values else 0.0, "ci_hi": values[0] if values else 0.0}
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    std = math.sqrt(variance)
    t_values = {0.90: 6.314, 0.95: 12.706, 0.99: 63.657}
    t_val = t_values.get(confidence, 12.706) if n <= 2 else _t_approx(confidence, n - 1)
    ci_half = t_val * std / math.sqrt(n)
    return {"mean": mean, "std": std, "ci_half": ci_half, "ci_lo": mean - ci_half, "ci_hi": mean + ci_half}


def _t_approx(confidence: float, df: int) -> float:
    z = {0.90: 1.645, 0.95: 1.960, 0.99: 2.576}.get(confidence, 1.960)
    return z * (1 + (1 / (4 * df)) + (1 / (96 * df * df)))


def multi_run(
    experiment_fn: Callable[[], Dict[str, Dict[str, float]]],
    num_runs: int = 3,
    confidence: float = 0.95,
) -> Dict[str, Dict[str, Any]]:
    all_runs = [experiment_fn() for _ in range(num_runs)]
    defense_names = list(all_runs[0].keys())
    metric_names = list(all_runs[0][defense_names[0]].keys())

    result = {}
    for dname in defense_names:
        result[dname] = {}
        for metric in metric_names:
            values = [run_data[dname][metric] for run_data in all_runs if metric in run_data.get(dname, {})]
            if values:
                ci = compute_ci(values, confidence)
                result[dname][metric] = round(ci["mean"], 1)
                result[dname][f"{metric}_std"] = round(ci["std"], 2)
                result[dname][f"{metric}_ci"] = round(ci["ci_half"], 2)
            else:
                result[dname][metric] = 0.0
                result[dname][f"{metric}_std"] = 0.0
                result[dname][f"{metric}_ci"] = 0.0
    return result