import json
import os
import sys
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.mcp_client import MCPMessage, MCPMessageType, Origin, ReasoningStep, ReasoningTrace
from src.attacks.attack_generator import AttackCategory, AttackGenerator, ATTACK_TEMPLATES
from src.rtv import ConstrainedJudgeModel, AnomalyClass


def calibrate_thresholds(
    num_benign: int = 50,
    num_attack: int = 50,
    seed: int = 42,
    output_path: str = "results/calibrated_thresholds.json",
) -> Dict[str, float]:
    import random
    rng = random.Random(seed)
    gen = AttackGenerator(seed=seed)

    benign_scores = {c.value: [] for c in AnomalyClass}
    attack_scores = {c.value: [] for c in AnomalyClass}

    judge = ConstrainedJudgeModel(thresholds={c.value: 1.0 for c in AnomalyClass})

    for i in range(num_benign):
        trace = gen.generate_benign_trace("Standard file read operation for the user")
        intent = "Read file contents from user directory"
        scores = judge.score_trace(trace, intent)
        for c in AnomalyClass:
            benign_scores[c.value].append(scores[c.value])

    for cat in [AttackCategory.TOOL_DESCRIPTION_POISONING, AttackCategory.PARAMETER_INJECTION,
                AttackCategory.RESPONSE_MANIPULATION, AttackCategory.CAPABILITY_ESCALATION,
                AttackCategory.CONTEXT_DEPENDENT]:
        for i in range(num_attack // 5):
            tmpl = rng.choice(ATTACK_TEMPLATES.get(cat, []))
            trace = gen.generate_malicious_trace(cat, tmpl.get("malicious_response", ""))
            intent = tmpl.get("target_action", "")
            scores = judge.score_trace(trace, intent)
            for c in AnomalyClass:
                attack_scores[c.value].append(scores[c.value])

    calibrated = {}
    for c in AnomalyClass:
        benign_vals = sorted(benign_scores[c.value])
        attack_vals = sorted(attack_scores[c.value])

        if benign_vals and attack_vals:
            max_benign = benign_vals[-1]
            min_attack = attack_vals[0]
            if max_benign < min_attack:
                threshold = (max_benign + min_attack) / 2
            else:
                overlap_benign = [v for v in benign_vals if v >= min_attack]
                overlap_attack = [v for v in attack_vals if v <= max_benign]
                if overlap_benign and overlap_attack:
                    threshold = (sorted(overlap_benign + overlap_attack)[len(overlap_benign + overlap_attack) // 2])
                else:
                    threshold = max_benign
        else:
            threshold = 0.65

        calibrated[c.value] = round(max(0.3, min(0.9, threshold)), 2)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "thresholds": calibrated,
            "benign_score_stats": {k: {"mean": sum(v)/max(len(v),1),
                                        "max": max(v) if v else 0,
                                        "count": len(v)}
                                   for k, v in benign_scores.items()},
            "attack_score_stats": {k: {"mean": sum(v)/max(len(v),1),
                                        "min": min(v) if v else 0,
                                        "count": len(v)}
                                   for k, v in attack_scores.items()},
        }, f, indent=2)

    print(f"Calibrated thresholds: {calibrated}")
    print(f"Saved to: {output_path}")
    return calibrated


if __name__ == "__main__":
    calibrate_thresholds()