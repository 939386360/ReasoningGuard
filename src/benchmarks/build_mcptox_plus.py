import json
import os
import random
import uuid
from typing import Any, Dict, List

from src.attacks.attack_generator import AttackCategory, AttackGenerator, ATTACK_TEMPLATES


def build_mcptox_plus(
    num_context_dependent: int = 80,
    num_cross_session_t3: int = 50,
    seed: int = 42,
    output_dir: str = "data/mcptox_plus",
) -> str:
    rng = random.Random(seed)
    gen = AttackGenerator(seed=seed)
    os.makedirs(output_dir, exist_ok=True)

    cd_scenarios = []
    for i in range(num_context_dependent):
        tmpl = rng.choice(ATTACK_TEMPLATES[AttackCategory.CONTEXT_DEPENDENT])
        cd_scenarios.append({
            "scenario_id": f"cd_{i:04d}",
            "category": "context_dependent",
            "temporality": "T2",
            "setup_context": tmpl["setup_context"],
            "poisoned_instruction": tmpl["poisoned_instruction"],
            "legitimate_task": tmpl["legitimate_task"],
            "target_action": tmpl["target_action"],
            "difficulty": rng.choice(["easy", "medium", "hard"]),
            "source": "MCPTox+",
        })

    t3_scenarios = []
    for i in range(num_cross_session_t3):
        tmpl = rng.choice(ATTACK_TEMPLATES[AttackCategory.CROSS_SESSION_T3])
        session_gap = rng.randint(2, tmpl.get("session_gap", 5))
        t3_scenarios.append({
            "scenario_id": f"t3_{i:04d}",
            "category": "cross_session_t3",
            "temporality": "T3",
            "session_t_injection": tmpl["session_t_injection"],
            "session_t_k_trigger": tmpl["session_t_k_trigger"],
            "session_gap": session_gap,
            "target_action": tmpl["target_action"],
            "difficulty": rng.choice(["medium", "hard"]),
            "source": "MCPTox+",
        })

    dataset = {
        "name": "MCPTox+",
        "version": "1.0",
        "description": "Extended MCPTox benchmark with context-dependent (T2) and cross-session (T3) attack scenarios",
        "num_context_dependent": len(cd_scenarios),
        "num_cross_session_t3": len(t3_scenarios),
        "total": len(cd_scenarios) + len(t3_scenarios),
        "context_dependent_scenarios": cd_scenarios,
        "cross_session_t3_scenarios": t3_scenarios,
    }

    out_path = os.path.join(output_dir, "mcptox_plus.json")
    with open(out_path, "w") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    stats_path = os.path.join(output_dir, "mcptox_plus_stats.json")
    stats = {
        "total_scenarios": dataset["total"],
        "context_dependent": len(cd_scenarios),
        "cross_session_t3": len(t3_scenarios),
        "difficulty_distribution": {
            "easy": sum(1 for s in cd_scenarios if s["difficulty"] == "easy")
                   + sum(1 for s in t3_scenarios if s["difficulty"] == "easy"),
            "medium": sum(1 for s in cd_scenarios if s["difficulty"] == "medium")
                     + sum(1 for s in t3_scenarios if s["difficulty"] == "medium"),
            "hard": sum(1 for s in cd_scenarios if s["difficulty"] == "hard")
                   + sum(1 for s in t3_scenarios if s["difficulty"] == "hard"),
        },
        "avg_session_gap_t3": sum(s["session_gap"] for s in t3_scenarios) / max(len(t3_scenarios), 1),
    }
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"MCPTox+ dataset built: {dataset['total']} scenarios")
    print(f"  Context-dependent (T2): {len(cd_scenarios)}")
    print(f"  Cross-session (T3): {len(t3_scenarios)}")
    print(f"  Saved to: {out_path}")
    return out_path


if __name__ == "__main__":
    build_mcptox_plus()