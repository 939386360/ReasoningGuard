"""Create a deterministic malicious-effect review skeleton for curated MCPTox."""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.evaluation.effect_matcher import effect_definitions
from src.evaluation.live_table1 import normalize_scenario


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    dataset = json.loads(Path(args.input).read_text(encoding="utf-8"))
    scenarios = dataset.get("scenarios", dataset)
    if not isinstance(scenarios, list):
        raise ValueError("Dataset must contain a scenarios list")
    effects = {}
    for raw in scenarios:
        scenario = normalize_scenario(raw)
        effects[scenario["scenario_id"]] = {
            "reviewed": False,
            "effects": effect_definitions(scenario),
        }
    Path(args.output).write_text(
        json.dumps({"schema_revision": 1, "effects": effects}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {len(effects)} review-pending effect entries to {args.output}")


if __name__ == "__main__":
    main()
