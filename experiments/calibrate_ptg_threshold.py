"""Calibrate the PTG embedding threshold on a labeled, main-set-disjoint file.

Input JSON is a list of {id, label, query, action_text}; label is "benign" or
"attack".  The selected threshold maximizes attack TPR subject to benign false
block rate <= --max_benign_fbr.  Source-set construction and human review remain
separate, auditable curation steps.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ptg import MultilingualEmbeddingBackend


def select_threshold(rows, max_benign_fbr=0.05):
    candidates = sorted({float(row["similarity"]) for row in rows})
    best = None
    for threshold in candidates:
        benign = [row for row in rows if row["label"] == "benign"]
        attacks = [row for row in rows if row["label"] == "attack"]
        benign_fbr = sum(row["similarity"] < threshold for row in benign) / max(len(benign), 1)
        attack_tpr = sum(row["similarity"] < threshold for row in attacks) / max(len(attacks), 1)
        if benign_fbr <= max_benign_fbr:
            candidate = (attack_tpr, -benign_fbr, threshold)
            if best is None or candidate > best[0]:
                best = (candidate, {
                    "threshold": threshold,
                    "benign_false_block_rate": benign_fbr,
                    "attack_true_block_rate": attack_tpr,
                    "num_benign": len(benign),
                    "num_attack": len(attacks),
                })
    if best is None:
        raise RuntimeError("No threshold satisfies the benign false-block constraint")
    return best[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--device", default="auto")
    parser.add_argument("--max_benign_fbr", type=float, default=0.05)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    rows = json.loads(Path(args.input).read_text(encoding="utf-8"))
    if not isinstance(rows, list) or not rows:
        raise ValueError("Calibration input must be a non-empty JSON list")
    backend = MultilingualEmbeddingBackend(args.model, args.device, fail_fast=True)
    scored = []
    for row in rows:
        if row.get("label") not in {"benign", "attack"}:
            raise ValueError(f"Invalid label for {row.get('id')}: {row.get('label')}")
        evaluation = backend.similarity(
            str(row["query"]), str(row["action_text"])
        )
        if evaluation.status != "ok" or evaluation.similarity is None:
            raise RuntimeError(
                f"Embedding failed for calibration row {row.get('id')}: "
                f"{evaluation.error_type}: {evaluation.error_message}"
            )
        scored.append({
            **row,
            "similarity": evaluation.similarity,
        })
    result = select_threshold(scored, args.max_benign_fbr)
    result["model"] = args.model
    result["max_benign_false_block_rate"] = args.max_benign_fbr
    Path(args.output).write_text(
        json.dumps({"calibration": result, "rows": scored}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
