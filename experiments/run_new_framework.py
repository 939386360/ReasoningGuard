#!/usr/bin/env python3
"""
Run experiments with the restructured framework (experiment_runner.py).
Uses MCPTox+ v2 dataset (ScenarioCase objects) with per-profile isolation.
"""
import argparse
import json
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.mcptox_plus_v2 import build_mcptox_plus_dataset
from src.experiment_model import DefenseProfile
from src.experiment_runner import run_full_experiment
from src.agent_backbone_proxy import create_proxy_backbone


def make_agent_factory(model_name, model_map, base_url, api_key, timeout=120):
    def factory():
        return create_proxy_backbone(
            model_name=model_name,
            mock_mode=False,
            base_url=base_url,
            api_style="chat",
            api_key=api_key,
            model_map=model_map,
            timeout=timeout,
        )
    return factory


def select_subset(dataset, per_category, seed=42):
    import random
    rng = random.Random(seed)
    groups = defaultdict(list)
    for s in dataset:
        groups[s.category].append(s)
    subset = []
    for cat in sorted(groups):
        rng.shuffle(groups[cat])
        subset.extend(groups[cat][:per_category])
    return subset


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="GPT-4o")
    parser.add_argument("--model_map", default='{"GPT-4o":"gpt-4o","GPT-4o-mini":"gpt-4o-mini","DeepSeek-V4-Pro":"deepseek-chat"}')
    parser.add_argument("--per_category", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default="results/new_framework_results.json")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--api_key", default=os.environ.get("LLM_API_KEY", ""))
    parser.add_argument("--api_base_url", default=os.environ.get("LLM_API_BASE_URL", "https://api.chatanywhere.tech/v1/chat/completions"))
    args = parser.parse_args()

    model_map = json.loads(args.model_map)

    print(f"=== New Framework Experiment ===", flush=True)
    print(f"Model: {args.model} -> {model_map.get(args.model, args.model)}", flush=True)
    print(f"API: {args.api_base_url}", flush=True)
    print(f"Per category: {args.per_category}", flush=True)

    dataset = build_mcptox_plus_dataset()
    subset = select_subset(dataset, args.per_category, args.seed)
    print(f"Selected {len(subset)} scenarios", flush=True)

    cat_counts = defaultdict(int)
    for s in subset:
        cat_counts[s.category] += 1
    for cat, cnt in sorted(cat_counts.items()):
        print(f"  {cat}: {cnt}", flush=True)

    profiles = DefenseProfile.all_profiles()
    total = len(subset) * len(profiles)
    print(f"\n{len(subset)} scenarios x {len(profiles)} profiles = {total} episodes", flush=True)
    print(f"Started at {time.strftime('%H:%M:%S')}", flush=True)

    factory = make_agent_factory(
        args.model, model_map, args.api_base_url, args.api_key, args.timeout
    )

    t0 = time.time()
    results = run_full_experiment(subset, profiles, factory, seed=args.seed)
    elapsed = time.time() - t0

    print(f"\n=== Results: {args.model} (New Framework) ===", flush=True)
    print(f"{'Profile':<20s} {'ASR':>6s} {'TCR':>6s} {'L4':>6s} {'L2':>6s} {'Invalid':>8s} {'Valid':>6s}", flush=True)
    print("-" * 60, flush=True)
    for pid in ["no_defense","attest_mcp","guardrail","ptg_only","rtv_only","reasoning_guard"]:
        m = results["metrics"].get(pid, {})
        print(f"{pid:<20s} {m.get('ASR',0):>6.1f} {m.get('TCR',0):>6.1f} {m.get('L4_ASR',0):>6.1f} {m.get('L2_ASR',0):>6.1f} {m.get('num_invalid',0):>8d} {str(m.get('metrics_valid',False)):>6s}", flush=True)

    print(f"\nElapsed: {elapsed:.0f}s ({elapsed/60:.1f}m)", flush=True)
    print(f"Per-sample: {len(results['per_sample'])} episodes", flush=True)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str, ensure_ascii=False)
    print(f"Saved to {args.output}", flush=True)

    # Per-category breakdown
    print(f"\n=== Per-Category Breakdown ===", flush=True)
    for cat in sorted(cat_counts):
        cat_results = [r for r in results["per_sample"] if r["category"] == cat]
        for pid in ["no_defense","ptg_only","rtv_only","reasoning_guard"]:
            pid_results = [r for r in cat_results if r["profile_id"] == pid]
            attacks = [r for r in pid_results if r["attack_layer"] in ("L4","L2")]
            succeeded = sum(r["attack_succeeded"] for r in attacks)
            asr = 100 * succeeded / max(len(attacks), 1)
            if pid == "no_defense":
                print(f"  {cat:<30s} {pid:<20s} ASR={asr:>5.1f}% ({succeeded}/{len(attacks)})", flush=True)
            else:
                print(f"  {'':30s} {pid:<20s} ASR={asr:>5.1f}% ({succeeded}/{len(attacks)})", flush=True)


if __name__ == "__main__":
    main()
