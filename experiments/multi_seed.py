#!/usr/bin/env python3
"""
Multi-seed experiment: run main table with seeds 42, 43, 44 on 5 models.
Report mean ± std and paired t-tests for key comparisons.
"""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.mcptox_plus_v2 import build_mcptox_plus_dataset
from src.experiment_model import DefenseProfile
from src.experiment_runner import run_full_experiment
from src.agent_backbone_proxy import create_proxy_backbone
from collections import defaultdict
import random


def select_subset(dataset, per_category, seed):
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
    parser.add_argument("--model", required=True)
    parser.add_argument("--model_map", required=True)
    parser.add_argument("--seeds", default="42,43,44")
    parser.add_argument("--per_category", type=int, default=20)
    parser.add_argument("--api_key", default=os.environ.get("LLM_API_KEY", "sk-9ZuUA9MWpglHgMJhKyBsPUDnGDm95ygy9yN4YqVoLc7GsRp0"))
    parser.add_argument("--api_base_url", default="https://api.chatanywhere.tech/v1/chat/completions")
    parser.add_argument("--ablation", action="store_true")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    model_map = json.loads(args.model_map)
    seeds = [int(s.strip()) for s in args.seeds.split(",")]

    dataset = build_mcptox_plus_dataset()
    profiles = DefenseProfile.ablation_profiles() if args.ablation else DefenseProfile.all_profiles()

    print(f"=== Multi-Seed: {args.model} ({len(seeds)} seeds) ===", flush=True)
    print(f"Seeds: {seeds}", flush=True)
    if args.ablation:
        print(f"Mode: Ablation ({len(profiles)} profiles)", flush=True)
    else:
        print(f"Mode: Main ({len(profiles)} profiles)", flush=True)

    all_seed_results = []

    for seed in seeds:
        subset = select_subset(dataset, args.per_category, seed)
        print(f"\n--- Seed {seed}: {len(subset)} scenarios ---", flush=True)
        print(f"Started: {time.strftime('%H:%M:%S')}", flush=True)

        def make_agent():
            return create_proxy_backbone(
                model_name=args.model, mock_mode=False,
                base_url=args.api_base_url, api_style="chat",
                api_key=args.api_key, model_map=model_map, timeout=args.timeout,
            )

        t0 = time.time()
        results = run_full_experiment(subset, profiles, make_agent, seed=seed)
        elapsed = time.time() - t0

        # Print per-profile metrics
        profile_ids = [p.profile_id for p in profiles]
        print(f"{'Profile':<22s} {'ASR':>6s} {'TCR':>6s} {'L4':>6s} {'L2':>6s}", flush=True)
        for pid in profile_ids:
            m = results["metrics"].get(pid, {})
            print(f"{pid:<22s} {m.get('ASR',0):>5.1f}% {m.get('TCR',0):>5.1f}% {m.get('L4_ASR',0):>5.1f}% {m.get('L2_ASR',0):>5.1f}%", flush=True)
        print(f"Elapsed: {elapsed:.0f}s ({elapsed/60:.1f}m)", flush=True)

        all_seed_results.append({
            "seed": seed,
            "metrics": results["metrics"],
            "per_sample": results["per_sample"],
            "elapsed_sec": round(elapsed, 0),
        })

    # Compute mean ± std across seeds
    print(f"\n=== Multi-Seed Summary: {args.model} ===", flush=True)
    from statistics import mean, stdev

    summary = {}
    for pid in profile_ids:
        asr_vals = [r["metrics"].get(pid, {}).get("ASR", 0) for r in all_seed_results]
        tcr_vals = [r["metrics"].get(pid, {}).get("TCR", 0) for r in all_seed_results]
        l4_vals = [r["metrics"].get(pid, {}).get("L4_ASR", 0) for r in all_seed_results]
        l2_vals = [r["metrics"].get(pid, {}).get("L2_ASR", 0) for r in all_seed_results]

        summary[pid] = {
            "ASR_mean": round(mean(asr_vals), 1),
            "ASR_std": round(stdev(asr_vals), 1) if len(asr_vals) > 1 else 0.0,
            "TCR_mean": round(mean(tcr_vals), 1),
            "TCR_std": round(stdev(tcr_vals), 1) if len(tcr_vals) > 1 else 0.0,
            "L4_ASR_mean": round(mean(l4_vals), 1),
            "L4_ASR_std": round(stdev(l4_vals), 1) if len(l4_vals) > 1 else 0.0,
            "L2_ASR_mean": round(mean(l2_vals), 1),
            "L2_ASR_std": round(stdev(l2_vals), 1) if len(l2_vals) > 1 else 0.0,
            "ASR_values": asr_vals,
            "TCR_values": tcr_vals,
        }

    print(f"{'Profile':<22s} {'ASR (mean±std)':>15s} {'TCR (mean±std)':>15s} {'L2 (mean±std)':>15s}", flush=True)
    print("-" * 70, flush=True)
    for pid in profile_ids:
        s = summary[pid]
        print(f"{pid:<22s} {s['ASR_mean']:>5.1f}±{s['ASR_std']:>4.1f}     {s['TCR_mean']:>5.1f}±{s['TCR_std']:>4.1f}     {s['L2_ASR_mean']:>5.1f}±{s['L2_ASR_std']:>4.1f}", flush=True)

    # Paired t-test for key comparisons
    try:
        from scipy import stats as scipy_stats
        print(f"\n=== Paired t-tests ===", flush=True)

        if not args.ablation:
            # No Defense vs ReasoningGuard
            nd_asr = [r["metrics"].get("no_defense", {}).get("ASR", 0) for r in all_seed_results]
            rg_asr = [r["metrics"].get("reasoning_guard", {}).get("ASR", 0) for r in all_seed_results]
            t_stat, p_val = scipy_stats.ttest_rel(nd_asr, rg_asr)
            print(f"No Defense vs ReasoningGuard: t={t_stat:.2f}, p={p_val:.4f}", flush=True)

            # PTG-Only vs ReasoningGuard
            ptg_asr = [r["metrics"].get("ptg_only", {}).get("ASR", 0) for r in all_seed_results]
            t_stat2, p_val2 = scipy_stats.ttest_rel(ptg_asr, rg_asr)
            print(f"PTG-Only vs ReasoningGuard: t={t_stat2:.2f}, p={p_val2:.4f}", flush=True)

            summary["t_tests"] = {
                "no_defense_vs_rg": {"t": round(t_stat, 2), "p": round(p_val, 4)},
                "ptg_only_vs_rg": {"t": round(t_stat2, 2), "p": round(p_val2, 4)},
            }
    except ImportError:
        print("scipy not available, skipping t-tests", flush=True)

    output = {
        "model": args.model,
        "seeds": seeds,
        "ablation": args.ablation,
        "summary": summary,
        "raw_results": all_seed_results,
    }

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2, default=str, ensure_ascii=False)
    print(f"\nSaved to {args.output}", flush=True)


if __name__ == "__main__":
    main()
