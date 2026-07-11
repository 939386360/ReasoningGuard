#!/usr/bin/env python3
"""从已有的 records 文件中提取 Table 3 (per-category), L4/L2, Latency"""
import json, os, sys
from collections import defaultdict

def load_all_records():
    """Load all records from all 6 model result files"""
    results = {}
    base_dir = "results"
    for fname in os.listdir(base_dir):
        if fname.endswith("_heuristic_results_records.json") or fname.endswith("_qwen_judge_records.json"):
            path = os.path.join(base_dir, fname)
            with open(path) as f:
                records = json.load(f)
            model = fname.replace("table1_", "").replace("_qwen_judge_records.json", "").replace("_heuristic_results_records.json", "")
            results[model] = records
            print(f"Loaded {model}: {len(records)} records")
    return results

def extract_per_category(results):
    """按攻击类别分别计算 ASR"""
    print("\n=== Table Per-Category ASR ===")
    print(f"{'Model':<20s} {'Category':<30s} {'Total':>6s} {'Succeeded':>10s} {'ASR%':>8s}")
    print("-" * 80)

    category_map = {
        "tool_description_poisoning": "Tool Desc. Poisoning",
        "parameter_injection": "Parameter Injection",
        "response_manipulation": "Response Manipulation",
        "capability_escalation": "Capability Escalation",
    }

    per_category_results = {}

    for model, records in results.items():
        if not isinstance(records, list):
            continue
        model_results = {}
        for rec in records:
            if not isinstance(rec, dict):
                continue
            category = rec.get("category", "unknown")
            is_attack = rec.get("is_attack", False)
            if not is_attack:
                continue
            cat_name = category_map.get(category, category)
            if cat_name not in model_results:
                model_results[cat_name] = {"total": 0, "succeeded": 0}
            model_results[cat_name]["total"] += 1
            if rec.get("attack_succeeded", False):
                model_results[cat_name]["succeeded"] += 1

        for cat_name in sorted(model_results.keys()):
            m = model_results[cat_name]
            asr = 100 * m["succeeded"] / max(m["total"], 1)
            print(f"{model:<20s} {cat_name:<30s} {m['total']:>6d} {m['succeeded']:>10d} {asr:>8.1f}")
        per_category_results[model] = model_results
    return per_category_results

def extract_per_layer(results):
    """按 L4/L2 层分别统计"""
    print("\n=== Table Per-Layer ASR ===")
    print(f"{'Model':<20s} {'L4_Total':>8s} {'L4_ASR%':>8s} {'L2_Total':>8s} {'L2_ASR%':>8s}")
    print("-" * 60)

    for model, records in results.items():
        if not isinstance(records, list):
            continue
        l4_total, l4_success = 0, 0
        l2_total, l2_success = 0, 0

        for rec in records:
            if not isinstance(rec, dict) or not rec.get("is_attack"):
                continue
            layer = rec.get("attack_layer", "L4")
            if layer == "L4":
                l4_total += 1
                if rec.get("attack_succeeded"):
                    l4_success += 1
            else:
                l2_total += 1
                if rec.get("attack_succeeded"):
                    l2_success += 1

        l4_asr = 100 * l4_success / max(l4_total, 1)
        l2_asr = 100 * l2_success / max(l2_total, 1)
        print(f"{model:<20s} {l4_total:>8d} {l4_asr:>8.1f} {l2_total:>8d} {l2_asr:>8.1f}")

def extract_latency(results):
    """延迟统计"""
    print("\n=== Table Latency ===")
    print(f"{'Model':<20s} {'Samples':>8s} {'Mean(ms)':>10s} {'Median(ms)':>10s} {'Max(ms)':>10s}")
    print("-" * 60)

    for model, records in results.items():
        if not isinstance(records, list):
            continue
        latencies = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            lat = rec.get("latency_ms", 0)
            if lat and lat > 0:
                latencies.append(lat)

        if latencies:
            mean_lat = sum(latencies) / len(latencies)
            sorted_lat = sorted(latencies)
            median_lat = sorted_lat[len(sorted_lat)//2]
            max_lat = max(latencies)
            print(f"{model:<20s} {len(latencies):>8d} {mean_lat:>10.1f} {median_lat:>10.1f} {max_lat:>10.1f}")

def extract_defense_comparison(results):
    """各 defense 的 ASR/TCR 对比 (GPT-4o 和 DeepSeek 两个有信号的模型)"""
    print("\n=== Table Defense Comparison (per model) ===")
    
    target_models = {"GPT-4o", "DeepSeek-V4-Pro"}
    
    for model in target_models:
        if model not in results:
            continue
        records = results[model]
        if not isinstance(records, list):
            continue

        # Group by defense
        defense_stats = {}
        for rec in records:
            if not isinstance(rec, dict):
                continue
            defense = rec.get("defense", rec.get("name", "unknown"))
            if defense == "unknown" or not defense:
                continue
            if defense not in defense_stats:
                defense_stats[defense] = {"attacks": 0, "attack_succeeded": 0, "benign": 0, "task_completed": 0}
            
            if rec.get("is_attack"):
                defense_stats[defense]["attacks"] += 1
                if rec.get("attack_succeeded"):
                    defense_stats[defense]["attack_succeeded"] += 1
            else:
                defense_stats[defense]["benign"] += 1
                if rec.get("task_completed"):
                    defense_stats[defense]["task_completed"] += 1

        print(f"\n{model}:")
        print(f"{'Defense':<20s} {'ASR%':>8s} {'TCR%':>8s} {'Attacks':>8s} {'Benign':>8s}")
        print("-" * 60)
        for defense in ["No Defense", "AttestMCP", "Guardrail", "PTG-Only", "RTV-Only", "ReasoningGuard"]:
            if defense not in defense_stats:
                continue
            s = defense_stats[defense]
            asr = 100 * s["attack_succeeded"] / max(s["attacks"], 1)
            tcr = 100 * s["task_completed"] / max(s["benign"], 1)
            print(f"{defense:<20s} {asr:>8.1f} {tcr:>8.1f} {s['attacks']:>8d} {s['benign']:>8d}")

if __name__ == "__main__":
    print("Loading records from all 6 models...\n")
    results = load_all_records()
    
    # 从 records 中提取 Table 3
    per_category_results = extract_per_category(results)
    
    # 从 records 中提取 L4/L2
    extract_per_layer(results)
    
    # 从 records 中提取 Latency
    extract_latency(results)
    
    # 从 records 中提取 Defense comparison
    extract_defense_comparison(results)
    
    print("\n=== DONE ===")
