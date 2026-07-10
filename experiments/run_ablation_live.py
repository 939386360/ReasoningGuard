#!/usr/bin/env python3
"""Run ablation experiments - each variant uses a standard defense name so
_evaluate_all_defenses dispatch works correctly."""
import json
import os
import sys
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_backbone import AGENT_OUTCOME_PARSED_TOOL_CALL
from src.attacks.attack_generator import build_mcp_servers, build_servers_from_template
from src.benchmarks.load_mcptox import load_mcptox
from src.evaluation.live_table1 import (
    _normalize_with_metadata, _agent_output_to_inputs, _evaluate_all_defenses,
    compute_live_metrics, _combine_live_outputs, make_judge, _replace_trusted_registries,
    _invoke_attack_scenario, is_harmful_output,
)
from src.ptg import ProtocolAttestedToolGateway
from src.reasoning_guard import (
    AttestMCPBaseline, PTGOnlyBaseline, RTVOnlyBaseline, ReasoningGuard,
)
from src.rtv import ReasoningTraceVerifier, ConstrainedJudgeModel

# Ablation variants: each maps a readable label to a (defense_name, defense_builder)
ABLATION_VARIANTS = [
    ("ReasoningGuard", lambda judge: ReasoningGuard(rtv=ReasoningTraceVerifier(judge=judge))),
    ("-IntentAttest",   lambda judge: ReasoningGuard(
        ptg=ProtocolAttestedToolGateway(disable_intent_attestation=True),
        rtv=ReasoningTraceVerifier(judge=judge))),
    ("-OriginTags",     lambda judge: ReasoningGuard(
        ptg=ProtocolAttestedToolGateway(disable_origin_tags=True),
        rtv=ReasoningTraceVerifier(judge=judge))),
    ("-MemoryProv",     lambda judge: ReasoningGuard(
        rtv=ReasoningTraceVerifier(judge=judge, disable_memory_provenance=True))),
]

def run_ablation(runs=3, max_scenarios=200, seed=42, output="results/ablation_results.json"):
    from experiments.run_quick_benchmark_by_category import _make_agent_factory
    from src.agent_backbone_proxy import DEFAULT_PROXY_BASE_URL

    base_url = os.environ.get("LLM_API_BASE_URL", DEFAULT_PROXY_BASE_URL)
    agent_factory = _make_agent_factory(
        backend="proxy", base_url=base_url, api_style="chat",
        api_key_env="LLM_API_KEY", model_map={"GPT-4o": "gpt-4o"}, timeout=60)

    judge = make_judge("llm", "vllm", "qwen2.5-7B-Instruct",
                       os.environ.get("JUDGE_BASE_URL", "http://localhost:14545/v1/chat/completions"), "fallback")

    # Also prepare PTG-Only and RTV-Only for two extra variants
    extra_variants = [
        ("PTG-Only", lambda j: PTGOnlyBaseline()),
        ("RTV-Only", lambda j: RTVOnlyBaseline()),
    ]

    scenarios_raw = load_mcptox(data_dir="data/mcptox", use_official=False, seed=seed)
    scenarios = list(scenarios_raw)
    random.Random(seed).shuffle(scenarios)
    scenarios = scenarios[:max_scenarios]

    all_results = {}

    for variant in ABLATION_VARIANTS + extra_variants:
        label, builder = variant
        print(f"\n=== Ablation: {label} ===", flush=True)

        per_run_metrics = []
        for run_idx in range(runs):
            run_seed = seed + run_idx
            rng_run = random.Random(run_seed)
            run_scenarios = list(scenarios)
            rng_run.shuffle(run_scenarios)
            run_scenarios = run_scenarios[:max_scenarios]

            # Use a standard defense name so _evaluate_all_defenses can dispatch
            defense_name = "ReasoningGuard"
            if label == "PTG-Only":
                defense_name = "PTG-Only"
            elif label == "RTV-Only":
                defense_name = "RTV-Only"

            defense = builder(judge)
            defenses = {defense_name: defense}

            clean_servers = build_mcp_servers()
            for d in defenses.values():
                if hasattr(d, "ptg"):
                    for s in clean_servers:
                        d.ptg.register_server(s)

            agent = agent_factory("GPT-4o", mock_mode=False)
            records = {defense_name: []}

            for idx, raw_sc in enumerate(run_scenarios):
                scenario = _normalize_with_metadata(dict(raw_sc))
                template = scenario.get("raw", {}).get("template", {}) or scenario.get("raw", {})
                servers = build_servers_from_template(template)
                _replace_trusted_registries(defenses, servers)
                try:
                    attack_agent = _invoke_attack_scenario(agent, scenario, servers)
                    msg, trace, intent, outcome = _agent_output_to_inputs(attack_agent, scenario, is_attack=True)
                    if outcome == AGENT_OUTCOME_PARSED_TOOL_CALL:
                        harmful = is_harmful_output(msg, trace, intent, scenario)
                        _evaluate_all_defenses(defenses, records, msg, trace, intent, True, harmful, scenario, agent_output=attack_agent)
                except Exception as e:
                    pass

                if (idx+1) % 50 == 0:
                    print(f"  [{label}] Run {run_idx+1}: {idx+1}/{len(run_scenarios)}", flush=True)

            metrics = compute_live_metrics(records[defense_name])
            per_run_metrics.append({defense_name: metrics})
            print(f"  [{label}] Run {run_idx+1} ASR={metrics['ASR']} TCR={metrics['TCR']}", flush=True)

        combined = _combine_live_outputs(per_run_metrics, runs)
        all_results[label] = combined[defense_name]

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nAblation done -> {output}")
    print(json.dumps(all_results, indent=2, default=str))

if __name__ == "__main__":
    run_ablation(runs=3, max_scenarios=200, output="results/ablation_results.json")
