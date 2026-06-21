import argparse
import json
import os
import random
import sys
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_backbone import create_backbone
from src.agent_backbone_proxy import create_proxy_backbone
from src.benchmarks.load_agentpi import load_agentpi
from src.benchmarks.load_mcptox import load_mcptox
from src.evaluation.live_table1 import (
    _agent_output_to_inputs,
    _detail_record,
    _evaluate_all_defenses,
    build_attack_query,
    build_benign_query,
    compute_live_metrics,
    is_harmful_output,
    make_defenses,
    make_judge,
    normalize_scenario,
)
from src.attacks.attack_generator import build_mcp_servers


DEFAULT_OUTPUT_DIR = "results/quick_eval"
DEFAULT_MODELS = ["GPT-4o", "Claude-3.5-Sonnet", "Gemini-1.5-Pro", "Llama-3.1-70B"]


def load_benchmark_scenarios(
    benchmark: str,
    seed: int = 42,
    synthetic: bool = False,
    mcptox_data_dir: str = "data/mcptox",
    agentpi_data_dir: str = "data/agentpi",
    mcptox_plus_data_dir: str = "data/mcptox_plus",
) -> List[Dict[str, Any]]:
    selected = benchmark.lower()
    if selected == "all":
        scenarios: List[Dict[str, Any]] = []
        for name in ("mcptox", "agentpi", "mcptox_plus"):
            scenarios.extend(load_benchmark_scenarios(
                name,
                seed=seed,
                synthetic=synthetic,
                mcptox_data_dir=mcptox_data_dir,
                agentpi_data_dir=agentpi_data_dir,
                mcptox_plus_data_dir=mcptox_plus_data_dir,
            ))
        return scenarios

    if selected == "mcptox":
        return _tag_benchmark(
            load_mcptox(data_dir=mcptox_data_dir, use_official=not synthetic, seed=seed),
            "MCPTox",
        )
    if selected == "agentpi":
        return _tag_benchmark(
            load_agentpi(data_dir=agentpi_data_dir, use_official=not synthetic, seed=seed),
            "AgentPI",
        )
    if selected == "mcptox_plus":
        return load_mcptox_plus(mcptox_plus_data_dir)

    raise ValueError(f"Unsupported benchmark: {benchmark}")


def load_mcptox_plus(data_dir: str = "data/mcptox_plus") -> List[Dict[str, Any]]:
    path = os.path.join(data_dir, "mcptox_plus.json")
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Missing {path}. Build it first with: python -m src.benchmarks.build_mcptox_plus"
        )

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    scenarios = []
    for raw in data.get("context_dependent_scenarios", []):
        item = dict(raw)
        item["benchmark"] = "MCPTox+"
        scenarios.append(item)
    for raw in data.get("cross_session_t3_scenarios", []):
        item = dict(raw)
        item["benchmark"] = "MCPTox+"
        scenarios.append(item)

    print(f"Loaded MCPTox+: {len(scenarios)} scenarios from {path}")
    return scenarios


def select_per_category(
    scenarios: Iterable[Mapping[str, Any]],
    per_category: int,
    seed: int = 42,
    categories: Optional[Iterable[str]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    if per_category <= 0:
        raise ValueError("--per_category must be positive")

    wanted = {c.strip() for c in categories or [] if c.strip()}
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for raw in scenarios:
        item = dict(raw)
        category = str(item.get("category") or item.get("attack_vector") or "unknown")
        if wanted and category not in wanted:
            continue
        benchmark = str(item.get("benchmark") or item.get("source") or "unknown")
        groups[f"{benchmark}::{category}"].append(item)

    rng = random.Random(seed)
    selected: List[Dict[str, Any]] = []
    summary: Dict[str, int] = {}
    for key in sorted(groups):
        rows = list(groups[key])
        rng.shuffle(rows)
        chosen = rows[:per_category]
        summary[key] = len(chosen)
        selected.extend(chosen)

    return selected, summary


def run_quick_evaluation(
    scenarios: List[Mapping[str, Any]],
    model_name: str = "GPT-4o",
    seed: int = 42,
    agent_backend: str = "proxy",
    agent_mock: bool = False,
    agent_base_url: Optional[str] = None,
    agent_api_style: str = "chat",
    agent_api_key_env: str = "LLM_API_KEY",
    agent_model_map: Optional[Mapping[str, str]] = None,
    agent_timeout: int = 60,
    judge_mode: str = "heuristic",
    judge_provider: str = "vllm",
    judge_model: str = "models/judge_qwen2.5-7b/final",
    judge_base_url: Optional[str] = None,
    llamaguard_mock: bool = True,
    benign_ratio: float = 0.0,
    output_results: Optional[str] = None,
    output_records: Optional[str] = None,
) -> Dict[str, Dict[str, float]]:
    rng = random.Random(seed)
    servers = build_mcp_servers()
    judge = make_judge(judge_mode, judge_provider, judge_model, judge_base_url)
    defenses = make_defenses(judge=judge, llamaguard_mock=llamaguard_mock)
    agent = _make_agent(
        model_name=model_name,
        backend=agent_backend,
        mock_mode=agent_mock,
        base_url=agent_base_url,
        api_style=agent_api_style,
        api_key_env=agent_api_key_env,
        model_map=agent_model_map,
        timeout=agent_timeout,
    )

    records: Dict[str, List[Dict[str, Any]]] = {name: [] for name in defenses}
    detailed_records: List[Dict[str, Any]] = []

    for idx, raw in enumerate(scenarios):
        scenario = normalize_scenario(dict(raw))
        scenario["benchmark"] = raw.get("benchmark") or raw.get("source") or "unknown"

        attack_agent = agent.invoke(build_attack_query(scenario), servers)
        attack_msg, attack_trace, attack_intent = _agent_output_to_inputs(attack_agent, scenario, is_attack=True)
        attack_harmful = is_harmful_output(attack_msg, attack_trace, attack_intent, scenario)
        _evaluate_all_defenses(defenses, records, attack_msg, attack_trace, attack_intent, True, attack_harmful, scenario)
        _tag_latest_rows(records, scenario)
        detailed_records.append(_quick_detail_record(idx, scenario, True, attack_agent, attack_msg, attack_harmful))

        if rng.random() < benign_ratio:
            benign_agent = agent.invoke(build_benign_query(scenario), servers)
            benign_msg, benign_trace, benign_intent = _agent_output_to_inputs(benign_agent, scenario, is_attack=False)
            _evaluate_all_defenses(defenses, records, benign_msg, benign_trace, benign_intent, False, False, scenario)
            _tag_latest_rows(records, scenario)
            detailed_records.append(_quick_detail_record(idx, scenario, False, benign_agent, benign_msg, False))

    results = {name: compute_live_metrics(rows) for name, rows in records.items()}
    if output_results:
        _write_json(output_results, results)
    if output_records:
        _write_json(output_records, detailed_records)
    return results


def main():
    parser = argparse.ArgumentParser(description="Run a small per-category benchmark sample for quick debugging.")
    parser.add_argument("--benchmark", choices=["mcptox", "agentpi", "mcptox_plus", "all"], default="mcptox")
    parser.add_argument("--per_category", type=int, default=2)
    parser.add_argument("--categories", default="", help="Comma-separated category filter after loading the benchmark.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--synthetic", action="store_true", help="Force synthetic fallback for MCPTox/AgentPI.")
    parser.add_argument("--model", default="GPT-4o")
    parser.add_argument("--agent_backend", choices=["proxy", "default"], default="proxy")
    parser.add_argument("--agent_mock", action="store_true")
    parser.add_argument("--agent_base_url", default=os.environ.get("LLM_API_BASE_URL", "https://llm-api.net/v1/chat/completions"))
    parser.add_argument("--agent_api_style", choices=["auto", "chat", "responses"], default="chat")
    parser.add_argument("--agent_api_key_env", default="LLM_API_KEY")
    parser.add_argument("--agent_model_map", default=None)
    parser.add_argument("--agent_timeout", type=int, default=60)
    parser.add_argument("--judge_mode", choices=["heuristic", "llm"], default="heuristic")
    parser.add_argument("--judge_provider", default="vllm")
    parser.add_argument("--judge_model", default="models/judge_qwen2.5-7b/final")
    parser.add_argument("--judge_base_url", default=None)
    parser.add_argument("--llamaguard_mock", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--benign_ratio", type=float, default=0.0)
    parser.add_argument("--mcptox_data_dir", default="data/mcptox")
    parser.add_argument("--agentpi_data_dir", default="data/agentpi")
    parser.add_argument("--mcptox_plus_data_dir", default="data/mcptox_plus")
    parser.add_argument("--output_dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--results_output", default=None)
    parser.add_argument("--records_output", default=None)
    args = parser.parse_args()

    model_map = _parse_json_map(args.agent_model_map, "--agent_model_map")
    categories = _parse_csv(args.categories)
    scenarios = load_benchmark_scenarios(
        args.benchmark,
        seed=args.seed,
        synthetic=args.synthetic,
        mcptox_data_dir=args.mcptox_data_dir,
        agentpi_data_dir=args.agentpi_data_dir,
        mcptox_plus_data_dir=args.mcptox_plus_data_dir,
    )
    selected, summary = select_per_category(scenarios, args.per_category, seed=args.seed, categories=categories)
    if not selected:
        raise SystemExit("No scenarios selected. Check --benchmark, --categories, and data paths.")

    results_output = args.results_output or os.path.join(args.output_dir, "quick_benchmark_results.json")
    records_output = args.records_output or os.path.join(args.output_dir, "quick_benchmark_records.json")

    print("Selected scenarios by benchmark/category:")
    for key, count in summary.items():
        print(f"  {key}: {count}")
    print(f"Total selected attack scenarios: {len(selected)}")

    results = run_quick_evaluation(
        selected,
        model_name=args.model,
        seed=args.seed,
        agent_backend=args.agent_backend,
        agent_mock=args.agent_mock,
        agent_base_url=args.agent_base_url,
        agent_api_style=args.agent_api_style,
        agent_api_key_env=args.agent_api_key_env,
        agent_model_map=model_map,
        agent_timeout=args.agent_timeout,
        judge_mode=args.judge_mode,
        judge_provider=args.judge_provider,
        judge_model=args.judge_model,
        judge_base_url=args.judge_base_url,
        llamaguard_mock=args.llamaguard_mock,
        benign_ratio=args.benign_ratio,
        output_results=results_output,
        output_records=records_output,
    )

    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"Saved quick results to {results_output}")
    print(f"Saved quick records to {records_output}")


def _tag_benchmark(scenarios: Iterable[Mapping[str, Any]], benchmark: str) -> List[Dict[str, Any]]:
    tagged = []
    for raw in scenarios:
        item = dict(raw)
        item.setdefault("benchmark", benchmark)
        tagged.append(item)
    return tagged


def _make_agent(
    model_name: str,
    backend: str,
    mock_mode: bool,
    base_url: Optional[str],
    api_style: str,
    api_key_env: str,
    model_map: Optional[Mapping[str, str]],
    timeout: int,
):
    if backend == "proxy":
        return create_proxy_backbone(
            model_name=model_name,
            mock_mode=mock_mode,
            base_url=base_url,
            api_style=api_style,
            api_key_env=api_key_env,
            model_map=model_map,
            timeout=timeout,
        )
    return create_backbone(model_name, mock_mode=mock_mode)


def _tag_latest_rows(records: Dict[str, List[Dict[str, Any]]], scenario: Mapping[str, Any]):
    for rows in records.values():
        if rows:
            rows[-1]["benchmark"] = scenario.get("benchmark", "unknown")
            rows[-1]["sample_key"] = f"{scenario.get('benchmark', 'unknown')}::{scenario.get('category', 'unknown')}"


def _quick_detail_record(
    idx: int,
    scenario: Mapping[str, Any],
    is_attack: bool,
    agent_output: Mapping[str, Any],
    msg: Any,
    harmful: bool,
) -> Dict[str, Any]:
    record = _detail_record(idx, dict(scenario), is_attack, dict(agent_output), msg, harmful)
    record["benchmark"] = scenario.get("benchmark", "unknown")
    record["sample_key"] = f"{scenario.get('benchmark', 'unknown')}::{scenario.get('category', 'unknown')}"
    return record


def _parse_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_json_map(value: Optional[str], name: str) -> Optional[Dict[str, str]]:
    if not value:
        return None
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError(f"{name} must be a JSON object")
    return {str(k): str(v) for k, v in parsed.items()}


def _write_json(path: str, data: Any):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()


# 使用示例（PowerShell）：
#
# 1. 最小 smoke test：不调用真实模型，每个 MCPTox 类别抽 1 条。
# python experiments\run_quick_benchmark_by_category.py `
#   --benchmark mcptox `
#   --per_category 1 `
#   --synthetic `
#   --agent_mock
#
# 2. 使用中转站真实调用 GPT-4o，每个 MCPTox 类别抽 2 条。
# $env:LLM_API_KEY="你的中转站 key"
# $env:LLM_API_BASE_URL="https://llm-api.net/v1/chat/completions"
# python experiments\run_quick_benchmark_by_category.py `
#   --benchmark mcptox `
#   --per_category 2 `
#   --model GPT-4o
#
# 3. 跑 MCPTox+，每个类别抽 3 条，仍使用默认 heuristic judge。
# python experiments\run_quick_benchmark_by_category.py `
#   --benchmark mcptox_plus `
#   --per_category 3 `
#   --model GPT-4o
#
# 4. 三个 benchmark 都跑，每个 benchmark/category 只抽 1 条，适合快速看链路是否稳定。
# python experiments\run_quick_benchmark_by_category.py `
#   --benchmark all `
#   --per_category 1 `
#   --model GPT-4o
