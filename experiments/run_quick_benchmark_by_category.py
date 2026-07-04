import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_backbone import create_backbone
from src.agent_backbone_proxy import DEFAULT_PROXY_BASE_URL, create_proxy_backbone
from src.benchmarks.load_agentpi import load_agentpi
from src.benchmarks.load_mcptox import load_mcptox
from src.evaluation import live_table1
from src.judge import DEFAULT_LOCAL_JUDGE_MODEL
from src.runtime_audit import configure_audit, default_audit_log_path


DEFAULT_OUTPUT_DIR = "results/quick_eval"
DEFAULT_MODELS = ["GPT-4o", "Claude-3.5-Sonnet", "Gemini-1.5-Pro", "Llama-3.1-70B"]


def load_benchmark_scenarios(
    benchmark: str,
    seed: int = 42,
    official: bool = False,
    official_variant: str = "derived",
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
                official=official,
                official_variant=official_variant,
                mcptox_data_dir=mcptox_data_dir,
                agentpi_data_dir=agentpi_data_dir,
                mcptox_plus_data_dir=mcptox_plus_data_dir,
            ))
        return scenarios

    if selected == "mcptox":
        return _tag_benchmark(
            load_mcptox(
                data_dir=mcptox_data_dir,
                use_official=official,
                seed=seed,
                official_variant=official_variant,
            ),
            "MCPTox",
        )
    if selected == "agentpi":
        return _tag_benchmark(
            load_agentpi(data_dir=agentpi_data_dir, use_official=official, seed=seed),
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


def summarize_selected(scenarios: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    summary: Dict[str, int] = defaultdict(int)
    for raw in scenarios:
        category = str(raw.get("category") or raw.get("attack_vector") or "unknown")
        benchmark = str(raw.get("benchmark") or raw.get("source") or "unknown")
        summary[f"{benchmark}::{category}"] += 1
    return dict(sorted(summary.items()))


def run_quick_evaluation(
    scenarios: List[Mapping[str, Any]],
    model_name: str = "GPT-4o",
    runs: int = 1,
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
    judge_model: str = DEFAULT_LOCAL_JUDGE_MODEL,
    judge_base_url: Optional[str] = None,
    judge_failure_policy: str = "record_invalid",
    llamaguard_mock: bool = False,
    llamaguard_model: str = "meta-llama/LlamaGuard-3-8B",
    llamaguard_device: str = "auto",
    llamaguard_fail_fast: bool = False,
    benign_ratio: float = 0.30,
    output_results: Optional[str] = None,
    output_records: Optional[str] = None,
    ptg_embedding_model: Optional[str] = None,
    ptg_embedding_device: str = "auto",
    ptg_embedding_threshold: float = 0.45,
    ptg_embedding_fail_fast: bool = False,
) -> Dict[str, Dict[str, float]]:
    agent_factory = _make_agent_factory(
        backend=agent_backend,
        base_url=agent_base_url,
        api_style=agent_api_style,
        api_key_env=agent_api_key_env,
        model_map=agent_model_map,
        timeout=agent_timeout,
    )

    results = live_table1.run_live_table1_scenarios_multi(
        scenarios=[dict(s) for s in scenarios],
        runs=runs,
        model_name=model_name,
        seed=seed,
        agent_mock=agent_mock,
        judge_mode=judge_mode,
        judge_provider=judge_provider,
        judge_model=judge_model,
        judge_base_url=judge_base_url,
        judge_failure_policy=judge_failure_policy,
        llamaguard_mock=llamaguard_mock,
        llamaguard_model=llamaguard_model,
        llamaguard_device=llamaguard_device,
        llamaguard_fail_fast=llamaguard_fail_fast,
        benign_ratio=benign_ratio,
        output_records=output_records,
        agent_factory=agent_factory,
        ptg_embedding_model=ptg_embedding_model,
        ptg_embedding_device=ptg_embedding_device,
        ptg_embedding_threshold=ptg_embedding_threshold,
        ptg_embedding_fail_fast=ptg_embedding_fail_fast,
    )
    if output_results:
        _write_json(output_results, results)
    return results


def main():
    parser = argparse.ArgumentParser(description="Run a small per-category sample through the live Table 1 evaluation path.")
    parser.add_argument("--model", default="GPT-4o")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--max_scenarios", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--data_dir", default="data/mcptox")
    parser.add_argument(
        "--official",
        action="store_true",
        help=(
            "Use the explicitly selected official/adapted benchmark variant."
        ),
    )
    parser.add_argument(
        "--official_variant",
        choices=["derived", "curated", "legacy"],
        default="derived",
        help="MCPTox dataset selected when --official is enabled.",
    )
    parser.add_argument("--agent_mock", action="store_true", help="Use mock agent for smoke tests.")
    parser.add_argument("--judge_mode", choices=["heuristic", "llm"], default="heuristic")
    parser.add_argument("--judge_provider", default="vllm")
    parser.add_argument("--judge_model", default=DEFAULT_LOCAL_JUDGE_MODEL)
    parser.add_argument("--judge_base_url", default=live_table1.default_judge_base_url())
    parser.add_argument(
        "--judge_failure_policy",
        choices=["record_invalid", "inherit", "fallback", "raise"],
        default="record_invalid",
        help="Judge failure handling; record_invalid logs and excludes only the affected defense row.",
    )
    parser.add_argument("--llamaguard_mock", action="store_true")
    parser.add_argument("--llamaguard_model", default="meta-llama/LlamaGuard-3-8B")
    parser.add_argument("--llamaguard_device", default="auto")
    parser.add_argument("--llamaguard_fail_fast", action="store_true")
    parser.add_argument("--benign_ratio", type=float, default=0.30)
    parser.add_argument("--output", default=os.path.join(DEFAULT_OUTPUT_DIR, "quick_benchmark_results.json"))
    parser.add_argument("--tex_output", default=os.path.join(DEFAULT_OUTPUT_DIR, "quick_benchmark_table.tex"))
    parser.add_argument("--records_output", default=os.path.join(DEFAULT_OUTPUT_DIR, "quick_benchmark_records.json"))
    parser.add_argument("--benchmark", choices=["mcptox", "agentpi", "mcptox_plus", "all"], default="mcptox")
    parser.add_argument("--per_category", type=int, default=2)
    parser.add_argument("--categories", default="", help="Comma-separated category filter after loading the benchmark.")
    parser.add_argument("--agent_backend", choices=["proxy", "default"], default="proxy")
    parser.add_argument("--agent_base_url", default=os.environ.get("LLM_API_BASE_URL", DEFAULT_PROXY_BASE_URL))
    parser.add_argument("--agent_api_style", choices=["auto", "chat", "responses"], default="chat")
    parser.add_argument("--agent_api_key_env", default="LLM_API_KEY")
    parser.add_argument("--agent_model_map", default=None)
    parser.add_argument("--agent_timeout", type=int, default=60)
    parser.add_argument("--ptg_embedding_model", default=os.environ.get("PTG_EMBEDDING_MODEL"))
    parser.add_argument("--ptg_embedding_device", default="auto")
    parser.add_argument("--ptg_embedding_threshold", type=float, default=0.45)
    parser.add_argument("--ptg_embedding_fail_fast", action="store_true")
    parser.add_argument(
        "--effect_sidecar",
        default=os.environ.get("MALICIOUS_EFFECT_SIDECAR"),
        help="Reviewed scenario_id -> malicious_effects JSON; omitted uses deterministic derivation from references.",
    )
    parser.add_argument("--mcptox_data_dir", default=None)
    parser.add_argument("--agentpi_data_dir", default="data/agentpi")
    parser.add_argument("--mcptox_plus_data_dir", default="data/mcptox_plus")
    parser.add_argument("--results_output", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--audit_log", default=None, help="JSONL runtime audit log path. Defaults to <output>_audit.jsonl.")
    parser.add_argument("--no_audit_log", action="store_true", help="Disable runtime audit log.")
    parser.add_argument("--strict_runtime", action="store_true", help="Enable strict handling for agent failures and legacy inherit/fallback paths; record_invalid still excludes defense-model failures per row.")
    args = parser.parse_args()

    model_map = _parse_json_map(args.agent_model_map, "--agent_model_map")
    categories = _parse_csv(args.categories)
    scenarios = load_benchmark_scenarios(
        args.benchmark,
        seed=args.seed,
        official=args.official,
        official_variant=args.official_variant,
        mcptox_data_dir=args.mcptox_data_dir or args.data_dir,
        agentpi_data_dir=args.agentpi_data_dir,
        mcptox_plus_data_dir=args.mcptox_plus_data_dir,
    )
    if args.effect_sidecar:
        scenarios = _apply_effect_sidecar(scenarios, args.effect_sidecar)
    selected, summary = select_per_category(scenarios, args.per_category, seed=args.seed, categories=categories)
    selected = selected[:args.max_scenarios]
    summary = summarize_selected(selected)
    if not selected:
        raise SystemExit("No scenarios selected. Check --benchmark, --categories, and data paths.")

    results_output = args.results_output or args.output
    records_output = args.records_output
    audit_log = None if args.no_audit_log else (args.audit_log or default_audit_log_path(results_output))
    configure_audit(audit_log, strict_runtime=args.strict_runtime)

    print("Selected scenarios by benchmark/category:")
    for key, count in summary.items():
        print(f"  {key}: {count}")
    print(f"Total selected attack scenarios: {len(selected)}")

    results = run_quick_evaluation(
        selected,
        model_name=args.model,
        runs=args.runs,
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
        judge_failure_policy=args.judge_failure_policy,
        llamaguard_mock=args.llamaguard_mock,
        llamaguard_model=args.llamaguard_model,
        llamaguard_device=args.llamaguard_device,
        llamaguard_fail_fast=args.llamaguard_fail_fast,
        benign_ratio=args.benign_ratio,
        output_results=results_output,
        output_records=records_output,
        ptg_embedding_model=args.ptg_embedding_model,
        ptg_embedding_device=args.ptg_embedding_device,
        ptg_embedding_threshold=args.ptg_embedding_threshold,
        ptg_embedding_fail_fast=args.ptg_embedding_fail_fast,
    )

    metadata = {
        "git_commit": _git_commit(),
        "scenario_sha256": hashlib.sha256(
            json.dumps(selected, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest(),
        "effect_sidecar": args.effect_sidecar,
        "effect_sidecar_sha256": _file_sha256(args.effect_sidecar),
        "benchmark": args.benchmark,
        "official": args.official,
        "official_variant": args.official_variant,
        "model": args.model,
        "runs": args.runs,
        "seed": args.seed,
        "strict_runtime": args.strict_runtime,
        "judge": {
            "provider": args.judge_provider,
            "model": args.judge_model,
            "base_url": args.judge_base_url,
            "failure_policy": args.judge_failure_policy,
        },
        "ptg": {
            "embedding_model": args.ptg_embedding_model,
            "embedding_device": args.ptg_embedding_device,
            "embedding_threshold": args.ptg_embedding_threshold,
            "embedding_fail_fast": args.ptg_embedding_fail_fast,
        },
        "llamaguard": {
            "model": args.llamaguard_model,
            "device": args.llamaguard_device,
            "fail_fast": args.llamaguard_fail_fast,
        },
    }
    _write_json(f"{results_output}.metadata.json", metadata)

    live_table1.write_table1_tex(results, args.tex_output, include_ci=args.runs > 1)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"Saved quick results to {results_output}")
    print(f"Saved quick records to {records_output}")
    print(f"Saved quick LaTeX table to {args.tex_output}")
    if audit_log:
        print(f"Saved runtime audit log to {audit_log}")


def _tag_benchmark(scenarios: Iterable[Mapping[str, Any]], benchmark: str) -> List[Dict[str, Any]]:
    tagged = []
    for raw in scenarios:
        item = dict(raw)
        item.setdefault("benchmark", benchmark)
        tagged.append(item)
    return tagged


def _make_agent_factory(
    backend: str,
    base_url: Optional[str],
    api_style: str,
    api_key_env: str,
    model_map: Optional[Mapping[str, str]],
    timeout: int,
):
    def factory(model_name: str, mock_mode: bool = True, api_key: Optional[str] = None):
        if backend != "proxy":
            return create_backbone(model_name, mock_mode=mock_mode, api_key=api_key)
        return create_proxy_backbone(
            model_name=model_name,
            mock_mode=mock_mode,
            api_key=api_key,
            base_url=base_url,
            api_style=api_style,
            api_key_env=api_key_env,
            model_map=model_map,
            timeout=timeout,
        )
    return factory


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


def _git_commit() -> Optional[str]:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _file_sha256(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _apply_effect_sidecar(
    scenarios: List[Dict[str, Any]], path: str
) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    mapping = raw.get("effects", raw) if isinstance(raw, dict) else None
    if not isinstance(mapping, dict):
        raise ValueError("Effect sidecar must be an object keyed by scenario_id")
    enriched = []
    missing = []
    for scenario in scenarios:
        item = dict(scenario)
        scenario_id = str(item.get("scenario_id") or item.get("original_id") or "")
        entry = mapping.get(scenario_id)
        reviewed = entry.get("reviewed") if isinstance(entry, dict) else False
        effects = entry.get("effects") if isinstance(entry, dict) else entry
        if reviewed is not True or not isinstance(effects, list) or not effects:
            missing.append(scenario_id)
        else:
            template = dict(item.get("template", {}) or {})
            template["malicious_effects"] = effects
            item["template"] = template
        enriched.append(item)
    if missing:
        raise ValueError(
            f"Effect sidecar has {len(missing)} missing or unreviewed scenarios; first={missing[0]}"
        )
    return enriched


if __name__ == "__main__":
    main()


# 使用示例（PowerShell）：
#
# 1. 最小 smoke test：不调用真实模型，每个 MCPTox 类别抽 1 条。
# python experiments\run_quick_benchmark_by_category.py `
#   --benchmark mcptox `
#   --per_category 1 `
#   --agent_mock
#
# 2. 使用中转站真实调用 GPT-4o，并用本地 Qwen judge，每个 MCPTox 类别抽 2 条。
# $env:LLM_API_KEY="你的中转站 key"
# $env:LLM_API_BASE_URL="https://llm-api.net/v1/chat/completions"
# python experiments\run_quick_benchmark_by_category.py `
#   --benchmark mcptox `
#   --per_category 2 `
#   --model GPT-4o `
#   --judge_mode llm
#
# 3. 跑 MCPTox+，每个类别抽 3 条，仍走主表 evaluation 链路。
# python experiments\run_quick_benchmark_by_category.py `
#   --benchmark mcptox_plus `
#   --per_category 3 `
#   --model GPT-4o `
#   --judge_mode llm
#
# 4. 三个 benchmark 都跑，每个 benchmark/category 只抽 1 条，适合快速看链路是否稳定。
# python experiments\run_quick_benchmark_by_category.py `
#   --benchmark all `
#   --per_category 1 `
#   --model GPT-4o
#
# 5. 使用中转站 GPT-4o agent + 自部署 Qwen judge 跑 MCPTox 主表链路（Linux/bash）。
# judge 服务地址参数是 --judge_base_url。
# 数据集默认使用 synthetic 200 条；显式加 --official 后优先读取 MCPTox-derived 200 条，
# 缺失时再回退到 legacy adapted official。
# export LLM_API_KEY="你的中转站 key"
# python experiments/run_quick_benchmark_by_category.py \
#   --benchmark mcptox \
#   --per_category 5 \
#   --categories "" \
#   --max_scenarios 200 \
#   --runs 3 \
#   --seed 42 \
#   --data_dir data/mcptox \
#   --model GPT-4o \
#   --agent_backend proxy \
#   --agent_base_url https://llm-api.net/v1/chat/completions \
#   --agent_api_style chat \
#   --agent_api_key_env LLM_API_KEY \
#   --agent_model_map '{"GPT-4o":"gpt-4o"}' \
#   --agent_timeout 60 \
#   --judge_mode llm \
#   --judge_provider vllm \
#   --judge_model qwen2.5-7B-Instruct \
#   --judge_base_url http://aias-compute-4:14545/v1/chat/completions \
#   --judge_failure_policy record_invalid \
#   --llamaguard_model /home/liuenguang24/models/LlamaGuard-3-8B \
#   --llamaguard_device auto \
#   --llamaguard_fail_fast \
#   --benign_ratio 0.30 \
#   --output results/quick_eval/table1_gpt4o_qwen_judge_results.json \
#   --tex_output results/quick_eval/table1_gpt4o_qwen_judge.tex \
#   --records_output results/quick_eval/table1_gpt4o_qwen_judge_records.json
#
# 常用可改参数：
#   --model: 实验展示用 agent 名称，例如 GPT-4o、Claude-3.5-Sonnet、Gemini-1.5-Pro、Llama-3.1-70B。
#   --agent_base_url: 中转站 Chat Completions endpoint。
#   --agent_model_map: 把实验模型名映射到中转站实际 model id；如果中转站直接支持 gpt-4o，可保持上面的写法。
#   --judge_base_url: 自部署 judge 的 Chat Completions endpoint。
#   --judge_model: 自部署 judge 服务接受的 model 字段。
#   --llamaguard_model: LlamaGuard 的 Hugging Face model id 或 transformers-compatible 本地目录。
#   --llamaguard_device: 传给 transformers device_map 的值，例如 auto、cuda:0、cpu。
#   --llamaguard_fail_fast: LlamaGuard 加载失败时直接报错，正式实验建议加。
#   --official: 使用 MCPTox-derived 200 条时加；不加则保持 synthetic 200 口径。
#   --per_category / --max_scenarios / --runs / --seed: 控制抽样规模、总样本数、多次运行和随机种子。
#   --benign_ratio: 每个 attack scenario 附带 benign case 的概率；主表默认 0.30。
#   --output / --tex_output / --records_output: JSON 结果、LaTeX 表格和逐样本记录输出路径。
#   --agent_mock: 只做 smoke test 时使用；正式实验不要加。
#   --llamaguard_mock: 没有本地 LlamaGuard 时可加；正式比较 Guardrail baseline 时不要加。
