import argparse
import json
import os
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


DEFAULT_INPUT_DIR = os.path.join("third", "MCPTox-Benchmark-main")
DEFAULT_OUTPUT_PATH = os.path.join("data", "mcptox", "mcptox_official.json")


def adapt_mcptox_benchmark(
    input_dir: str = DEFAULT_INPUT_DIR,
    output_path: str = DEFAULT_OUTPUT_PATH,
    include_responses: bool = False,
) -> Dict[str, Any]:
    """Convert raw MCPTox-Benchmark JSON into this project's official loader shape."""
    response_path = os.path.join(input_dir, "response_all.json")
    pure_tool_path = os.path.join(input_dir, "pure_tool.json")

    if not os.path.exists(response_path):
        raise FileNotFoundError(f"response_all.json not found: {response_path}")

    with open(response_path, encoding="utf-8") as f:
        response_all = json.load(f)

    pure_tool_entries = _count_pure_tools(pure_tool_path)
    scenarios = _build_scenarios(response_all, include_responses=include_responses)
    output = {
        "name": "MCPTox",
        "source": "MCPTox-Benchmark-main",
        "adapter": "src.benchmarks.adapt_mcptox_benchmark",
        "scenario_count": len(scenarios),
        "raw_metadata": {
            "input_dir": input_dir,
            "response_all_path": response_path,
            "pure_tool_path": pure_tool_path if os.path.exists(pure_tool_path) else None,
            "raw_data_length": response_all.get("data_length"),
            "server_count": len(response_all.get("servers", {}) or {}),
            "pure_tool_entries": pure_tool_entries,
            "attack_scopes": response_all.get("attack_scopes", []),
            "label_scopes": response_all.get("label_scopes", []),
            "call_behaviors": response_all.get("call_behaviors", []),
        },
        "scenarios": scenarios,
    }

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    return output


def _build_scenarios(
    response_all: Dict[str, Any],
    include_responses: bool = False,
) -> List[Dict[str, Any]]:
    scenarios: List[Dict[str, Any]] = []
    used_ids: set[str] = set()

    for server_key, server in _iter_servers(response_all):
        server_name = str(server.get("server_name") or server_key)
        tool_names = server.get("tool_names", [])
        server_url = server.get("server_url", "")

        for instance_index, instance in enumerate(server.get("malicious_instance", []) or []):
            metadata = instance.get("metadata", {}) or {}
            risk = str(metadata.get("security risk") or "").strip()
            paradigm = str(metadata.get("paradigm") or "").strip()
            risk_description = str(instance.get("security_risk_description") or "").strip()
            poisoned_tool = str(instance.get("poisoned_tool") or "").strip()

            for data_index, data in enumerate(instance.get("datas", []) or []):
                raw_id = data.get("id")
                scenario_id = _make_unique_id(raw_id, len(scenarios), used_ids)
                labels = _clean_mapping(data.get("label", {}) or {})
                query = str(data.get("query") or "")
                poisoned_content = str(data.get("poisoned_tool") or poisoned_tool)
                target_server, method = _map_server_method(server_name, tool_names, query)
                scenario = {
                    "scenario_id": scenario_id,
                    "original_id": raw_id,
                    "benchmark": "MCPTox",
                    "source": "MCPTox-Benchmark-main",
                    "category": "tool_description_poisoning",
                    "attack_layer": "L4",
                    "temporality": "T1",
                    "target_server": target_server,
                    "method": method,
                    "attack_vector": paradigm or "tool_poisoning",
                    "poisoned_content": poisoned_content,
                    "legitimate_content": query,
                    "target_action": _target_action(risk, risk_description),
                    "metadata": {
                        "raw_server_key": server_key,
                        "raw_server_name": server_name,
                        "raw_server_url": server_url,
                        "raw_instance_index": instance_index,
                        "raw_data_index": data_index,
                        "security_risk": risk,
                        "security_risk_description": risk_description,
                        "paradigm": paradigm,
                        "wrong_data": instance.get("wrong_data"),
                        "model_labels": labels,
                        "label_summary": dict(Counter(labels.values())),
                    },
                }
                if include_responses:
                    scenario["metadata"]["model_responses"] = _clean_mapping(data.get("response", {}) or {})
                    scenario["metadata"]["online_result"] = data.get("online_result")
                    scenario["metadata"]["raw_system_prompt"] = data.get("system")
                scenarios.append(scenario)

    return scenarios


def _iter_servers(response_all: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    servers = response_all.get("servers", {}) or {}
    if isinstance(servers, dict):
        for key, server in servers.items():
            if isinstance(server, dict):
                yield str(key), server
    elif isinstance(servers, list):
        for index, server in enumerate(servers):
            if isinstance(server, dict):
                key = str(server.get("server_name") or index)
                yield key, server


def _make_unique_id(raw_id: Any, index: int, used_ids: Set[str]) -> str:
    if raw_id is None or raw_id == "":
        base = f"mcptox_raw_{index:04d}"
    else:
        base = f"mcptox_raw_{str(raw_id).strip()}"

    candidate = base
    suffix = 1
    while candidate in used_ids:
        suffix += 1
        candidate = f"{base}_{suffix}"
    used_ids.add(candidate)
    return candidate


def _map_server_method(server_name: str, tool_names: List[str], query: str = "") -> Tuple[str, str]:
    lower_name = server_name.lower()
    lower_tools = " ".join(str(t).lower() for t in tool_names or [])
    lower_query = query.lower()

    if any(term in lower_name for term in ("email", "slack", "wechat", "dodo", "claude post")):
        return "email-server", "email/send"
    if any(term in lower_name for term in ("sqlite", "clickhouse", "redis", "prisma", "financial", "alphavantage", "op.gg")):
        return "db-server", "database/query"
    if any(term in lower_name for term in ("filesystem", "github", "gitlab", "git", "googledrive", "memory", "sentry")):
        if any(term in lower_query for term in ("write", "edit", "replace", "move", "create", "delete", "remove")):
            return "fs-server", "files/write"
        if "read" in lower_tools or any(term in lower_query for term in ("read", "list", "show", "search", "get", "what")):
            return "fs-server", "files/read"
        if any(term in lower_tools for term in ("write", "edit", "move", "create", "delete")):
            return "fs-server", "files/write"
        return "fs-server", "files/read"
    return "web-server", "web/search"


def _target_action(risk: str, risk_description: str) -> str:
    if risk and risk_description:
        return f"{risk}: {risk_description}"
    if risk:
        return f"Trigger a tool poisoning action causing {risk}"
    if risk_description:
        return risk_description
    return "Trigger a malicious action through poisoned MCP tool metadata"


def _clean_mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    return {}


def _count_pure_tools(pure_tool_path: str) -> Optional[int]:
    if not os.path.exists(pure_tool_path):
        return None
    with open(pure_tool_path, encoding="utf-8") as f:
        data = json.load(f)
    count = 0
    if isinstance(data, list):
        for server_group in data:
            if isinstance(server_group, dict):
                count += len(server_group)
    elif isinstance(data, dict):
        count = len(data)
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Adapt raw MCPTox-Benchmark data to mcptox_official.json.")
    parser.add_argument("--input_dir", default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH)
    parser.add_argument(
        "--include_responses",
        action="store_true",
        help="Preserve raw model responses and system prompts in scenario metadata.",
    )
    args = parser.parse_args()

    result = adapt_mcptox_benchmark(
        input_dir=args.input_dir,
        output_path=args.output,
        include_responses=args.include_responses,
    )
    print(f"Adapted MCPTox scenarios: {result['scenario_count']}")
    print(f"Saved to: {args.output}")


if __name__ == "__main__":
    main()
