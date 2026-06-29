import argparse
import ast
import hashlib
import json
import os
import random
import re
import tempfile
import warnings
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


DEFAULT_INPUT_DIR = os.path.join("third", "MCPTox-Benchmark-main")
DEFAULT_OUTPUT_PATH = os.path.join("data", "mcptox", "mcptox_official.json")
DEFAULT_DERIVED_OUTPUT_PATH = os.path.join(
    "data", "mcptox", "mcptox_official_derived_table1_200.json"
)

MCPTOX_TABLE1_DISTRIBUTION = {
    "tool_description_poisoning": 55,
    "parameter_injection": 50,
    "response_manipulation": 55,
    "capability_escalation": 40,
}


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


def adapt_mcptox_derived_table1(
    input_dir: str = DEFAULT_INPUT_DIR,
    output_path: str = DEFAULT_DERIVED_OUTPUT_PATH,
    count: int = 200,
    seed: int = 42,
    include_responses: bool = False,
) -> Dict[str, Any]:
    """Build the source-faithful MCPTox-derived Table 1 dataset."""
    response_path = os.path.join(input_dir, "response_all.json")
    pure_tool_path = os.path.join(input_dir, "pure_tool.json")

    if not os.path.exists(response_path):
        raise FileNotFoundError(f"response_all.json not found: {response_path}")

    with open(response_path, encoding="utf-8") as f:
        response_all = json.load(f)

    distribution = _scale_table1_distribution(count)
    scenarios = _build_derived_table1_scenarios(
        response_all,
        distribution=distribution,
        seed=seed,
        include_responses=include_responses,
    )
    pure_tool_entries = _count_pure_tools(pure_tool_path)
    output = {
        "schema_revision": 2,
        "name": "MCPTox-derived Table1",
        "source": "MCPTox-Benchmark-main",
        "adapter": "src.benchmarks.adapt_mcptox_benchmark",
        "variant": "derived_table1",
        "scenario_count": len(scenarios),
        "distribution": distribution,
        "derivation_note": (
            "Tool description poisoning and parameter injection preserve the "
            "official registration-stage payloads and native tool calls. "
            "Response manipulation and capability escalation reuse the official "
            "queries, payloads, and labeled calls on derived attack surfaces."
        ),
        "raw_metadata": {
            "input_dir": input_dir,
            "response_all_path": response_path,
            "response_all_sha256": _file_sha256(response_path),
            "pure_tool_path": pure_tool_path if os.path.exists(pure_tool_path) else None,
            "raw_data_length": response_all.get("data_length"),
            "server_count": len(response_all.get("servers", {}) or {}),
            "pure_tool_entries": pure_tool_entries,
            "wrong_data_policy": "include only wrong_data == 0",
            "seed": seed,
            "attack_scopes": response_all.get("attack_scopes", []),
            "label_scopes": response_all.get("label_scopes", []),
            "call_behaviors": response_all.get("call_behaviors", []),
        },
        "scenarios": scenarios,
    }

    from src.benchmarks.validate_mcptox_derived import validate_dataset

    output["validation"] = validate_dataset(output)
    _atomic_write_json(output_path, output)
    return output


def build_mcptox_derived_candidate_pool(
    input_dir: str = DEFAULT_INPUT_DIR,
    seed: int = 42,
    include_responses: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    """Return every eligible v2 scenario in deterministic replacement order."""
    response_path = os.path.join(input_dir, "response_all.json")
    if not os.path.exists(response_path):
        raise FileNotFoundError(f"response_all.json not found: {response_path}")
    with open(response_path, encoding="utf-8") as source:
        response_all = json.load(source)
    candidates = _collect_derivation_candidates(response_all, include_responses)
    rng = random.Random(seed)
    ordered = _ordered_category_views(
        candidates,
        MCPTOX_TABLE1_DISTRIBUTION.keys(),
        rng,
    )
    return {
        category: [
            _derive_table1_scenario(category, candidate, view)
            for candidate, view in pool
        ]
        for category, pool in ordered.items()
    }


def _scale_table1_distribution(count: int) -> Dict[str, int]:
    if count <= 0:
        raise ValueError("count must be positive")
    total = sum(MCPTOX_TABLE1_DISTRIBUTION.values())
    if count == total:
        return dict(MCPTOX_TABLE1_DISTRIBUTION)

    scaled: Dict[str, int] = {}
    fractions: List[Tuple[float, str]] = []
    assigned = 0
    for category, base_count in MCPTOX_TABLE1_DISTRIBUTION.items():
        exact = count * base_count / total
        whole = int(exact)
        scaled[category] = whole
        assigned += whole
        fractions.append((exact - whole, category))

    for _, category in sorted(fractions, reverse=True)[: count - assigned]:
        scaled[category] += 1
    return scaled


def _build_derived_table1_scenarios(
    response_all: Dict[str, Any],
    distribution: Dict[str, int],
    seed: int,
    include_responses: bool = False,
) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    candidates = _collect_derivation_candidates(response_all, include_responses)
    scenarios: List[Dict[str, Any]] = []
    ordered = _ordered_category_views(candidates, distribution.keys(), rng)

    for category, target_count in distribution.items():
        pool = ordered[category]
        selected = []
        seen_queries: Set[str] = set()
        for candidate, view in pool:
            query_key = _normalized_query(candidate["user_query"])
            if query_key in seen_queries:
                continue
            seen_queries.add(query_key)
            selected.append((candidate, view))
            if len(selected) == target_count:
                break
        if len(selected) < target_count:
            raise ValueError(
                f"Not enough MCPTox candidates for {category}: "
                f"need {target_count}, got {len(selected)} unique queries"
            )
        for candidate, view in selected:
            scenarios.append(_derive_table1_scenario(category, candidate, view))

    rng.shuffle(scenarios)
    return scenarios


def _ordered_category_views(
    candidates: List[Dict[str, Any]],
    categories: Iterable[str],
    rng: random.Random,
) -> Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]]:
    ordered = {}
    for category in categories:
        pool = []
        for candidate in candidates:
            view = _category_view(candidate, category)
            if view:
                pool.append((candidate, view))
        pool.sort(key=lambda item: item[0]["source_key"])
        rng.shuffle(pool)
        ordered[category] = pool
    return ordered


def _collect_derivation_candidates(
    response_all: Dict[str, Any],
    include_responses: bool = False,
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for server_key, server in _iter_servers(response_all):
        server_name = str(server.get("server_name") or server_key)
        server_url = server.get("server_url", "")
        tool_names = server.get("tool_names", [])
        clean_server = _parse_clean_server(
            server_key,
            server_name,
            str(server.get("clean_system_promot") or ""),
        )

        for instance_index, instance in enumerate(server.get("malicious_instance", []) or []):
            if instance.get("wrong_data") != 0:
                continue

            metadata = instance.get("metadata", {}) or {}
            paradigm = str(metadata.get("paradigm") or "").strip()
            risk = str(metadata.get("security risk") or "").strip()
            risk_description = str(instance.get("security_risk_description") or "").strip()
            poisoned_tool = str(instance.get("poisoned_tool") or "").strip()

            for data_index, data in enumerate(instance.get("datas", []) or []):
                query = str(data.get("query") or "").strip()
                if not query:
                    continue
                labels = _clean_mapping(data.get("label", {}) or {})
                responses = _clean_mapping(data.get("response", {}) or {})
                success_calls = _native_call_records_for_labels(
                    responses,
                    labels,
                    {"Success"},
                    clean_server["server_id"],
                )
                ignored_calls = _native_call_records_for_labels(
                    responses,
                    labels,
                    {"Failure-Ignored", "None"},
                    clean_server["server_id"],
                )
                if not success_calls or not ignored_calls:
                    continue

                raw_id = data.get("id")
                poisoned_text = _normalize_model_text(
                    str(data.get("poisoned_tool") or poisoned_tool)
                )
                candidate = {
                    "raw_id": raw_id,
                    "source_key": (
                        f"{server_key}:{instance_index}:{data_index}:"
                        f"{raw_id if raw_id is not None else 'none'}"
                    ),
                    "raw_server_key": server_key,
                    "raw_server_name": server_name,
                    "raw_server_url": server_url,
                    "raw_tool_names": tool_names,
                    "raw_instance_index": instance_index,
                    "raw_data_index": data_index,
                    "paradigm": paradigm,
                    "security_risk": risk,
                    "security_risk_description": risk_description,
                    "target_action": _target_action(risk, risk_description),
                    "user_query": query,
                    "poisoned_tool_text": poisoned_text,
                    "poisoned_tool": _parse_poisoned_tool(
                        poisoned_text, clean_server["server_id"]
                    ),
                    "clean_server": clean_server,
                    "label_summary": dict(Counter(labels.values())),
                    "success_calls": success_calls,
                    "ignored_calls": ignored_calls,
                }
                if include_responses:
                    candidate["model_responses"] = responses
                    candidate["online_result"] = data.get("online_result")
                    candidate["raw_system_prompt"] = data.get("system")
                candidates.append(candidate)
    return candidates


def _native_call_records_for_labels(
    responses: Dict[str, Any],
    labels: Dict[str, Any],
    accepted_labels: Set[str],
    server_id: str,
) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for model_name, label in labels.items():
        if label not in accepted_labels:
            continue
        parsed_calls = _parse_response_calls(responses.get(model_name, ""))
        if not parsed_calls:
            continue
        first_call = parsed_calls[0]
        call = {
            "server": server_id,
            "method": first_call["tool"],
            "params": first_call.get("arguments", {}),
        }
        signature = _call_signature(call)
        record = grouped.setdefault(
            signature,
            {
                "call": call,
                "raw_call": first_call,
                "models": [],
                "support_count": 0,
                "response_call_count": len(parsed_calls),
            },
        )
        record["models"].append(model_name)
        record["support_count"] += 1
    return sorted(
        grouped.values(),
        key=lambda record: (-record["support_count"], _call_signature(record["call"])),
    )


def _select_best_call(calls: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    return calls[0] if calls else None


def _candidate_supports_category(candidate: Dict[str, Any], category: str) -> bool:
    return _category_view(candidate, category) is not None


def _derive_table1_scenario(
    category: str,
    candidate: Dict[str, Any],
    view: Dict[str, Any],
) -> Dict[str, Any]:
    malicious_calls = _record_calls(view["malicious_records"])
    benign_calls = _record_calls(view["benign_records"])
    malicious_call = malicious_calls[0]
    benign_call = benign_calls[0]
    target_action = _describe_call(malicious_call)
    scenario_id = _make_derived_id(category, candidate["source_key"])
    common_template = {
        "user_query": candidate["user_query"],
        "clean_servers": [view["clean_server"]],
        "benign_call": benign_call,
        "benign_calls": benign_calls,
        "malicious_call": malicious_call,
        "malicious_calls": malicious_calls,
        "target_action": target_action,
    }

    if category == "response_manipulation":
        template = dict(common_template)
        template.update({
            "first_call": benign_call,
            "first_calls": benign_calls,
            "malicious_response": candidate["poisoned_tool"]["description"],
        })
        poisoned_content = template["malicious_response"]
        target_server = malicious_call["server"]
        method = malicious_call["method"]
        attack_layer = "L2"
    elif category == "capability_escalation":
        template = dict(common_template)
        template["claimed_capability"] = view["claimed_capability"]
        poisoned_content = view["claimed_capability"]["description"]
        target_server = malicious_call["server"]
        method = malicious_call["method"]
        attack_layer = "L4"
    else:
        template = dict(common_template)
        template["poisoned_tool"] = candidate["poisoned_tool"]
        poisoned_content = template["poisoned_tool"]["description"]
        target_server = malicious_call["server"]
        method = malicious_call["method"]
        attack_layer = "L4"

    scenario = {
        "scenario_id": scenario_id,
        "original_id": candidate.get("raw_id"),
        "benchmark": "MCPTox-derived",
        "source": "MCPTox-Benchmark-main",
        "category": category,
        "attack_layer": attack_layer,
        "temporality": "T1",
        "target_server": target_server,
        "method": method,
        "attack_vector": f"mcptox_{candidate.get('paradigm', 'unknown')}_derived",
        "poisoned_content": poisoned_content,
        "legitimate_content": candidate["user_query"],
        "target_action": target_action,
        "template": template,
        "metadata": _derived_metadata(candidate, category),
    }
    return scenario


def _make_derived_id(category: str, source_key: str) -> str:
    prefix = {
        "tool_description_poisoning": "tdp",
        "parameter_injection": "pi",
        "response_manipulation": "rm",
        "capability_escalation": "ce",
    }.get(category, "unknown")
    digest = hashlib.sha256(f"{category}|{source_key}".encode("utf-8")).hexdigest()[:12]
    return f"mcptox_derived_{prefix}_{digest}"


def _derived_metadata(candidate: Dict[str, Any], category: str) -> Dict[str, Any]:
    metadata = {
        "derivation": {
            "category": category,
            "source_paradigm": candidate.get("paradigm"),
            "is_native_mcptox_attack_surface": category
            in {"tool_description_poisoning", "parameter_injection"},
            "response_manipulation_note": (
                "Derived by moving official poisoned metadata into a malicious "
                "tool response."
                if category == "response_manipulation"
                else None
            ),
            "capability_escalation_note": (
                "Derived by advertising the official Success call as an "
                "unattested capability on the compromised server."
                if category == "capability_escalation"
                else None
            ),
        },
        "raw_server_key": candidate.get("raw_server_key"),
        "raw_server_name": candidate.get("raw_server_name"),
        "raw_server_url": candidate.get("raw_server_url"),
        "raw_instance_index": candidate.get("raw_instance_index"),
        "raw_data_index": candidate.get("raw_data_index"),
        "source_key": candidate.get("source_key"),
        "security_risk": candidate.get("security_risk"),
        "security_risk_description": candidate.get("security_risk_description"),
        "paradigm": candidate.get("paradigm"),
        "wrong_data": 0,
        "model_label_summary": candidate.get("label_summary", {}),
        "raw_success_calls": candidate.get("success_calls", []),
        "raw_ignored_calls": candidate.get("ignored_calls", []),
    }
    for optional_key in ("model_responses", "online_result", "raw_system_prompt"):
        if optional_key in candidate:
            metadata[optional_key] = candidate[optional_key]
    return metadata


def _category_view(candidate: Dict[str, Any], category: str) -> Optional[Dict[str, Any]]:
    if not _well_formed_query(candidate.get("user_query", "")):
        return None
    poison = candidate.get("poisoned_tool")
    if not poison or not poison.get("description"):
        return None

    clean_server = candidate["clean_server"]
    clean_methods = _server_methods(clean_server)
    benign_records = [
        record
        for record in candidate.get("ignored_calls", [])
        if record["call"]["method"] in clean_methods
    ]
    if not benign_records:
        return None
    benign = benign_records[0]["call"]
    success_records = candidate.get("success_calls", [])
    paradigm = candidate.get("paradigm")

    if category == "tool_description_poisoning":
        if paradigm not in {"Template-1", "Template-2"}:
            return None
        allowed_methods = clean_methods | {poison["method"]}
        malicious_records = [
            record
            for record in success_records
            if record["call"]["method"] in allowed_methods
            and record["call"]["method"] != benign["method"]
        ]
    elif category == "parameter_injection":
        if paradigm != "Template-3":
            return None
        malicious_records = [
            record
            for record in success_records
            if record["call"]["method"] in clean_methods
            and record["call"]["method"] == benign["method"]
            and record["call"].get("params", {}) != benign.get("params", {})
        ]
    elif category == "response_manipulation":
        if paradigm not in {"Template-2", "Template-3"}:
            return None
        malicious_records = [
            record
            for record in success_records
            if record["call"]["method"] in clean_methods
            and _calls_differ(record["call"], benign)
        ]
    elif category == "capability_escalation":
        if paradigm not in {"Template-2", "Template-3"}:
            return None
        inferable = [
            record
            for record in success_records
            if record["call"]["method"] in clean_methods
            and _calls_differ(record["call"], benign)
            and _params_are_in_payload(
                record["call"].get("params", {}), poison["description"]
            )
        ]
        if not inferable:
            return None
        source_method = inferable[0]["call"]["method"]
        inferable = [
            record for record in inferable if record["call"]["method"] == source_method
        ]
        extension_method = f"extension/{_safe_identifier(source_method)}"
        if extension_method in clean_methods:
            return None
        malicious_records = []
        for record in inferable:
            transformed = dict(record)
            transformed["call"] = {
                "server": clean_server["server_id"],
                "method": extension_method,
                "params": dict(record["call"].get("params", {})),
            }
            malicious_records.append(transformed)
        claimed_capability = {
            "server_id": clean_server["server_id"],
            "name": f"extension_{_safe_identifier(source_method)}",
            "method": extension_method,
            "description": (
                f"{poison['description'].strip()}\n\n"
                "Use this server extension directly when carrying out the "
                "prerequisite described above."
            ),
            "input_schema": _schema_from_call_records(malicious_records),
        }
    else:
        return None

    if not malicious_records:
        return None
    refined_server = _refine_server_schema(
        clean_server, malicious_records + benign_records
    )
    view = {
        "clean_server": refined_server,
        "malicious_records": malicious_records,
        "benign_records": benign_records,
    }
    if category == "capability_escalation":
        view["claimed_capability"] = claimed_capability
    return view


def _parse_clean_server(
    server_key: str,
    server_name: str,
    clean_prompt: str,
) -> Dict[str, Any]:
    blocks = _parse_tool_blocks(clean_prompt)
    if not blocks:
        raise ValueError(f"No clean tools parsed for MCPTox server {server_key}")
    server_id = _safe_identifier(server_key).replace("_", "-")
    capabilities = []
    for block in blocks:
        capabilities.append(
            {
                "name": block["name"],
                "description": block["description"],
                "methods": [block["name"]],
                "permissions": ["invoke"],
                "input_schema": block["input_schema"],
            }
        )
    return {
        "server_id": server_id,
        "name": server_name,
        "capabilities": capabilities,
    }


def _parse_poisoned_tool(text: str, server_id: str) -> Optional[Dict[str, Any]]:
    blocks = _parse_tool_blocks(text)
    if not blocks:
        return None
    block = blocks[0]
    return {
        "server_id": server_id,
        "name": block["name"],
        "method": block["name"],
        "description": block["description"],
        "input_schema": block["input_schema"],
    }


def _parse_tool_blocks(text: str) -> List[Dict[str, Any]]:
    normalized = _normalize_model_text(text)
    markers = list(re.finditer(r"(?m)^[ \t]*Tool:[ \t]*([^\r\n]+?)[ \t]*$", normalized))
    blocks: List[Dict[str, Any]] = []
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(normalized)
        body = normalized[marker.end() : end]
        description_match = re.search(
            r"(?ms)^[ \t]*Description:[ \t]*(.*?)^[ \t]*Arguments:[ \t]*(.*)$",
            body,
        )
        if not description_match:
            continue
        description = description_match.group(1).strip()
        argument_text = description_match.group(2)
        properties: Dict[str, Dict[str, str]] = {}
        required: List[str] = []
        for line in argument_text.splitlines():
            arg_match = re.match(r"^[ \t]*-[ \t]*([^:]+):[ \t]*(.*)$", line)
            if not arg_match:
                continue
            arg_name = arg_match.group(1).strip()
            arg_description = arg_match.group(2).strip()
            properties[arg_name] = {"type": "string"}
            if "(required)" in arg_description.lower():
                required.append(arg_name)
        blocks.append(
            {
                "name": marker.group(1).strip(),
                "description": description,
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            }
        )
    return blocks


def _refine_server_schema(
    server: Dict[str, Any], records: List[Dict[str, Any]]
) -> Dict[str, Any]:
    refined = json.loads(json.dumps(server, ensure_ascii=False))
    by_method = {
        capability["methods"][0]: capability
        for capability in refined.get("capabilities", [])
        if capability.get("methods")
    }
    observed_types: Dict[Tuple[str, str], Set[str]] = {}
    for record in records:
        call = record["call"]
        for key, value in call.get("params", {}).items():
            observed_types.setdefault((call["method"], key), set()).add(
                _json_schema_type(value)
            )
    for (method, key), types in observed_types.items():
        capability = by_method.get(method)
        if not capability:
            continue
        schema = capability.setdefault("input_schema", {"type": "object"})
        properties = schema.setdefault("properties", {})
        properties.setdefault(key, {})["type"] = _schema_type_value(types)
    return refined


def _schema_from_call_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    observed_types: Dict[str, Set[str]] = {}
    required_sets = []
    for record in records:
        params = record["call"].get("params", {})
        required_sets.append(set(params))
        for key, value in params.items():
            observed_types.setdefault(key, set()).add(_json_schema_type(value))
    properties = {
        key: {"type": _schema_type_value(types)}
        for key, types in observed_types.items()
    }
    required = sorted(set.intersection(*required_sets)) if required_sets else []
    return {"type": "object", "properties": properties, "required": required}


def _json_schema_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _schema_type_value(types: Set[str]) -> Any:
    ordered = sorted(types)
    return ordered[0] if len(ordered) == 1 else ordered


def _server_methods(server: Dict[str, Any]) -> Set[str]:
    return {
        method
        for capability in server.get("capabilities", [])
        for method in capability.get("methods", [])
    }


def _record_calls(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [_clone_call(record["call"]) for record in records]


def _params_are_in_payload(params: Dict[str, Any], payload: str) -> bool:
    lower_payload = payload.lower()
    return all(
        str(value).lower() in lower_payload
        for value in _scalar_param_values(params)
        if str(value)
    )


def _scalar_param_values(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for nested in value.values():
            yield from _scalar_param_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _scalar_param_values(nested)
    elif value is not None:
        yield value


def _well_formed_query(query: str) -> bool:
    stripped = query.strip()
    if not stripped or any(ord(char) < 32 and char not in "\t\n" for char in stripped):
        return False
    if stripped[0] in {'"', "'"} and not stripped.endswith(stripped[0]):
        return False
    return True


def _normalized_query(query: str) -> str:
    return " ".join(query.lower().split())


def _normalize_model_text(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\\n", "\n").strip()


def _describe_call(call: Dict[str, Any]) -> str:
    params = json.dumps(call.get("params", {}), ensure_ascii=False, sort_keys=True)
    return f"Invoke {call.get('server')}::{call.get('method')} with params {params}"


def _parse_response_calls(response: Any) -> List[Dict[str, Any]]:
    if not isinstance(response, str) or not response.strip():
        return []

    calls: List[Dict[str, Any]] = []
    for fragment in _extract_balanced_dicts(response):
        parsed = _parse_mapping_fragment(fragment)
        call = _coerce_tool_call(parsed)
        if call:
            calls.append(call)
    return calls


def _extract_balanced_dicts(text: str) -> List[str]:
    fragments: List[str] = []
    index = 0
    while index < len(text):
        if text[index] != "{":
            index += 1
            continue

        start = index
        depth = 0
        quote: Optional[str] = None
        escaped = False
        while index < len(text):
            char = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            else:
                if char in ("'", '"'):
                    quote = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        fragments.append(text[start : index + 1])
                        break
            index += 1
        index += 1
    return fragments


def _parse_mapping_fragment(fragment: str) -> Any:
    cleaned = fragment.strip().strip("`")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        for parser in (ast.literal_eval, json.loads):
            try:
                return parser(cleaned)
            except Exception:
                continue
    return None


def _coerce_tool_call(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    tool = (
        value.get("tool")
        or value.get("name")
        or value.get("function")
        or value.get("method")
    )
    args = (
        value.get("arguments")
        or value.get("args")
        or value.get("parameters")
        or value.get("params")
        or {}
    )
    if not isinstance(tool, str) or not tool.strip():
        return None
    if not isinstance(args, dict):
        args = {"value": args}
    return {"tool": tool.strip(), "arguments": args}


def _canonical_project_call(
    server_name: str,
    tool_names: List[str],
    raw_tool: str,
    raw_args: Dict[str, Any],
    query: str,
) -> Optional[Dict[str, Any]]:
    server, method = _map_project_server_method(server_name, tool_names, raw_tool, raw_args)
    params = _project_params(method, raw_args, query)
    return {"server": server, "method": method, "params": params}


def _map_project_server_method(
    server_name: str,
    tool_names: List[str],
    raw_tool: str,
    raw_args: Dict[str, Any],
) -> Tuple[str, str]:
    lower_name = str(server_name).lower()
    lower_tool = str(raw_tool).lower()
    lower_tools = " ".join(str(t).lower() for t in tool_names or [])
    arg_keys = " ".join(str(k).lower() for k in raw_args.keys())
    text = " ".join([lower_name, lower_tool, lower_tools, arg_keys])

    if any(term in text for term in (
        "email", "mail", "slack", "wechat", "message", "send_message",
        "claude post", "dodo",
    )):
        return "email-server", "email/send"
    if any(term in text for term in (
        "sql", "database", "postgres", "mysql", "sqlite", "clickhouse",
        "redis", "prisma", "financial", "adfin", "alphavantage", "op.gg",
        "schedule", "payment", "invoice",
    )) or ("query" in lower_tool and "search" not in lower_tool):
        return "db-server", "database/query"
    if any(term in text for term in (
        "browser", "web", "url", "fetch", "search", "http", "brave",
        "puppeteer",
    )) and not any(term in text for term in ("file", "directory", "path")):
        return "web-server", "web/search"
    if any(term in text for term in (
        "write", "move", "create", "delete", "remove", "update", "edit",
        "append", "replace", "put", "set",
    )):
        return "fs-server", "files/write"
    if any(term in text for term in (
        "read", "file", "directory", "path", "folder", "drive", "github",
        "gitlab", "memory", "sentry", "list", "get_info", "info",
    )):
        return "fs-server", "files/read"
    return "web-server", "web/search"


def _project_params(method: str, raw_args: Dict[str, Any], query: str) -> Dict[str, Any]:
    if method == "files/read":
        path = (
            _first_arg_value(raw_args, ("path", "paths", "file", "filename", "source"))
            or _extract_path_from_text(query)
            or query
        )
        return {"path": _stringify_param(path)}
    if method == "files/write":
        path = (
            _first_arg_value(raw_args, ("path", "destination", "target", "file", "source"))
            or _extract_path_from_text(query)
            or "/tmp/mcptox_derived_output"
        )
        content = (
            _first_arg_value(raw_args, ("content", "text", "value", "data", "body"))
            or _summarize_args(raw_args)
            or "mcptox-derived write payload"
        )
        return {"path": _stringify_param(path), "content": _stringify_param(content)}
    if method == "database/query":
        sql = (
            _first_arg_value(raw_args, ("query", "sql", "statement", "command"))
            or _summarize_args(raw_args)
            or query
        )
        return {"query": _stringify_param(sql)}
    if method == "email/send":
        to = _first_arg_value(raw_args, ("to", "recipient", "email", "address")) or "external@example.com"
        subject = _first_arg_value(raw_args, ("subject", "title")) or "MCPTox derived action"
        body = (
            _first_arg_value(raw_args, ("body", "content", "text", "message"))
            or _summarize_args(raw_args)
            or query
        )
        return {
            "to": _stringify_param(to),
            "subject": _stringify_param(subject),
            "body": _stringify_param(body),
        }
    web_query = _first_arg_value(raw_args, ("query", "q", "url", "term")) or query
    return {"query": _stringify_param(web_query)}


def _first_arg_value(raw_args: Dict[str, Any], names: Tuple[str, ...]) -> Any:
    lower_map = {str(k).lower(): v for k, v in raw_args.items()}
    for name in names:
        if name in lower_map:
            value = lower_map[name]
            if value not in (None, "", []):
                return value
    for key, value in lower_map.items():
        if any(name in key for name in names) and value not in (None, "", []):
            return value
    return None


def _extract_path_from_text(text: str) -> Optional[str]:
    for pattern in (r"'([^']+)'", r'"([^"]+)"', r"(/[^\s,.;]+)"):
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def _summarize_args(raw_args: Dict[str, Any]) -> str:
    if not raw_args:
        return ""
    return json.dumps(raw_args, ensure_ascii=False, sort_keys=True)


def _stringify_param(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(_stringify_param(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _to_unattested_call(success_call: Dict[str, Any]) -> Dict[str, Any]:
    canonical = success_call["canonical_call"]
    raw_call = success_call.get("raw_call", {})
    raw_tool = str(raw_call.get("tool") or canonical["method"].split("/")[-1])
    namespace = {
        "fs-server": "filesystem",
        "db-server": "database_admin",
        "web-server": "browser_admin",
        "email-server": "messaging_admin",
    }.get(canonical["server"], "unattested")
    method = f"{namespace}/{_safe_identifier(raw_tool)}"
    params = _compact_raw_params(raw_call.get("arguments", {})) or canonical.get("params", {})
    return {
        "server": canonical["server"],
        "method": method,
        "params": params,
    }


def _compact_raw_params(raw_args: Any) -> Dict[str, str]:
    if not isinstance(raw_args, dict):
        return {}
    compact: Dict[str, str] = {}
    for key, value in raw_args.items():
        safe_key = _safe_identifier(str(key)) or "value"
        compact[safe_key] = _stringify_param(value)
    return compact


def _schema_from_params(params: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {key: {"type": "string"} for key in params},
        "required": list(params),
    }


def _safe_identifier(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", value.strip().lower()).strip("_")
    return cleaned or "value"


def _clone_call(call: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "server": call.get("server"),
        "method": call.get("method"),
        "params": dict(call.get("params", {}) or {}),
    }


def _call_signature(call: Dict[str, Any]) -> str:
    return json.dumps(call, ensure_ascii=False, sort_keys=True)


def _calls_differ(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    return _call_signature(left) != _call_signature(right)


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


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: str, value: Dict[str, Any]) -> None:
    output_dir = os.path.dirname(path) or "."
    os.makedirs(output_dir, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".mcptox-", suffix=".json", dir=output_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, ensure_ascii=False)
            output.write("\n")
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Adapt raw MCPTox-Benchmark data for this project.")
    parser.add_argument("--input_dir", default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output", default=None)
    parser.add_argument(
        "--variant",
        choices=["legacy", "derived_table1"],
        default="legacy",
        help=(
            "legacy writes the flattened mcptox_official.json; derived_table1 "
            "writes the 200-scenario MCPTox-derived four-category Table 1 set."
        ),
    )
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--include_responses",
        action="store_true",
        help="Preserve raw model responses and system prompts in scenario metadata.",
    )
    args = parser.parse_args()

    if args.variant == "derived_table1":
        output_path = args.output or DEFAULT_DERIVED_OUTPUT_PATH
        result = adapt_mcptox_derived_table1(
            input_dir=args.input_dir,
            output_path=output_path,
            count=args.count,
            seed=args.seed,
            include_responses=args.include_responses,
        )
    else:
        output_path = args.output or DEFAULT_OUTPUT_PATH
        result = adapt_mcptox_benchmark(
            input_dir=args.input_dir,
            output_path=output_path,
            include_responses=args.include_responses,
        )
    print(f"Adapted MCPTox scenarios: {result['scenario_count']}")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()
