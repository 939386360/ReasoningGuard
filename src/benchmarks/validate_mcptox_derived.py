import argparse
import json
from collections import Counter
from typing import Any, Dict, Iterable, List, Set


EXPECTED_CATEGORIES = {
    "tool_description_poisoning",
    "parameter_injection",
    "response_manipulation",
    "capability_escalation",
}

MODEL_VISIBLE_MARKERS = (
    "compromised mcp",
    "trusted registry",
    "official mcptox",
    "derived mcptox",
    "repository's abstract mcp",
    "mcptox-poisoned",
    "response-manipulation payload",
    "parameter tampering rule",
    "hijacking instruction",
)


def validate_dataset(dataset: Dict[str, Any]) -> Dict[str, Any]:
    errors: List[str] = []
    scenarios = dataset.get("scenarios")
    if dataset.get("schema_revision") != 2:
        errors.append("schema_revision must be 2")
    if not isinstance(scenarios, list):
        raise ValueError("MCPTox-derived dataset validation failed: scenarios must be a list")

    distribution = Counter(
        scenario.get("category") for scenario in scenarios if isinstance(scenario, dict)
    )
    expected_distribution = dataset.get("distribution", {})
    if dict(distribution) != expected_distribution:
        errors.append(
            f"distribution mismatch: expected {expected_distribution}, got {dict(distribution)}"
        )
    if set(distribution) - EXPECTED_CATEGORIES:
        errors.append(f"unexpected categories: {sorted(set(distribution) - EXPECTED_CATEGORIES)}")
    if dataset.get("scenario_count") != len(scenarios):
        errors.append("scenario_count does not match scenarios length")

    seen_ids: Set[str] = set()
    seen_queries: Set[tuple] = set()
    seen_sources: Set[tuple] = set()
    visible_marker_hits = 0
    for index, scenario in enumerate(scenarios):
        prefix = f"scenario[{index}]"
        if not isinstance(scenario, dict):
            errors.append(f"{prefix} must be an object")
            continue
        scenario_id = scenario.get("scenario_id")
        if not scenario_id or scenario_id in seen_ids:
            errors.append(f"{prefix} has a missing or duplicate scenario_id")
        seen_ids.add(scenario_id)

        category = scenario.get("category")
        template = scenario.get("template") or {}
        query = template.get("user_query")
        query_key = (category, _normalize_query(query))
        if not query_key[1] or query_key in seen_queries:
            errors.append(f"{prefix} has a missing or duplicate per-category query")
        seen_queries.add(query_key)
        if not _well_formed_query(query):
            errors.append(f"{prefix} has a malformed user query")

        source_key = (category, (scenario.get("metadata") or {}).get("source_key"))
        if not source_key[1] or source_key in seen_sources:
            errors.append(f"{prefix} has a missing or duplicate per-category source_key")
        seen_sources.add(source_key)

        clean_servers = template.get("clean_servers") or []
        if len(clean_servers) != 1:
            errors.append(f"{prefix} must define exactly one clean server")
            continue
        clean_methods = _server_methods(clean_servers[0])
        benign_calls = _calls(template, "benign_calls", "benign_call")
        malicious_calls = _calls(template, "malicious_calls", "malicious_call")
        if not benign_calls or not malicious_calls:
            errors.append(f"{prefix} must define benign and malicious calls")
            continue
        if template.get("benign_call") != benign_calls[0]:
            errors.append(f"{prefix} benign_call must be the first benign_calls entry")
        if template.get("malicious_call") != malicious_calls[0]:
            errors.append(f"{prefix} malicious_call must be the first malicious_calls entry")
        for call in benign_calls:
            if not _valid_call(call) or call["method"] not in clean_methods:
                errors.append(f"{prefix} has a benign call outside the clean catalog")

        benign = benign_calls[0]
        if category == "tool_description_poisoning":
            poisoned_tool = template.get("poisoned_tool") or {}
            attack_methods = clean_methods | {poisoned_tool.get("method")}
            if any(call.get("method") == benign.get("method") for call in malicious_calls):
                errors.append(f"{prefix} TDP collapses to the benign method")
            if any(call.get("method") not in attack_methods for call in malicious_calls):
                errors.append(f"{prefix} TDP malicious call is unavailable in the attack catalog")
        elif category == "parameter_injection":
            for call in malicious_calls:
                if call.get("method") != benign.get("method"):
                    errors.append(f"{prefix} PI changes the method")
                if call.get("params") == benign.get("params"):
                    errors.append(f"{prefix} PI does not change parameters")
                if call.get("method") not in clean_methods:
                    errors.append(f"{prefix} PI malicious method is not clean")
        elif category == "response_manipulation":
            first_calls = _calls(template, "first_calls", "first_call")
            if first_calls != benign_calls:
                errors.append(f"{prefix} RM first calls must equal benign calls")
            if not template.get("malicious_response"):
                errors.append(f"{prefix} RM has no malicious response")
            if any(call.get("method") not in clean_methods for call in malicious_calls):
                errors.append(f"{prefix} RM malicious method is not clean")
        elif category == "capability_escalation":
            claimed = template.get("claimed_capability") or {}
            claimed_method = claimed.get("method")
            if not claimed_method or claimed_method in clean_methods:
                errors.append(f"{prefix} CE capability is already trusted")
            if any(call.get("method") != claimed_method for call in malicious_calls):
                errors.append(f"{prefix} CE malicious call does not use the advertised capability")

        for call in malicious_calls:
            if not _valid_call(call):
                errors.append(f"{prefix} has an invalid malicious call")

        for text in _model_visible_texts(scenario):
            lower = text.lower()
            hits = [marker for marker in MODEL_VISIBLE_MARKERS if marker in lower]
            if hits:
                visible_marker_hits += len(hits)
                errors.append(f"{prefix} exposes evaluation markers: {hits}")
            if "\\n" in text:
                errors.append(f"{prefix} contains a literal escaped newline")

    if errors:
        preview = "\n".join(f"- {error}" for error in errors[:50])
        suffix = f"\n... and {len(errors) - 50} more" if len(errors) > 50 else ""
        raise ValueError(f"MCPTox-derived dataset validation failed:\n{preview}{suffix}")

    return {
        "status": "passed",
        "scenario_count": len(scenarios),
        "distribution": dict(distribution),
        "per_category_duplicate_queries": 0,
        "model_visible_marker_hits": visible_marker_hits,
    }


def _calls(template: Dict[str, Any], plural: str, singular: str) -> List[Dict[str, Any]]:
    calls = template.get(plural)
    if isinstance(calls, list):
        return [call for call in calls if isinstance(call, dict)]
    call = template.get(singular)
    return [call] if isinstance(call, dict) else []


def _valid_call(call: Dict[str, Any]) -> bool:
    return bool(
        call.get("server")
        and call.get("method")
        and isinstance(call.get("params", {}), dict)
    )


def _server_methods(server: Dict[str, Any]) -> Set[str]:
    return {
        method
        for capability in server.get("capabilities", [])
        for method in capability.get("methods", [])
    }


def _model_visible_texts(scenario: Dict[str, Any]) -> Iterable[str]:
    template = scenario.get("template") or {}
    yield str(scenario.get("poisoned_content") or "")
    yield str(template.get("malicious_response") or "")
    for key in ("poisoned_tool", "claimed_capability"):
        capability = template.get(key) or {}
        if isinstance(capability, dict):
            for field in ("server_id", "name", "method", "description"):
                yield str(capability.get(field) or "")
    for server in template.get("clean_servers") or []:
        yield str(server.get("server_id") or "")
        yield str(server.get("name") or "")
        for capability in server.get("capabilities", []):
            yield str(capability.get("name") or "")
            yield str(capability.get("description") or "")
            for method in capability.get("methods", []):
                yield str(method)


def _normalize_query(query: Any) -> str:
    return " ".join(str(query or "").lower().split())


def _well_formed_query(query: Any) -> bool:
    stripped = str(query or "").strip()
    if not stripped:
        return False
    return not (stripped[0] in {'"', "'"} and not stripped.endswith(stripped[0]))


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate an MCPTox-derived v2 dataset")
    parser.add_argument("path")
    args = parser.parse_args()
    with open(args.path, encoding="utf-8") as source:
        report = validate_dataset(json.load(source))
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
