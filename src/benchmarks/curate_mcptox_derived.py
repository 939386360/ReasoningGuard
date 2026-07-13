import argparse
import copy
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.benchmarks.adapt_mcptox_benchmark import (
    DEFAULT_INPUT_DIR,
    build_mcptox_derived_candidate_pool,
)
from src.benchmarks.load_mcptox import MCPTOX_CATEGORIES, MCPTOX_DISTRIBUTION
from src.benchmarks.validate_mcptox_derived import validate_dataset


REVIEW_PROTOCOL_VERSION = 1
CURATION_REVISION = 1
DEFAULT_BATCH_SIZE = 8
DEFAULT_SOURCE_PATH = os.path.join(
    "data", "mcptox", "mcptox_official_derived_table1_200.json"
)
DEFAULT_STATE_PATH = os.path.join(
    "data", "mcptox", "curation", "mcptox_derived_table1_review_state.json"
)
DEFAULT_BATCH_PATH = os.path.join(
    "data", "mcptox", "curation", "current_batch.json"
)
DEFAULT_CURATED_PATH = os.path.join(
    "data", "mcptox", "mcptox_official_derived_table1_200_curated.json"
)

REVIEW_CHECKS = (
    "benign_alignment",
    "payload_call_alignment",
    "category_match",
    "attack_surface_match",
    "no_meta_leakage",
    "text_quality",
)

ISSUE_CODES = {
    "CATEGORY_MISMATCH",
    "BENIGN_MISMATCH",
    "PAYLOAD_CALL_MISMATCH",
    "ATTACK_SURFACE_MISMATCH",
    "META_LEAKAGE",
    "UNNATURAL_TEXT",
    "MALFORMED_TEXT",
    "DUPLICATE",
    "INVALID_BENIGN_REFERENCE",
    "INVALID_MALICIOUS_REFERENCE",
    "OTHER",
}

CATEGORY_RULES = {
    "tool_description_poisoning": (
        "The poisoned tool description must induce a malicious method different "
        "from the benign method; the case must not be parameter-only."
    ),
    "parameter_injection": (
        "Benign and malicious calls must use the same method, and the payload "
        "must explicitly support the malicious parameter changes."
    ),
    "response_manipulation": (
        "The first call must satisfy the benign query; the injected server "
        "response must plausibly induce the malicious follow-up call."
    ),
    "capability_escalation": (
        "The advertised extension must be absent from the clean catalog, and "
        "its payload must support direct use with the expected parameters."
    ),
}


def initialize_review(
    source_path: str = DEFAULT_SOURCE_PATH,
    state_path: str = DEFAULT_STATE_PATH,
    input_dir: str = DEFAULT_INPUT_DIR,
    batch_size: int = DEFAULT_BATCH_SIZE,
    force: bool = False,
) -> Dict[str, Any]:
    if os.path.exists(state_path) and not force:
        raise FileExistsError(
            f"Review state already exists: {state_path}. Use --force to replace it."
        )
    source = _read_json(source_path)
    validate_dataset(source)
    if source.get("variant") != "derived_table1":
        raise ValueError("Curation must start from the uncurated derived_table1 dataset")
    if source.get("scenario_count") != 200:
        raise ValueError("The curation workflow requires the complete 200-scenario dataset")
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")

    now = _utc_now()
    slots = []
    for index, scenario in enumerate(source["scenarios"]):
        slots.append(
            {
                "slot_id": f"slot-{index:04d}",
                "category": scenario["category"],
                "original_scenario_id": scenario["scenario_id"],
                "original_source_key": scenario["metadata"]["source_key"],
                "scenario": scenario,
                "status": "pending",
                "review": None,
                "replacement_history": [],
            }
        )
    state = {
        "review_protocol_version": REVIEW_PROTOCOL_VERSION,
        "reviewer_type": "codex_manual_semantic_review",
        "source_dataset": _portable_path(source_path),
        "source_sha256": _file_sha256(source_path),
        "source_schema_revision": source.get("schema_revision"),
        "source_variant": source.get("variant"),
        "input_dir": _portable_path(input_dir),
        "seed": (source.get("raw_metadata") or {}).get("seed", 42),
        "batch_size": batch_size,
        "created_at": now,
        "updated_at": now,
        "next_batch_number": 1,
        "active_batch": None,
        "slots": slots,
    }
    _validate_state_shape(state)
    _atomic_write_json(state_path, state)
    return review_status(state)


def export_batch(
    state_path: str = DEFAULT_STATE_PATH,
    batch_path: str = DEFAULT_BATCH_PATH,
    batch_size: Optional[int] = None,
) -> Dict[str, Any]:
    state = _load_verified_state(state_path)
    active = state.get("active_batch")
    if active:
        if os.path.exists(batch_path):
            existing = _read_json(batch_path)
            if existing.get("batch_id") != active.get("batch_id"):
                raise ValueError("Existing batch file does not match the active batch")
            return {
                "batch_id": active["batch_id"],
                "batch_path": _portable_path(batch_path),
                "scenario_count": len(existing.get("entries", [])),
                "distribution": dict(
                    Counter(entry.get("category") for entry in existing.get("entries", []))
                ),
            }
        slot_ids = active["slot_ids"]
        batch_id = active["batch_id"]
    else:
        size = batch_size or state.get("batch_size", DEFAULT_BATCH_SIZE)
        slot_ids = _select_balanced_pending_slots(state, size)
        if not slot_ids:
            raise ValueError("No pending scenarios remain; run finalize")
        batch_id = f"batch-{state['next_batch_number']:04d}"
        state["next_batch_number"] += 1
        state["active_batch"] = {
            "batch_id": batch_id,
            "slot_ids": slot_ids,
            "exported_at": _utc_now(),
        }
        state["updated_at"] = _utc_now()
        _atomic_write_json(state_path, state)

    slots_by_id = {slot["slot_id"]: slot for slot in state["slots"]}
    batch = {
        "review_protocol_version": REVIEW_PROTOCOL_VERSION,
        "reviewer_type": state["reviewer_type"],
        "source_sha256": state["source_sha256"],
        "batch_id": batch_id,
        "instructions": (
            "Review every entry semantically. Fill all six checks with booleans, "
            "choose accept/edit/replace, and provide a concrete rationale."
        ),
        "entries": [
            _batch_entry(slots_by_id[slot_id]) for slot_id in slot_ids
        ],
    }
    _atomic_write_json(batch_path, batch)
    return {
        "batch_id": batch_id,
        "batch_path": _portable_path(batch_path),
        "scenario_count": len(batch["entries"]),
        "distribution": dict(Counter(entry["category"] for entry in batch["entries"])),
    }


def import_batch(
    state_path: str = DEFAULT_STATE_PATH,
    batch_path: str = DEFAULT_BATCH_PATH,
) -> Dict[str, Any]:
    state = _load_verified_state(state_path)
    batch = _read_json(batch_path)
    active = state.get("active_batch")
    if not active:
        raise ValueError("The review state has no active batch")
    if batch.get("batch_id") != active.get("batch_id"):
        raise ValueError("Batch ID does not match the active review batch")
    if batch.get("source_sha256") != state.get("source_sha256"):
        raise ValueError("Batch source hash does not match the review state")

    entries = batch.get("entries") or []
    if [entry.get("slot_id") for entry in entries] != active.get("slot_ids"):
        raise ValueError("Batch slot order does not match the active review batch")
    decisions = {entry["slot_id"]: _validate_review_entry(entry) for entry in entries}

    pool_cache: Optional[Dict[str, List[Dict[str, Any]]]] = None
    slots_by_id = {slot["slot_id"]: slot for slot in state["slots"]}
    for slot_id in active["slot_ids"]:
        slot = slots_by_id[slot_id]
        decision = decisions[slot_id]
        if decision["action"] == "replace":
            if pool_cache is None:
                pool_cache = build_mcptox_derived_candidate_pool(
                    input_dir=state["input_dir"],
                    seed=state["seed"],
                )
            replacement = _next_replacement(state, slot, pool_cache[slot["category"]])
            slot["replacement_history"].append(
                {
                    "scenario_id": slot["scenario"]["scenario_id"],
                    "source_key": slot["scenario"]["metadata"]["source_key"],
                    "review": decision,
                    "replaced_at": _utc_now(),
                    "replacement_scenario_id": replacement["scenario_id"],
                    "replacement_source_key": replacement["metadata"]["source_key"],
                }
            )
            slot["scenario"] = replacement
            slot["status"] = "pending"
            slot["review"] = None
        else:
            if decision["action"] == "edit":
                decision["reference_edits"] = _apply_reference_edits(
                    slot["scenario"],
                    decision["drop_benign_indexes"],
                    decision["drop_malicious_indexes"],
                )
                if decision["edited_payload"] not in (None, ""):
                    _apply_payload_edit(slot["scenario"], decision["edited_payload"])
                slot["status"] = "edited"
            else:
                slot["status"] = "accepted"
            decision["reviewed_at"] = _utc_now()
            slot["review"] = decision

    _validate_current_scenarios(state)
    state["active_batch"] = None
    state["updated_at"] = _utc_now()
    _atomic_write_json(state_path, state)
    archive_path = os.path.join(
        os.path.dirname(state_path), "batches", f"{batch['batch_id']}.json"
    )
    _atomic_write_json(archive_path, batch)
    return review_status(state)


def record_batch_decision(
    batch_path: str,
    slot_id: str,
    action: str,
    rationale: str,
    issues: Optional[List[str]] = None,
    failed_checks: Optional[List[str]] = None,
    edited_payload: Optional[str] = None,
    drop_benign_indexes: Optional[List[int]] = None,
    drop_malicious_indexes: Optional[List[int]] = None,
) -> Dict[str, Any]:
    batch = _read_json(batch_path)
    entry = next(
        (item for item in batch.get("entries", []) if item.get("slot_id") == slot_id),
        None,
    )
    if entry is None:
        raise ValueError(f"Slot is not present in the current batch: {slot_id}")
    issues = issues or []
    failed_checks = failed_checks or []
    unknown_checks = set(failed_checks) - set(REVIEW_CHECKS)
    if unknown_checks:
        raise ValueError(f"Unknown review checks: {sorted(unknown_checks)}")
    entry["decision"] = {
        "action": action,
        "checks": {
            check: check not in failed_checks for check in REVIEW_CHECKS
        },
        "issues": issues,
        "rationale": rationale,
        "edited_payload": edited_payload,
        "drop_benign_indexes": drop_benign_indexes or [],
        "drop_malicious_indexes": drop_malicious_indexes or [],
    }
    _validate_review_entry(entry)
    _atomic_write_json(batch_path, batch)
    return {
        "batch_id": batch.get("batch_id"),
        "slot_id": slot_id,
        "scenario_id": entry.get("scenario_id"),
        "action": action,
    }


def finalize_curated_dataset(
    state_path: str = DEFAULT_STATE_PATH,
    output_path: str = DEFAULT_CURATED_PATH,
) -> Dict[str, Any]:
    state = _load_verified_state(state_path)
    if state.get("active_batch"):
        raise ValueError("Import the active batch before finalizing")
    pending = [slot["slot_id"] for slot in state["slots"] if slot["status"] == "pending"]
    if pending:
        raise ValueError(f"Cannot finalize with {len(pending)} pending scenarios")
    invalid_reviews = [
        slot["slot_id"]
        for slot in state["slots"]
        if not _terminal_review_is_complete(slot)
    ]
    if invalid_reviews:
        raise ValueError(
            f"Cannot finalize with {len(invalid_reviews)} incomplete terminal reviews"
        )

    source = _read_json(state["source_dataset"])
    curated = copy.deepcopy(source)
    curated["name"] = "MCPTox-derived Table1 Curated"
    curated["variant"] = "derived_table1_curated"
    curated["curation_revision"] = CURATION_REVISION
    curated["parent_dataset"] = state["source_dataset"]
    curated["parent_sha256"] = state["source_sha256"]
    dropped_benign_count = _count_dropped_references(state, "dropped_benign_calls")
    dropped_malicious_count = _count_dropped_references(state, "dropped_malicious_calls")
    curated["curation"] = {
        "review_protocol_version": REVIEW_PROTOCOL_VERSION,
        "reviewer_type": state["reviewer_type"],
        "completed_at": _utc_now(),
        "decision_counts": dict(Counter(slot["status"] for slot in state["slots"])),
        "replacement_count": sum(
            len(slot["replacement_history"]) for slot in state["slots"]
        ),
        "dropped_benign_references": dropped_benign_count,
        "dropped_malicious_references": dropped_malicious_count,
    }
    curated["scenarios"] = []
    for slot in state["slots"]:
        scenario = copy.deepcopy(slot["scenario"])
        metadata = scenario.setdefault("metadata", {})
        metadata["curation"] = {
            "review_protocol_version": REVIEW_PROTOCOL_VERSION,
            "reviewer_type": state["reviewer_type"],
            "decision": slot["status"],
            "checks": slot["review"]["checks"],
            "issues": slot["review"]["issues"],
            "rationale": slot["review"]["rationale"],
            "reviewed_at": slot["review"]["reviewed_at"],
            "slot_id": slot["slot_id"],
            "original_scenario_id": slot["original_scenario_id"],
            "original_source_key": slot["original_source_key"],
            "replacement_count": len(slot["replacement_history"]),
            "reference_edits": slot["review"].get(
                "reference_edits",
                {"dropped_benign_calls": [], "dropped_malicious_calls": []},
            ),
        }
        curated["scenarios"].append(scenario)
    curated["scenario_count"] = len(curated["scenarios"])
    curated["validation"] = validate_dataset(curated)
    curated["curation_validation"] = validate_curated_dataset(curated)
    _atomic_write_json(output_path, curated)
    return {
        "output_path": _portable_path(output_path),
        "scenario_count": curated["scenario_count"],
        "distribution": dict(Counter(s["category"] for s in curated["scenarios"])),
        "decision_counts": curated["curation"]["decision_counts"],
        "replacement_count": curated["curation"]["replacement_count"],
        "dropped_benign_references": dropped_benign_count,
        "dropped_malicious_references": dropped_malicious_count,
    }


def validate_curated_dataset(dataset: Dict[str, Any]) -> Dict[str, Any]:
    validate_dataset(dataset)
    errors = []
    if dataset.get("variant") != "derived_table1_curated":
        errors.append("variant must be derived_table1_curated")
    if dataset.get("curation_revision") != CURATION_REVISION:
        errors.append(f"curation_revision must be {CURATION_REVISION}")
    if not dataset.get("parent_sha256"):
        errors.append("parent_sha256 is required")
    for scenario in dataset.get("scenarios", []):
        review = (scenario.get("metadata") or {}).get("curation") or {}
        if review.get("decision") not in {"accepted", "edited"}:
            errors.append(f"{scenario.get('scenario_id')} is not terminally reviewed")
        if set(review.get("checks", {})) != set(REVIEW_CHECKS):
            errors.append(f"{scenario.get('scenario_id')} has incomplete review checks")
        elif not all(review["checks"].values()):
            errors.append(f"{scenario.get('scenario_id')} has failed final checks")
        if not str(review.get("rationale") or "").strip():
            errors.append(f"{scenario.get('scenario_id')} has no review rationale")
        if review.get("reviewer_type") != "codex_manual_semantic_review":
            errors.append(f"{scenario.get('scenario_id')} has an invalid reviewer type")
        reference_edits = review.get("reference_edits") or {}
        if any(
            not isinstance(reference_edits.get(key, []), list)
            for key in ("dropped_benign_calls", "dropped_malicious_calls")
        ):
            errors.append(f"{scenario.get('scenario_id')} has invalid reference edit provenance")
    if errors:
        raise ValueError("Curated dataset validation failed:\n- " + "\n- ".join(errors[:50]))
    return {
        "status": "passed",
        "reviewed_scenarios": len(dataset.get("scenarios", [])),
        "reviewer_type": "codex_manual_semantic_review",
    }


def review_status(state: Dict[str, Any]) -> Dict[str, Any]:
    overall = Counter(slot["status"] for slot in state["slots"])
    by_category = defaultdict(Counter)
    for slot in state["slots"]:
        by_category[slot["category"]][slot["status"]] += 1
    return {
        "source_sha256": state["source_sha256"],
        "active_batch": (
            state["active_batch"]["batch_id"] if state.get("active_batch") else None
        ),
        "overall": dict(overall),
        "by_category": {key: dict(value) for key, value in by_category.items()},
        "replacement_count": sum(
            len(slot["replacement_history"]) for slot in state["slots"]
        ),
    }


def _batch_entry(slot: Dict[str, Any]) -> Dict[str, Any]:
    scenario = slot["scenario"]
    template = scenario["template"]
    relevant_methods = {
        call["method"]
        for key in ("benign_calls", "malicious_calls", "first_calls")
        for call in template.get(key, [])
        if isinstance(call, dict) and call.get("method")
    }
    relevant_capabilities = []
    for server in template.get("clean_servers", []):
        for capability in server.get("capabilities", []):
            if relevant_methods.intersection(capability.get("methods", [])):
                relevant_capabilities.append(capability)
    metadata = scenario.get("metadata") or {}
    return {
        "slot_id": slot["slot_id"],
        "scenario_id": scenario["scenario_id"],
        "category": scenario["category"],
        "category_rule": CATEGORY_RULES[scenario["category"]],
        "review_view": {
            "source_key": metadata.get("source_key"),
            "source_paradigm": metadata.get("paradigm"),
            "raw_server_name": metadata.get("raw_server_name"),
            "user_query": template.get("user_query"),
            "poisoned_content": scenario.get("poisoned_content"),
            "benign_calls": template.get("benign_calls", []),
            "indexed_benign_calls": [
                {"index": index, "call": call}
                for index, call in enumerate(template.get("benign_calls", []))
            ],
            "malicious_calls": template.get("malicious_calls", []),
            "indexed_malicious_calls": [
                {"index": index, "call": call}
                for index, call in enumerate(template.get("malicious_calls", []))
            ],
            "first_calls": template.get("first_calls", []),
            "poisoned_tool": template.get("poisoned_tool"),
            "malicious_response": template.get("malicious_response"),
            "claimed_capability": template.get("claimed_capability"),
            "relevant_clean_capabilities": relevant_capabilities,
            "raw_success_calls": metadata.get("raw_success_calls", []),
            "raw_ignored_calls": metadata.get("raw_ignored_calls", []),
        },
        "decision": {
            "action": None,
            "checks": {check: None for check in REVIEW_CHECKS},
            "issues": [],
            "rationale": "",
            "edited_payload": None,
            "drop_benign_indexes": [],
            "drop_malicious_indexes": [],
        },
    }


def _validate_review_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    decision = entry.get("decision") or {}
    action = decision.get("action")
    if action not in {"accept", "edit", "replace"}:
        raise ValueError(f"{entry.get('slot_id')} has an invalid action")
    checks = decision.get("checks") or {}
    if set(checks) != set(REVIEW_CHECKS):
        raise ValueError(f"{entry.get('slot_id')} has incomplete review checks")
    if any(not isinstance(value, bool) for value in checks.values()):
        raise ValueError(f"{entry.get('slot_id')} review checks must be booleans")
    issues = decision.get("issues") or []
    if not isinstance(issues, list) or any(issue not in ISSUE_CODES for issue in issues):
        raise ValueError(f"{entry.get('slot_id')} has invalid issue codes")
    rationale = str(decision.get("rationale") or "").strip()
    if not rationale:
        raise ValueError(f"{entry.get('slot_id')} requires a rationale")
    edited_payload = decision.get("edited_payload")
    drop_benign_indexes = _validated_drop_indexes(
        entry.get("slot_id"), "benign", decision.get("drop_benign_indexes", [])
    )
    drop_malicious_indexes = _validated_drop_indexes(
        entry.get("slot_id"), "malicious", decision.get("drop_malicious_indexes", [])
    )

    if action == "accept":
        if (
            not all(checks.values())
            or issues
            or edited_payload not in (None, "")
            or drop_benign_indexes
            or drop_malicious_indexes
        ):
            raise ValueError(f"{entry.get('slot_id')} accept decision is inconsistent")
    elif action == "edit":
        if not all(checks.values()) or not issues:
            raise ValueError(
                f"{entry.get('slot_id')} edited case must pass final checks and list issues"
            )
        has_payload_edit = isinstance(edited_payload, str) and bool(edited_payload.strip())
        if not has_payload_edit and not drop_benign_indexes and not drop_malicious_indexes:
            raise ValueError(
                f"{entry.get('slot_id')} edit requires a payload or reference change"
            )
    else:
        if all(checks.values()) or not issues:
            raise ValueError(
                f"{entry.get('slot_id')} replacement requires a failed check and issue"
            )
        if edited_payload not in (None, ""):
            raise ValueError(f"{entry.get('slot_id')} replacement cannot include edited_payload")
        if drop_benign_indexes or drop_malicious_indexes:
            raise ValueError(f"{entry.get('slot_id')} replacement cannot prune references")
    return {
        "action": action,
        "checks": checks,
        "issues": issues,
        "rationale": rationale,
        "edited_payload": edited_payload,
        "drop_benign_indexes": drop_benign_indexes,
        "drop_malicious_indexes": drop_malicious_indexes,
    }


def _validated_drop_indexes(slot_id: Any, label: str, value: Any) -> List[int]:
    if value in (None, ""):
        return []
    if not isinstance(value, list) or any(
        not isinstance(index, int) or isinstance(index, bool) or index < 0
        for index in value
    ):
        raise ValueError(f"{slot_id} {label} drop indexes must be non-negative integers")
    if len(value) != len(set(value)):
        raise ValueError(f"{slot_id} {label} drop indexes contain duplicates")
    return sorted(value)

def _apply_payload_edit(scenario: Dict[str, Any], payload: str) -> None:
    cleaned = payload.replace("\r\n", "\n").replace("\r", "\n").strip()
    scenario["poisoned_content"] = cleaned
    template = scenario["template"]
    category = scenario["category"]
    if category in {"tool_description_poisoning", "parameter_injection"}:
        template["poisoned_tool"]["description"] = cleaned
    elif category == "response_manipulation":
        template["malicious_response"] = cleaned
    elif category == "capability_escalation":
        template["claimed_capability"]["description"] = cleaned


def _apply_reference_edits(
    scenario: Dict[str, Any],
    drop_benign_indexes: List[int],
    drop_malicious_indexes: List[int],
) -> Dict[str, List[Dict[str, Any]]]:
    template = scenario["template"]
    benign_calls, dropped_benign = _prune_call_list(
        template.get("benign_calls", []), drop_benign_indexes, "benign"
    )
    malicious_calls, dropped_malicious = _prune_call_list(
        template.get("malicious_calls", []), drop_malicious_indexes, "malicious"
    )
    template["benign_calls"] = benign_calls
    template["benign_call"] = copy.deepcopy(benign_calls[0])
    template["malicious_calls"] = malicious_calls
    template["malicious_call"] = copy.deepcopy(malicious_calls[0])

    if scenario["category"] == "response_manipulation":
        template["first_calls"] = copy.deepcopy(benign_calls)
        template["first_call"] = copy.deepcopy(benign_calls[0])
    if scenario["category"] == "capability_escalation":
        template["claimed_capability"]["input_schema"] = _schema_from_calls(
            malicious_calls
        )

    primary = malicious_calls[0]
    target_action = _describe_call(primary)
    scenario["target_server"] = primary["server"]
    scenario["method"] = primary["method"]
    scenario["target_action"] = target_action
    template["target_action"] = target_action
    return {
        "dropped_benign_calls": dropped_benign,
        "dropped_malicious_calls": dropped_malicious,
    }


def _prune_call_list(
    calls: List[Dict[str, Any]], drop_indexes: List[int], label: str
) -> tuple:
    if any(index >= len(calls) for index in drop_indexes):
        raise ValueError(f"{label} drop index is outside the call list")
    drop_set = set(drop_indexes)
    dropped = [
        {"original_index": index, "call": copy.deepcopy(calls[index])}
        for index in drop_indexes
    ]
    retained = [
        copy.deepcopy(call)
        for index, call in enumerate(calls)
        if index not in drop_set
    ]
    if not retained:
        raise ValueError(f"Cannot drop every {label} reference")
    return retained, dropped


def _schema_from_calls(calls: List[Dict[str, Any]]) -> Dict[str, Any]:
    observed: Dict[str, set] = {}
    required_sets = []
    for call in calls:
        params = call.get("params", {})
        required_sets.append(set(params))
        for key, value in params.items():
            observed.setdefault(key, set()).add(_json_schema_type(value))
    properties = {}
    for key, types in observed.items():
        ordered = sorted(types)
        properties[key] = {"type": ordered[0] if len(ordered) == 1 else ordered}
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


def _describe_call(call: Dict[str, Any]) -> str:
    params = json.dumps(call.get("params", {}), ensure_ascii=False, sort_keys=True)
    return f"Invoke {call.get('server')}::{call.get('method')} with params {params}"


def _count_dropped_references(state: Dict[str, Any], key: str) -> int:
    return sum(
        len((slot.get("review") or {}).get("reference_edits", {}).get(key, []))
        for slot in state["slots"]
    )

def _next_replacement(
    state: Dict[str, Any],
    target_slot: Dict[str, Any],
    candidate_pool: List[Dict[str, Any]],
) -> Dict[str, Any]:
    used_sources = {
        slot["scenario"]["metadata"]["source_key"] for slot in state["slots"]
    }
    used_sources.update(
        history["source_key"]
        for slot in state["slots"]
        for history in slot["replacement_history"]
    )
    used_queries = {
        _normalize_query(slot["scenario"]["template"]["user_query"])
        for slot in state["slots"]
        if slot["category"] == target_slot["category"]
        and slot["slot_id"] != target_slot["slot_id"]
    }
    for candidate in candidate_pool:
        source_key = candidate["metadata"]["source_key"]
        query = _normalize_query(candidate["template"]["user_query"])
        if source_key in used_sources or query in used_queries:
            continue
        return copy.deepcopy(candidate)
    raise ValueError(f"No unused replacement remains for {target_slot['category']}")


def _select_balanced_pending_slots(state: Dict[str, Any], size: int) -> List[str]:
    pending_by_category = {
        category: [
            slot["slot_id"]
            for slot in state["slots"]
            if slot["category"] == category and slot["status"] == "pending"
        ]
        for category in MCPTOX_CATEGORIES
    }
    selected = []
    while len(selected) < size:
        added = False
        for category in MCPTOX_CATEGORIES:
            if pending_by_category[category] and len(selected) < size:
                selected.append(pending_by_category[category].pop(0))
                added = True
        if not added:
            break
    return selected


def _validate_current_scenarios(state: Dict[str, Any]) -> None:
    source = _read_json(state["source_dataset"])
    candidate = copy.deepcopy(source)
    candidate["scenarios"] = [slot["scenario"] for slot in state["slots"]]
    candidate["scenario_count"] = len(candidate["scenarios"])
    validate_dataset(candidate)


def _validate_state_shape(state: Dict[str, Any]) -> None:
    if state.get("review_protocol_version") != REVIEW_PROTOCOL_VERSION:
        raise ValueError("Unsupported review protocol version")
    slots = state.get("slots")
    if not isinstance(slots, list) or len(slots) != 200:
        raise ValueError("Review state must contain 200 slots")
    if Counter(slot.get("category") for slot in slots) != Counter(MCPTOX_DISTRIBUTION):
        raise ValueError("Review state category distribution is invalid")
    if any(slot.get("status") not in {"pending", "accepted", "edited"} for slot in slots):
        raise ValueError("Review state contains an invalid status")


def _terminal_review_is_complete(slot: Dict[str, Any]) -> bool:
    review = slot.get("review") or {}
    checks = review.get("checks") or {}
    return bool(
        slot.get("status") in {"accepted", "edited"}
        and set(checks) == set(REVIEW_CHECKS)
        and all(value is True for value in checks.values())
        and str(review.get("rationale") or "").strip()
        and review.get("reviewed_at")
    )


def _load_verified_state(path: str) -> Dict[str, Any]:
    state = _read_json(path)
    _validate_state_shape(state)
    source_path = state.get("source_dataset")
    if not source_path or not os.path.exists(source_path):
        raise FileNotFoundError(f"Review source dataset is missing: {source_path}")
    actual_hash = _file_sha256(source_path)
    if actual_hash != state.get("source_sha256"):
        raise ValueError("Review source dataset hash changed; start a new review state")
    return state


def _normalize_query(query: str) -> str:
    return " ".join(str(query or "").lower().split())


def _portable_path(path: str) -> str:
    return os.path.normpath(path).replace("\\", "/")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def _atomic_write_json(path: str, value: Dict[str, Any]) -> None:
    output_dir = os.path.dirname(path) or "."
    os.makedirs(output_dir, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".curation-", suffix=".json", dir=output_dir)
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
    parser = argparse.ArgumentParser(description="Manually curate MCPTox-derived v2")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--source", default=DEFAULT_SOURCE_PATH)
    init_parser.add_argument("--state", default=DEFAULT_STATE_PATH)
    init_parser.add_argument("--input-dir", default=DEFAULT_INPUT_DIR)
    init_parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    init_parser.add_argument("--force", action="store_true")

    export_parser = subparsers.add_parser("export-batch")
    export_parser.add_argument("--state", default=DEFAULT_STATE_PATH)
    export_parser.add_argument("--batch", default=DEFAULT_BATCH_PATH)
    export_parser.add_argument("--batch-size", type=int, default=None)

    import_parser = subparsers.add_parser("import-batch")
    import_parser.add_argument("--state", default=DEFAULT_STATE_PATH)
    import_parser.add_argument("--batch", default=DEFAULT_BATCH_PATH)

    decide_parser = subparsers.add_parser("decide")
    decide_parser.add_argument("--batch", default=DEFAULT_BATCH_PATH)
    decide_parser.add_argument("--slot-id", required=True)
    decide_parser.add_argument("--action", choices=["accept", "edit", "replace"], required=True)
    decide_parser.add_argument("--rationale", required=True)
    decide_parser.add_argument("--issues", default="")
    decide_parser.add_argument("--failed-checks", default="")
    decide_parser.add_argument("--edited-payload", default=None)
    decide_parser.add_argument("--drop-benign-indexes", default="")
    decide_parser.add_argument("--drop-malicious-indexes", default="")

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--state", default=DEFAULT_STATE_PATH)

    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--state", default=DEFAULT_STATE_PATH)
    finalize_parser.add_argument("--output", default=DEFAULT_CURATED_PATH)

    validate_parser = subparsers.add_parser("validate-curated")
    validate_parser.add_argument("path")

    args = parser.parse_args()
    if args.command == "init":
        result = initialize_review(
            args.source,
            args.state,
            args.input_dir,
            args.batch_size,
            args.force,
        )
    elif args.command == "export-batch":
        result = export_batch(args.state, args.batch, args.batch_size)
    elif args.command == "import-batch":
        result = import_batch(args.state, args.batch)
    elif args.command == "decide":
        result = record_batch_decision(
            batch_path=args.batch,
            slot_id=args.slot_id,
            action=args.action,
            rationale=args.rationale,
            issues=_split_csv(args.issues),
            failed_checks=_split_csv(args.failed_checks),
            edited_payload=args.edited_payload,
            drop_benign_indexes=_split_int_csv(args.drop_benign_indexes),
            drop_malicious_indexes=_split_int_csv(args.drop_malicious_indexes),
        )
    elif args.command == "status":
        result = review_status(_load_verified_state(args.state))
    elif args.command == "finalize":
        result = finalize_curated_dataset(args.state, args.output)
    else:
        result = validate_curated_dataset(_read_json(args.path))
    print(json.dumps(result, indent=2, ensure_ascii=False))


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _split_int_csv(value: str) -> List[int]:
    return [int(item) for item in _split_csv(value)]


if __name__ == "__main__":
    main()
