import json
import logging
import os
import uuid
from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Optional


_LOGGER_NAME = "reasoningguard.audit"
_context: ContextVar[Dict[str, Any]] = ContextVar("runtime_audit_context", default={})
_strict_runtime = False
_audit_path: Optional[str] = None
_run_id = ""
_counts: Counter = Counter()


def default_audit_log_path(output_path: Optional[str]) -> Optional[str]:
    if not output_path:
        return None
    root, ext = os.path.splitext(output_path)
    if not root:
        return None
    return f"{root}_audit.jsonl"


def configure_audit(
    path: Optional[str],
    strict_runtime: bool = False,
    run_id: Optional[str] = None,
) -> Optional[str]:
    global _strict_runtime, _audit_path, _run_id, _counts
    _strict_runtime = strict_runtime
    _audit_path = path or None
    _run_id = run_id or str(uuid.uuid4())
    _counts = Counter()

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    if _audit_path:
        parent = os.path.dirname(_audit_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        handler = logging.FileHandler(_audit_path, mode="w", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    return _audit_path


def is_strict_runtime() -> bool:
    return _strict_runtime


def get_audit_path() -> Optional[str]:
    return _audit_path


def get_audit_summary() -> Dict[str, int]:
    return dict(_counts)


@contextmanager
def audit_context(**fields: Any) -> Iterator[None]:
    current = dict(_context.get())
    current.update({k: v for k, v in fields.items() if v is not None})
    token = _context.set(current)
    try:
        yield
    finally:
        _context.reset(token)


def audit_event(
    component: str,
    event: str,
    severity: str = "INFO",
    message: Optional[str] = None,
    **fields: Any,
) -> None:
    severity = severity.upper()
    _counts[f"events.{event}"] += 1
    _counts[f"severity.{severity}"] += 1
    if fields.get("fallback_used") is True:
        _counts["fallback_used"] += 1
    if fields.get("mock_used") is True:
        _counts["mock_used"] += 1

    payload: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "run_id": _run_id,
        "level": severity,
        "component": component,
        "event": event,
    }
    if message:
        payload["message"] = message
    payload.update(_context.get())
    payload.update({k: _json_safe(v) for k, v in fields.items() if v is not None})

    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        logger.info(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def excerpt(text: Any, limit: int = 500) -> str:
    value = "" if text is None else str(text)
    if len(value) <= limit:
        return value
    return value[:limit] + "...<truncated>"


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)
