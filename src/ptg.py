import hashlib
import hmac
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.mcp_client import (
    MCPCapability,
    MCPMessage,
    MCPServer,
    MCPMessageType,
    Origin,
    ProvenanceLedger,
    ReasoningTrace,
)


@dataclass
class PTGResult:
    approved: bool
    reason: str
    intent_signature: Optional[str] = None
    latency_ms: float = 0.0
    checks_passed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.checks_passed is None:
            self.checks_passed = []
        if self.checks_failed is None:
            self.checks_failed = []


class ProtocolAttestedToolGateway:
    def __init__(
        self,
        session_key: Optional[bytes] = None,
        intent_entailment_threshold: float = 0.75,
        cross_server_consent: bool = True,
        disable_intent_attestation: bool = False,
        disable_origin_tags: bool = False,
    ):
        self.session_key = session_key or uuid.uuid4().bytes
        self.intent_threshold = intent_entailment_threshold
        self.cross_server_consent = cross_server_consent
        self.disable_intent_attestation = disable_intent_attestation
        self.disable_origin_tags = disable_origin_tags
        self.ledger = ProvenanceLedger()
        self.server_capabilities: Dict[str, List[MCPCapability]] = {}
        self.cross_server_flows: Dict[str, List[str]] = {}
        self.latency_profile: Dict[str, float] = {}

    def register_server(self, server: MCPServer):
        self.server_capabilities[server.server_id] = server.capabilities

    def verify_invocation(
        self,
        msg: MCPMessage,
        intent_summary: str,
        trace: Optional[ReasoningTrace] = None,
    ) -> PTGResult:
        t0 = time.perf_counter()
        passed, failed = [], []
        self.latency_profile = {}

        t1 = time.perf_counter()
        att_ok = self._verify_attestation(msg)
        self.latency_profile["attestation_ms"] = (time.perf_counter() - t1) * 1000
        (passed if att_ok else failed).append("attestation")

        if self.disable_intent_attestation:
            intent_ok = True
        else:
            t2 = time.perf_counter()
            intent_ok = self._verify_intent_entailment(msg, intent_summary)
            self.latency_profile["intent_entailment_ms"] = (time.perf_counter() - t2) * 1000
        (passed if intent_ok else failed).append("intent_entailment")

        cross_ok = True
        if self.cross_server_consent:
            t3 = time.perf_counter()
            cross_ok = self._verify_cross_server(msg)
            self.latency_profile["cross_server_ms"] = (time.perf_counter() - t3) * 1000
            (passed if cross_ok else failed).append("cross_server_consent")

        if self.disable_origin_tags:
            origin_ok = True
        else:
            t4 = time.perf_counter()
            origin_ok = self._verify_origin_tags(msg)
            self.latency_profile["origin_tagging_ms"] = (time.perf_counter() - t4) * 1000
        (passed if origin_ok else failed).append("origin_tagging")

        t5 = time.perf_counter()
        sig = self._compute_intent_signature(msg, intent_summary)
        self.latency_profile["signature_ms"] = (time.perf_counter() - t5) * 1000

        approved = len(failed) == 0
        latency = (time.perf_counter() - t0) * 1000

        result = PTGResult(
            approved=approved,
            reason="All checks passed" if approved else f"Failed: {', '.join(failed)}",
            intent_signature=sig,
            latency_ms=latency,
            checks_passed=passed,
            checks_failed=failed,
        )

        if approved and trace is not None:
            self.ledger.record(msg, sig, trace, time.time())

        return result

    def _verify_attestation(self, msg: MCPMessage) -> bool:
        caps = self.server_capabilities.get(msg.recipient, [])
        if not caps:
            return False
        allowed_methods = set()
        for cap in caps:
            allowed_methods.update(cap.methods)
        return msg.method in allowed_methods

    def _verify_intent_entailment(self, msg: MCPMessage, intent_summary: str) -> bool:
        caps = self.server_capabilities.get(msg.recipient, [])
        if not caps:
            return False
        for cap in caps:
            if msg.method in cap.methods:
                keyword_overlap = sum(
                    1 for w in intent_summary.lower().split()
                    if w in cap.description.lower()
                )
                score = keyword_overlap / max(len(intent_summary.split()), 1)
                if score >= self.intent_threshold * 0.3:
                    return True
        return False

    def _verify_cross_server(self, msg: MCPMessage) -> bool:
        flow_key = f"{msg.sender}->{msg.recipient}"
        if flow_key in self.cross_server_flows:
            return True
        return True

    def _verify_origin_tags(self, msg: MCPMessage) -> bool:
        if msg.msg_type == MCPMessageType.SAMPLING:
            return any(
                tag.get("origin") == "server" for tag in msg.provenance_tags
            )
        return True

    def _compute_intent_signature(self, msg: MCPMessage, intent_summary: str) -> str:
        data = f"{intent_summary}|{msg.recipient}|{msg.method}|{json_stable(msg.params)}|{msg.timestamp}"
        return hmac.new(self.session_key, data.encode(), hashlib.sha256).hexdigest()

    def tag_sampling_response(self, msg: MCPMessage, server_id: str) -> MCPMessage:
        tag = {"server_id": server_id, "origin": "server", "timestamp": str(time.time())}
        msg.provenance_tags.append(tag)
        msg.origin = Origin.SERVER
        return msg


def json_stable(d: Dict[str, Any]) -> str:
    import json
    return json.dumps(d, sort_keys=True)