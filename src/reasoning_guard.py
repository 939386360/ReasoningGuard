from typing import Any, Dict, List, Optional, Tuple
from src.mcp_client import MCPMessage, Origin, ReasoningTrace
from src.ptg import ProtocolAttestedToolGateway, PTGResult
from src.rtv import ReasoningTraceVerifier, RTVResult, AnomalyClass


class Verdict:
    APPROVE = "APPROVE"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class ReasoningGuard:
    def __init__(
        self,
        ptg: Optional[ProtocolAttestedToolGateway] = None,
        rtv: Optional[ReasoningTraceVerifier] = None,
    ):
        self.ptg = ptg or ProtocolAttestedToolGateway()
        self.rtv = rtv or ReasoningTraceVerifier()

    def evaluate(
        self,
        msg: MCPMessage,
        intent_summary: str,
        trace: ReasoningTrace,
        memory_read_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        ptg_result = self.ptg.verify_invocation(msg, intent_summary, trace)

        if not ptg_result.approved:
            return {
                "verdict": Verdict.BLOCK,
                "ptg": ptg_result,
                "rtv": None,
                "total_latency_ms": ptg_result.latency_ms,
                "reason": f"PTG blocked: {ptg_result.reason}",
            }

        origin_tags = msg.provenance_tags if msg.msg_type.value == "sampling" else None
        rtv_result = self.rtv.verify(trace, intent_summary, origin_tags, memory_read_ids)

        total_latency = ptg_result.latency_ms + rtv_result.latency_ms

        if not rtv_result.approved:
            return {
                "verdict": Verdict.ESCALATE,
                "ptg": ptg_result,
                "rtv": rtv_result,
                "total_latency_ms": total_latency,
                "reason": f"RTV escalated: {rtv_result.escalation_reason}",
            }

        return {
            "verdict": Verdict.APPROVE,
            "ptg": ptg_result,
            "rtv": rtv_result,
            "total_latency_ms": total_latency,
            "reason": "Approved by both PTG and RTV",
        }


class AttestMCPBaseline:
    """AttestMCP (Maloyan & Larionov 2026): protocol-only baseline.

    Performs basic capability attestation only. LACKS the three novel
    PTG mechanisms: semantic intent attestation, origin-tagged sampling,
    and intent-aware cross-server isolation.
    """

    def __init__(self):
        self.ptg = ProtocolAttestedToolGateway(
            disable_intent_attestation=True,
            disable_origin_tags=True,
            cross_server_consent=False,
        )

    def evaluate(self, msg: MCPMessage, intent_summary: str) -> Dict[str, Any]:
        result = self.ptg.verify_invocation(msg, intent_summary)
        return {
            "verdict": Verdict.APPROVE if result.approved else Verdict.BLOCK,
            "latency_ms": result.latency_ms,
            "reason": result.reason,
        }


class GuardrailBaseline:
    def __init__(
        self,
        action_filter_threshold: float = 0.15,
        use_llamaguard: bool = True,
        mock_mode: bool = True,
        llamaguard_model: str = "meta-llama/LlamaGuard-3-8B",
        llamaguard_device: str = "auto",
        llamaguard_fail_fast: bool = False,
    ):
        self.threshold = action_filter_threshold
        self.use_llamaguard = use_llamaguard
        self.mock_mode = mock_mode
        if use_llamaguard:
            from src.guardrails.llamaguard import LlamaGuardBaseline
            self._llamaguard = LlamaGuardBaseline(
                mock_mode=mock_mode,
                model=llamaguard_model,
                device=llamaguard_device,
                fail_fast=llamaguard_fail_fast,
            )
        else:
            self._llamaguard = None

    def evaluate(self, msg: MCPMessage) -> Dict[str, Any]:
        if self.use_llamaguard and self._llamaguard is not None:
            return self._llamaguard.evaluate(msg)

        import time
        t0 = time.perf_counter()
        params_str = str(msg.params).lower()
        dangerous_patterns = [
            "delete", "remove", "exec", "system(", "sudo",
            "password", "credential", "token", "secret",
            "exfiltrate", "forward", "upload to external",
        ]
        score = sum(1 for p in dangerous_patterns if p in params_str) / max(len(dangerous_patterns), 1)
        approved = score < self.threshold
        latency = (time.perf_counter() - t0) * 1000
        return {
            "verdict": Verdict.APPROVE if approved else Verdict.BLOCK,
            "latency_ms": latency,
            "reason": "Action-level filter passed" if approved else f"Dangerous pattern detected (score={score:.2f})",
        }


class PTGOnlyBaseline:
    """PTG-Only: our full Protocol-Attested Tool Gateway without RTV.

    Includes all three novel mechanisms: semantic intent attestation,
    origin-tagged sampling, and intent-aware cross-server isolation.
    """

    def __init__(self):
        self.ptg = ProtocolAttestedToolGateway()

    def evaluate(self, msg: MCPMessage, intent_summary: str) -> Dict[str, Any]:
        result = self.ptg.verify_invocation(msg, intent_summary)
        return {
            "verdict": Verdict.APPROVE if result.approved else Verdict.BLOCK,
            "latency_ms": result.latency_ms,
            "reason": result.reason,
        }


class RTVOnlyBaseline:
    def __init__(self):
        self.rtv = ReasoningTraceVerifier()

    def evaluate(
        self,
        trace: ReasoningTrace,
        intent_summary: str,
        origin_tags: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        result = self.rtv.verify(trace, intent_summary, origin_tags)
        return {
            "verdict": Verdict.APPROVE if result.approved else Verdict.ESCALATE,
            "latency_ms": result.latency_ms,
            "flagged": result.flagged_anomalies,
            "anomaly_scores": result.anomaly_scores,
            "rtv": result,
            "reason": result.escalation_reason or "No anomalies detected",
        }
