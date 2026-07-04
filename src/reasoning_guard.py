from typing import Any, Dict, List, Optional, Tuple
from src.mcp_client import MCPMessage, Origin, ReasoningTrace
from src.ptg import ProtocolAttestedToolGateway, PTGResult
from src.rtv import RTVContext, ReasoningTraceVerifier, RTVResult, AnomalyClass


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

    def preflight(self) -> None:
        self.ptg.preflight()
        self.rtv.preflight()

    def evaluate(
        self,
        msg: MCPMessage,
        intent_summary: str,
        trace: ReasoningTrace,
        memory_read_ids: Optional[List[str]] = None,
        invocation_context: Optional[Dict[str, Any]] = None,
        user_query: Optional[str] = None,
        rtv_context: Optional[RTVContext] = None,
    ) -> Dict[str, Any]:
        ptg_result = self.ptg.verify_invocation(
            msg, intent_summary, user_query=user_query, trace=trace
        )

        if ptg_result.runtime_status != "ok":
            return {
                "verdict": None,
                "ptg": ptg_result,
                "rtv": None,
                "total_latency_ms": ptg_result.latency_ms,
                "reason": "PTG runtime unavailable",
                "runtime_status": ptg_result.runtime_status,
                "runtime_component": ptg_result.runtime_component,
                "runtime_stage": ptg_result.runtime_stage,
                "runtime_error": ptg_result.runtime_error,
            }

        if not ptg_result.approved:
            return {
                "verdict": Verdict.BLOCK,
                "ptg": ptg_result,
                "rtv": None,
                "total_latency_ms": ptg_result.latency_ms,
                "reason": f"PTG blocked: {ptg_result.reason}",
            }

        origin_tags = msg.provenance_tags
        rtv_result = self.rtv.verify(
            trace,
            intent_summary,
            origin_tags,
            memory_read_ids,
            invocation_context=invocation_context,
            rtv_context=rtv_context,
        )

        total_latency = ptg_result.latency_ms + rtv_result.latency_ms

        if rtv_result.runtime_status != "ok":
            return {
                "verdict": None,
                "ptg": ptg_result,
                "rtv": rtv_result,
                "total_latency_ms": total_latency,
                "reason": "RTV runtime unavailable",
                "runtime_status": rtv_result.runtime_status,
                "runtime_component": rtv_result.runtime_component,
                "runtime_stage": rtv_result.runtime_stage,
                "runtime_error": rtv_result.runtime_error,
            }

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

    def evaluate(
        self, msg: MCPMessage, intent_summary: str, user_query: Optional[str] = None
    ) -> Dict[str, Any]:
        result = self.ptg.verify_invocation(msg, intent_summary)
        return {
            "verdict": Verdict.APPROVE if result.approved else Verdict.BLOCK,
            "latency_ms": result.latency_ms,
            "reason": result.reason,
            "ptg": result,
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

    def preflight(self) -> None:
        if self.use_llamaguard and self._llamaguard is not None:
            self._llamaguard.preflight()

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

    def __init__(self, ptg: Optional[ProtocolAttestedToolGateway] = None):
        self.ptg = ptg or ProtocolAttestedToolGateway()

    def preflight(self) -> None:
        self.ptg.preflight()

    def evaluate(
        self, msg: MCPMessage, intent_summary: str, user_query: Optional[str] = None
    ) -> Dict[str, Any]:
        result = self.ptg.verify_invocation(
            msg, intent_summary, user_query=user_query
        )
        if result.runtime_status != "ok":
            return {
                "verdict": None,
                "latency_ms": result.latency_ms,
                "reason": "PTG runtime unavailable",
                "ptg": result,
                "runtime_status": result.runtime_status,
                "runtime_component": result.runtime_component,
                "runtime_stage": result.runtime_stage,
                "runtime_error": result.runtime_error,
            }
        return {
            "verdict": Verdict.APPROVE if result.approved else Verdict.BLOCK,
            "latency_ms": result.latency_ms,
            "reason": result.reason,
            "ptg": result,
        }


class RTVOnlyBaseline:
    def __init__(self):
        self.rtv = ReasoningTraceVerifier()

    def preflight(self) -> None:
        self.rtv.preflight()

    def evaluate(
        self,
        trace: ReasoningTrace,
        intent_summary: str,
        origin_tags: Optional[List[Dict[str, str]]] = None,
        invocation_context: Optional[Dict[str, Any]] = None,
        user_query: Optional[str] = None,
        rtv_context: Optional[RTVContext] = None,
    ) -> Dict[str, Any]:
        result = self.rtv.verify(
            trace,
            intent_summary,
            origin_tags,
            invocation_context=invocation_context,
            rtv_context=rtv_context,
        )
        if result.runtime_status != "ok":
            return {
                "verdict": None,
                "latency_ms": result.latency_ms,
                "flagged": [],
                "anomaly_scores": {},
                "rtv": result,
                "reason": "RTV runtime unavailable",
                "runtime_status": result.runtime_status,
                "runtime_component": result.runtime_component,
                "runtime_stage": result.runtime_stage,
                "runtime_error": result.runtime_error,
            }
        return {
            "verdict": Verdict.APPROVE if result.approved else Verdict.ESCALATE,
            "latency_ms": result.latency_ms,
            "flagged": result.flagged_anomalies,
            "anomaly_scores": result.anomaly_scores,
            "rtv": result,
            "reason": result.escalation_reason or "No anomalies detected",
        }
