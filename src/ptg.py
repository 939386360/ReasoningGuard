import hashlib
import hmac
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from jsonschema import Draft202012Validator

from src.mcp_client import (
    MCPCapability,
    MCPMessage,
    MCPServer,
    MCPMessageType,
    Origin,
    ProvenanceLedger,
    ReasoningTrace,
)
from src.runtime_audit import audit_event


@dataclass
class PTGResult:
    approved: Optional[bool]
    reason: str
    intent_signature: Optional[str] = None
    latency_ms: float = 0.0
    checks_passed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)
    semantic_similarity: Optional[float] = None
    semantic_path: Optional[str] = None
    runtime_status: str = "ok"
    runtime_component: Optional[str] = None
    runtime_stage: Optional[str] = None
    runtime_error: Optional[Dict[str, str]] = None

    def __post_init__(self):
        if self.checks_passed is None:
            self.checks_passed = []
        if self.checks_failed is None:
            self.checks_failed = []


@dataclass
class CapabilitySemanticView:
    original_description: str
    description_missing: bool
    humanized_method: str
    schema_summary: str
    permission_summary: str
    actual_parameter_summary: str
    action_text: str


@dataclass
class EmbeddingEvaluationResult:
    status: str
    similarity: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None


class MultilingualEmbeddingBackend:
    def __init__(self, model_name: str, device: str = "auto", fail_fast: bool = False):
        self.model_name = model_name
        self.device = device
        self.fail_fast = fail_fast
        self._model = None
        self._cache: Dict[str, Any] = {}

    def load_or_raise(self):
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer

            kwargs = {} if self.device == "auto" else {"device": self.device}
            self._model = SentenceTransformer(self.model_name, **kwargs)
            return self._model
        except Exception as exc:
            audit_event(
                "embedding",
                "embedding.load_failed",
                severity="ERROR",
                message="Failed to load multilingual embedding model",
                model=self.model_name,
                device=self.device,
                fallback_used=False,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            raise RuntimeError(
                f"Failed to load multilingual embedding model {self.model_name}: {exc}"
            ) from exc

    # Backward-compatible alias for callers that used the previous private API.
    def _load(self):
        return self.load_or_raise()

    def similarity(self, query: str, action: str) -> EmbeddingEvaluationResult:
        model = self.load_or_raise()
        try:
            import numpy as np

            # paraphrase-multilingual-MiniLM-L12-v2 is a symmetric sentence
            # encoder; unlike E5 models, it expects raw sentences without
            # query/passage role prefixes.
            texts = [query, action]
            vectors = []
            missing = []
            for text in texts:
                if text in self._cache:
                    vectors.append(self._cache[text])
                else:
                    vectors.append(None)
                    missing.append(text)
            if missing:
                encoded = model.encode(missing, normalize_embeddings=True)
                for text, vector in zip(missing, encoded):
                    self._cache[text] = vector
                vectors = [self._cache[text] for text in texts]
            similarity = float(np.dot(vectors[0], vectors[1]))
            if not np.isfinite(similarity):
                raise ValueError("Embedding similarity must be finite")
            return EmbeddingEvaluationResult(status="ok", similarity=similarity)
        except Exception as exc:
            audit_event(
                "embedding",
                "embedding.inference_failed",
                severity="ERROR",
                message="Multilingual embedding inference failed",
                model=self.model_name,
                device=self.device,
                fallback_used=False,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            return EmbeddingEvaluationResult(
                status="call_failed",
                error_type=type(exc).__name__,
                error_message=str(exc),
            )


class ProtocolAttestedToolGateway:
    def __init__(
        self,
        session_key: Optional[bytes] = None,
        intent_entailment_threshold: float = 0.75,
        cross_server_consent: bool = True,
        disable_intent_attestation: bool = False,
        disable_origin_tags: bool = False,
        embedding_model: Optional[str] = None,
        embedding_device: str = "auto",
        embedding_threshold: float = 0.45,
        embedding_fail_fast: bool = False,
        overlap_threshold: float = 0.60,
        embedding_backend: Optional[Any] = None,
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
        self.embedding_threshold = embedding_threshold
        self.overlap_threshold = overlap_threshold
        self.embedding_backend = embedding_backend or (
            MultilingualEmbeddingBackend(
                embedding_model, embedding_device, embedding_fail_fast
            ) if embedding_model else None
        )
        self.last_semantic_similarity: Optional[float] = None
        self.last_semantic_path: Optional[str] = None
        self.last_contract_check: str = "semantic_alignment"
        self.last_runtime_status: str = "ok"
        self.last_runtime_error: Optional[Dict[str, str]] = None

    def preflight(self) -> None:
        if self.embedding_backend is not None:
            loader = getattr(self.embedding_backend, "load_or_raise", None)
            if callable(loader):
                loader()

    def register_server(self, server: MCPServer):
        self.server_capabilities[server.server_id] = server.capabilities

    def replace_registry(self, servers: List[MCPServer]) -> None:
        """Replace trusted capabilities for a scenario without retaining stale entries."""
        self.server_capabilities = {
            server.server_id: server.capabilities for server in servers
        }

    def verify_invocation(
        self,
        msg: MCPMessage,
        intent_summary: str,
        user_query: Optional[str] = None,
        trace: Optional[ReasoningTrace] = None,
    ) -> PTGResult:
        t0 = time.perf_counter()
        passed, failed = [], []
        self.latency_profile = {}
        self.last_semantic_similarity = None
        self.last_semantic_path = None
        self.last_contract_check = "semantic_alignment"
        self.last_runtime_status = "ok"
        self.last_runtime_error = None

        t1 = time.perf_counter()
        att_ok = self._verify_attestation(msg)
        self.latency_profile["attestation_ms"] = (time.perf_counter() - t1) * 1000
        (passed if att_ok else failed).append("attestation")

        if self.disable_intent_attestation:
            intent_ok = True
        else:
            t2 = time.perf_counter()
            intent_ok = self._verify_intent_entailment(
                msg, intent_summary, user_query=user_query
            )
            self.latency_profile["intent_entailment_ms"] = (time.perf_counter() - t2) * 1000
        (passed if intent_ok else failed).append(
            "intent_attestation" if intent_ok else self.last_contract_check
        )

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

        approved = None if self.last_runtime_status != "ok" else len(failed) == 0
        latency = (time.perf_counter() - t0) * 1000

        result = PTGResult(
            approved=approved,
            reason=(
                "All checks passed"
                if approved
                else (
                    "PTG runtime unavailable"
                    if approved is None
                    else f"Failed: {', '.join(failed)}"
                )
            ),
            intent_signature=sig,
            latency_ms=latency,
            checks_passed=passed,
            checks_failed=failed,
            semantic_similarity=self.last_semantic_similarity,
            semantic_path=self.last_semantic_path,
            runtime_status=self.last_runtime_status,
            runtime_component="embedding" if self.last_runtime_status != "ok" else None,
            runtime_stage="inference" if self.last_runtime_status != "ok" else None,
            runtime_error=self.last_runtime_error,
        )

        if approved is True and trace is not None:
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

    def _verify_intent_entailment(
        self,
        msg: MCPMessage,
        intent_summary: str,
        user_query: Optional[str] = None,
    ) -> bool:
        caps = self.server_capabilities.get(msg.recipient, [])
        if not caps:
            return False
        for cap in caps:
            if msg.method in cap.methods:
                if self._verify_capability_contract(msg, cap, user_query):
                    return True
                if self.last_runtime_status != "ok":
                    return False
        return False

    def _verify_capability_contract(
        self,
        msg: MCPMessage,
        cap: MCPCapability,
        user_query: Optional[str] = None,
    ) -> bool:
        """Validate invocation against structured capability contract.

        This replaces the former raw substring-overlap check. A valid call must
        satisfy method attestation, schema shape, and coarse permission guards.
        Textual intent overlap is kept only as an auxiliary signal when the
        structured contract is incomplete.
        """
        if msg.method not in cap.methods:
            self.last_contract_check = "method_attestation"
            return False
        if not self._params_match_schema(msg.params, getattr(cap, "input_schema", {}) or {}):
            self.last_contract_check = "schema_contract"
            return False
        if not self._permissions_allow_params(msg.params, cap.permissions):
            self.last_contract_check = "parameter_policy"
            return False
        if user_query and not self._semantic_alignment(user_query, msg, cap):
            if self.last_runtime_status == "ok":
                self.last_contract_check = "semantic_alignment"
            return False
        self.last_contract_check = "intent_attestation"
        return True

    @staticmethod
    def _params_match_schema(params: Dict[str, Any], schema: Dict[str, Any]) -> bool:
        if not schema:
            return True
        return Draft202012Validator(schema).is_valid(params)

    def _semantic_alignment(
        self, user_query: str, msg: MCPMessage, cap: MCPCapability
    ) -> bool:
        view = self.build_semantic_view(msg, cap)
        self.last_semantic_similarity = None
        self.last_semantic_path = None
        if self._overlap_fast_path(user_query, view, msg, cap):
            self.last_semantic_path = "english_overlap"
            return True
        if self.embedding_backend is None:
            self.last_semantic_path = "not_configured"
            return True
        evaluation = self.embedding_backend.similarity(user_query, view.action_text)
        # Compatibility for injected test/custom backends that still return a float.
        if evaluation is None:
            evaluation = EmbeddingEvaluationResult(
                status="call_failed",
                error_type="EmbeddingInferenceError",
                error_message="Embedding backend returned no similarity result",
            )
        elif isinstance(evaluation, (int, float)):
            evaluation = EmbeddingEvaluationResult(
                status="ok", similarity=float(evaluation)
            )
        if evaluation.status != "ok":
            self.last_runtime_status = evaluation.status
            self.last_runtime_error = {
                "error_type": evaluation.error_type or "EmbeddingInferenceError",
                "error_message": evaluation.error_message or "Embedding inference failed",
            }
            self.last_contract_check = "embedding_runtime"
            self.last_semantic_path = "multilingual_embedding"
            return False
        similarity = evaluation.similarity
        self.last_semantic_similarity = similarity
        self.last_semantic_path = "multilingual_embedding"
        return similarity is not None and similarity >= self.embedding_threshold

    @staticmethod
    def build_semantic_view(
        msg: MCPMessage, cap: MCPCapability
    ) -> CapabilitySemanticView:
        raw_description = "" if cap.description is None else str(cap.description).strip()
        missing = raw_description.casefold() in {"", "none", "null", "n/a"}
        description = "" if missing else raw_description
        method = re.sub(r"[/_.-]+", " ", msg.method).strip()
        schema = getattr(cap, "input_schema", {}) or {}
        properties = schema.get("properties", {}) or {}
        schema_parts = []
        for name, spec in properties.items():
            if isinstance(spec, dict):
                detail = " ".join(
                    str(item) for item in (spec.get("type", "any"), spec.get("description", ""))
                    if item
                )
            else:
                detail = "any"
            schema_parts.append(f"{name}: {detail}")
        schema_summary = "; ".join(schema_parts)
        permission_summary = ", ".join(cap.permissions or [])
        actual_parameter_summary = "; ".join(
            f"{key}={value}" for key, value in sorted(msg.params.items())
        )
        action_text = "\n".join(
            part for part in (
                description,
                f"method: {method}",
                f"schema: {schema_summary}" if schema_summary else "",
                f"parameters: {actual_parameter_summary}" if actual_parameter_summary else "",
                f"permissions: {permission_summary}" if permission_summary else "",
            ) if part
        )
        return CapabilitySemanticView(
            original_description=raw_description,
            description_missing=missing,
            humanized_method=method,
            schema_summary=schema_summary,
            permission_summary=permission_summary,
            actual_parameter_summary=actual_parameter_summary,
            action_text=action_text,
        )

    def _overlap_fast_path(
        self,
        user_query: str,
        view: CapabilitySemanticView,
        msg: MCPMessage,
        cap: MCPCapability,
    ) -> bool:
        if view.description_missing or not _is_english_text(user_query) or not _is_english_text(view.original_description):
            return False
        query_tokens = _content_tokens(user_query)
        action_tokens = _content_tokens(
            f"{view.original_description} {view.humanized_method}"
        )
        if len(query_tokens) < 2 or len(action_tokens) < 2:
            return False
        coverage = len(query_tokens & action_tokens) / max(len(action_tokens), 1)
        if coverage < self.overlap_threshold:
            return False
        return self._security_parameters_grounded(user_query, msg, cap)

    @staticmethod
    def _security_parameters_grounded(
        user_query: str, msg: MCPMessage, cap: MCPCapability
    ) -> bool:
        query = user_query.casefold()
        properties = (getattr(cap, "input_schema", {}) or {}).get("properties", {}) or {}
        for key, value in msg.params.items():
            spec = properties.get(key, {}) if isinstance(properties, dict) else {}
            if isinstance(spec, dict) and (value == spec.get("default") or value in (spec.get("enum") or [])):
                continue
            if isinstance(value, (str, int, float)) and str(value).casefold() not in query:
                return False
        return True

    @staticmethod
    def _permissions_allow_params(params: Dict[str, Any], permissions: List[str]) -> bool:
        text = json_stable(params).lower()
        if any(p in permissions for p in ("read:user_dir", "write:user_dir")):
            sensitive_path_patterns = [
                r"/etc/passwd",
                r"/etc/shadow",
                r"\.ssh/id_rsa",
                r"\.aws/credentials",
                r"/secrets?/",
            ]
            if any(re.search(pattern, text) for pattern in sensitive_path_patterns):
                return False
        if "read:db" in permissions:
            destructive_sql = ["drop table", "delete from", "update ", "insert into", "truncate "]
            sensitive_sql = ["card_number", "cvv", "password", "token", "secret"]
            if any(term in text for term in destructive_sql + sensitive_sql):
                return False
        return True

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


_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
    "in", "is", "it", "of", "on", "or", "that", "the", "this", "to",
    "use", "using", "with", "please", "tool", "get", "retrieve",
}


def _is_english_text(text: str) -> bool:
    letters = [char for char in str(text) if char.isalpha()]
    if not letters:
        return False
    latin = sum("a" <= char.casefold() <= "z" for char in letters)
    return latin / len(letters) >= 0.9


def _content_tokens(text: str) -> set:
    normalized = re.sub(r"([a-z])([A-Z])", r"\1 \2", str(text))
    tokens = {
        token.casefold()
        for token in re.findall(r"[A-Za-z0-9]+", normalized)
        if token.casefold() not in _STOPWORDS and len(token) > 1
    }
    return tokens
