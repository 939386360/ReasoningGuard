"""
Core object model for the restructured ReasoningGuard experiment framework.

This module implements the data lifecycle described in the project's
technical specification, enforcing strict separation between:
  - RuntimeSpec (model-visible, no labels)
  - EvaluationOracle (evaluator-only, never reaches agent/defense)
  - DefenseProfile (immutable defense configuration per ablation)

Key design principles:
  1. Each DefenseProfile creates an isolated AgentEpisode
  2. Origin Tags are added per-profile, not globally
  3. is_malicious never appears on MCPMessage
  4. All defenses must achieve num_invalid=0 for valid comparison
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class GatewayMode(Enum):
    """Protocol-layer gateway type."""
    NONE = "none"
    ATTEST_MCP = "attest_mcp"
    PTG = "ptg"


class Origin(Enum):
    """Source attribution for evidence and tags."""
    USER = "user"
    SERVER = "server"
    SYSTEM = "system"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Invocation and Effect specs (frozen, hashable)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InvocationSpec:
    """Immutable declaration of a tool invocation for matching."""
    server: str
    method: str
    params: Dict[str, Any]

    def matches(self, other: "InvocationSpec", normalizers: Optional[List[str]] = None) -> bool:
        """Check if this spec matches another, with optional normalization."""
        if self.server != other.server:
            return False
        if self.method != other.method:
            return False
        for key, value in self.params.items():
            actual = other.params.get(key)
            if normalizers and "casefold" in normalizers:
                if str(value).casefold() != str(actual).casefold():
                    return False
            elif value != actual:
                return False
        return True


@dataclass(frozen=True)
class EffectSpec:
    """Structured effect used by evaluator to judge attack success / task completion."""
    effect_id: str
    invocation: InvocationSpec
    constraints: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def matches_invocation(self, inv: InvocationSpec) -> bool:
        """Check if an invocation satisfies this effect."""
        if inv.server != self.invocation.server:
            return False
        if inv.method != self.invocation.method:
            return False
        for key, constraint in self.constraints.items():
            operator = constraint.get("operator", "eq")
            expected = constraint.get("value")
            actual = inv.params.get(key)
            if operator == "eq" and str(actual) != str(expected):
                return False
            elif operator == "contains" and str(expected) not in str(actual):
                return False
            elif operator == "startswith" and not str(actual).startswith(str(expected)):
                return False
        return True


# ---------------------------------------------------------------------------
# ScheduledInput (for T2/T3 multi-turn delivery)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScheduledInput:
    """A simulated external input delivered by the runner after a trigger call."""
    input_id: str
    deliver_after: InvocationSpec
    source_id: str
    body: str
    benign_body: str = ""


# ---------------------------------------------------------------------------
# RuntimeSpec (model-visible, no labels)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuntimeSpec:
    """Execution specification visible to runner. Contains NO malicious labels."""
    user_query: str
    trusted_registry: Tuple[Any, ...]  # tuple of MCPServer
    agent_catalog: Tuple[Any, ...]     # tuple of MCPServer
    scheduled_inputs: Tuple[ScheduledInput, ...] = ()
    # For T2: setup and trigger queries
    setup_query: Optional[str] = None
    trigger_query: Optional[str] = None
    # For T3: poison session and gap sessions
    poison_session_query: Optional[str] = None
    gap_sessions: Tuple[str, ...] = ()  # gap session user queries
    trigger_session_query: Optional[str] = None


# ---------------------------------------------------------------------------
# EvaluationOracle (evaluator-only, NEVER reaches agent or defense)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvaluationOracle:
    """Ground truth for evaluation. Isolated from runtime."""
    benign_effects: Tuple[EffectSpec, ...]
    malicious_effects: Tuple[EffectSpec, ...]
    # For T2: effect only counts in trigger phase
    trigger_phase_only: bool = False
    # For T3: memory effect constraints
    memory_effect_constraints: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# ScenarioCase (top-level immutable experiment case)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScenarioCase:
    """One immutable experiment case with runtime spec and evaluation oracle."""
    scenario_id: str
    source_group_id: str
    category: str
    temporality: str  # "T1" | "T2" | "T3"
    attack_layer: str  # "L4" | "L2"
    runtime_spec: RuntimeSpec
    oracle: EvaluationOracle


# ---------------------------------------------------------------------------
# OriginTag and ParameterSource (defense-visible provenance)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OriginTag:
    """AttestMCP/PTG certified origin for a piece of evidence."""
    evidence_id: str
    origin: Origin
    source_id: str
    issuer: str  # "ATTEST_MCP" or "PTG"


@dataclass(frozen=True)
class ParameterSource:
    """Records which evidence supports a parameter value."""
    json_path: str
    value: Any
    source_evidence_ids: Tuple[str, ...]
    user_authorized: bool


@dataclass(frozen=True)
class ProvenanceEvidence:
    """A piece of model-visible fact with stable ID."""
    evidence_id: str
    content: str
    origin: Origin
    source_id: str
    turn_id: str


# ---------------------------------------------------------------------------
# DefenseProfile (immutable defense configuration)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DefenseProfile:
    """Immutable defense/ablation configuration."""
    profile_id: str
    gateway_mode: GatewayMode
    use_origin_tags: bool
    use_intent_attestation: bool
    use_action_guardrail: bool
    use_rtv: bool
    use_memory_graph: bool

    @staticmethod
    def no_defense() -> "DefenseProfile":
        return DefenseProfile(
            profile_id="no_defense",
            gateway_mode=GatewayMode.NONE,
            use_origin_tags=False,
            use_intent_attestation=False,
            use_action_guardrail=False,
            use_rtv=False,
            use_memory_graph=False,
        )

    @staticmethod
    def attest_mcp() -> "DefenseProfile":
        return DefenseProfile(
            profile_id="attest_mcp",
            gateway_mode=GatewayMode.ATTEST_MCP,
            use_origin_tags=True,
            use_intent_attestation=False,
            use_action_guardrail=False,
            use_rtv=False,
            use_memory_graph=False,
        )

    @staticmethod
    def guardrail() -> "DefenseProfile":
        return DefenseProfile(
            profile_id="guardrail",
            gateway_mode=GatewayMode.NONE,
            use_origin_tags=False,
            use_intent_attestation=False,
            use_action_guardrail=True,
            use_rtv=False,
            use_memory_graph=False,
        )

    @staticmethod
    def ptg_only() -> "DefenseProfile":
        return DefenseProfile(
            profile_id="ptg_only",
            gateway_mode=GatewayMode.PTG,
            use_origin_tags=True,
            use_intent_attestation=True,
            use_action_guardrail=False,
            use_rtv=False,
            use_memory_graph=False,
        )

    @staticmethod
    def rtv_only() -> "DefenseProfile":
        return DefenseProfile(
            profile_id="rtv_only",
            gateway_mode=GatewayMode.NONE,
            use_origin_tags=False,
            use_intent_attestation=False,
            use_action_guardrail=False,
            use_rtv=True,
            use_memory_graph=True,
        )

    @staticmethod
    def reasoning_guard() -> "DefenseProfile":
        return DefenseProfile(
            profile_id="reasoning_guard",
            gateway_mode=GatewayMode.PTG,
            use_origin_tags=True,
            use_intent_attestation=True,
            use_action_guardrail=False,
            use_rtv=True,
            use_memory_graph=True,
        )

    # Ablation variants for Table 5
    @staticmethod
    def rg_minus_intent() -> "DefenseProfile":
        return DefenseProfile(
            profile_id="rg_minus_intent",
            gateway_mode=GatewayMode.PTG,
            use_origin_tags=True,
            use_intent_attestation=False,
            use_action_guardrail=False,
            use_rtv=True,
            use_memory_graph=True,
        )

    @staticmethod
    def rg_minus_origin() -> "DefenseProfile":
        return DefenseProfile(
            profile_id="rg_minus_origin",
            gateway_mode=GatewayMode.PTG,
            use_origin_tags=False,
            use_intent_attestation=True,
            use_action_guardrail=False,
            use_rtv=True,
            use_memory_graph=True,
        )

    @staticmethod
    def rg_minus_memory() -> "DefenseProfile":
        return DefenseProfile(
            profile_id="rg_minus_memory",
            gateway_mode=GatewayMode.PTG,
            use_origin_tags=True,
            use_intent_attestation=True,
            use_action_guardrail=False,
            use_rtv=True,
            use_memory_graph=False,
        )

    @staticmethod
    def all_profiles() -> List["DefenseProfile"]:
        """Return the six main-table profiles."""
        return [
            DefenseProfile.no_defense(),
            DefenseProfile.attest_mcp(),
            DefenseProfile.guardrail(),
            DefenseProfile.ptg_only(),
            DefenseProfile.rtv_only(),
            DefenseProfile.reasoning_guard(),
        ]

    @staticmethod
    def ablation_profiles() -> List["DefenseProfile"]:
        """Return the six ablation profiles for Table 5."""
        return [
            DefenseProfile.reasoning_guard(),
            DefenseProfile.rg_minus_intent(),
            DefenseProfile.rg_minus_origin(),
            DefenseProfile.rg_minus_memory(),
            DefenseProfile.ptg_only(),  # -RTV
            DefenseProfile.rtv_only(),  # -PTG
        ]


# ---------------------------------------------------------------------------
# InteractionTurn / AgentSession / AgentEpisode (runtime state)
# ---------------------------------------------------------------------------

@dataclass
class InteractionTurn:
    """One turn of model interaction within a session."""
    turn_id: str
    model_messages: List[Dict[str, Any]] = field(default_factory=list)
    raw_model_response: Optional[str] = None
    reasoning_trace: Optional[Any] = None  # ReasoningTrace
    invocation: Optional[Any] = None       # MCPMessage (candidate tool call)
    tool_result: Optional[Any] = None      # MCPMessage (simulated tool response)
    evidence: List[ProvenanceEvidence] = field(default_factory=list)
    parameter_sources: List[ParameterSource] = field(default_factory=list)


@dataclass
class AgentSession:
    """A chat session with ordered turns."""
    session_id: str
    turns: List[InteractionTurn] = field(default_factory=list)
    memory_reads: List[str] = field(default_factory=list)
    memory_writes: List[str] = field(default_factory=list)


@dataclass
class AgentEpisode:
    """One isolated run of a ScenarioCase under a specific DefenseProfile."""
    episode_id: str
    scenario_id: str
    profile_id: str
    sessions: List[AgentSession] = field(default_factory=list)
    memory_store: Dict[str, Any] = field(default_factory=dict)  # entry_id -> MemoryEntry
    defense_runs: List["DefenseRun"] = field(default_factory=list)


# ---------------------------------------------------------------------------
# DefenseRun (one defense judgment per invocation)
# ---------------------------------------------------------------------------

@dataclass
class DefenseRun:
    """One defense judgment record for a specific invocation."""
    profile_id: str
    invocation_id: str
    visible_origin_tags: Tuple[OriginTag, ...] = ()
    visible_evidence_ids: Tuple[str, ...] = ()
    visible_memory_ids: Tuple[str, ...] = ()
    gateway_result: Optional[Any] = None   # PTGResult
    rtv_result: Optional[Any] = None       # RTVResult
    verdict: Optional[str] = None          # "APPROVE" | "BLOCK" | "ESCALATE"
    runtime_error: Optional[Dict[str, Any]] = None
    gateway_latency_ms: float = 0.0
    rtv_latency_ms: float = 0.0
    guardrail_latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# EvaluationOutcome (final evaluation per episode)
# ---------------------------------------------------------------------------

@dataclass
class EvaluationOutcome:
    """Final evaluation result after episode completion."""
    episode_id: str
    profile_id: str
    matched_effect_id: Optional[str] = None
    matched_invocation_id: Optional[str] = None
    attack_succeeded: bool = False
    task_completed: bool = False
    metrics_valid: bool = False
    # Diagnostic fields
    delivery_status: str = "pending"  # "delivered" | "failed" | "skipped"
    memory_write_status: str = "pending"
    memory_read_status: str = "pending"
