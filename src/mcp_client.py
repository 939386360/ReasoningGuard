import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class MCPMessageType(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    SAMPLING = "sampling"


class Origin(Enum):
    USER = "user"
    SERVER = "server"
    SYSTEM = "system"


@dataclass
class MCPCapability:
    name: str
    description: str
    methods: List[str]
    permissions: List[str]
    input_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPServer:
    server_id: str
    name: str
    capabilities: List[MCPCapability]
    is_compromised: bool = False


@dataclass
class MCPMessage:
    msg_type: MCPMessageType
    sender: str
    recipient: str
    method: str
    params: Dict[str, Any]
    msg_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    origin: Origin = Origin.USER
    provenance_tags: List[Dict[str, str]] = field(default_factory=list)
    intent_summary: Optional[str] = None
    is_malicious: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "msg_type": self.msg_type.value,
            "sender": self.sender,
            "recipient": self.recipient,
            "method": self.method,
            "params": self.params,
            "msg_id": self.msg_id,
            "timestamp": self.timestamp,
            "origin": self.origin.value,
            "provenance_tags": self.provenance_tags,
            "intent_summary": self.intent_summary,
        }


class MCPClient:
    def __init__(self, client_id: str = "agent"):
        self.client_id = client_id
        self.servers: Dict[str, MCPServer] = {}
        self.message_log: List[MCPMessage] = []
        self.session_id = str(uuid.uuid4())

    def register_server(self, server: MCPServer):
        self.servers[server.server_id] = server

    def create_tool_invocation(
        self,
        server_id: str,
        method: str,
        args: Dict[str, Any],
        intent_summary: Optional[str] = None,
    ) -> Optional[MCPMessage]:
        if server_id not in self.servers:
            return None
        msg = MCPMessage(
            msg_type=MCPMessageType.REQUEST,
            sender=self.client_id,
            recipient=server_id,
            method=method,
            params=args,
            intent_summary=intent_summary,
        )
        self.message_log.append(msg)
        return msg

    def create_sampling_response(
        self,
        server_id: str,
        content: str,
        origin: Origin = Origin.SERVER,
        is_malicious: bool = False,
    ) -> MCPMessage:
        msg = MCPMessage(
            msg_type=MCPMessageType.SAMPLING,
            sender=server_id,
            recipient=self.client_id,
            method="sampling/response",
            params={"content": content},
            origin=origin,
            is_malicious=is_malicious,
            provenance_tags=[{"server_id": server_id, "origin": "server"}],
        )
        self.message_log.append(msg)
        return msg


@dataclass
class ReasoningStep:
    observation: str
    inference: str
    decision: str
    evidence_citations: List[str] = field(default_factory=list)
    origin_awareness: Dict[str, Origin] = field(default_factory=dict)


@dataclass
class ReasoningTrace:
    steps: List[ReasoningStep] = field(default_factory=list)
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    def add_step(self, step: ReasoningStep):
        self.steps.append(step)

    def to_text(self) -> str:
        parts = []
        for i, s in enumerate(self.steps):
            parts.append(
                f"Step {i+1}:\n"
                f"  Observation: {s.observation}\n"
                f"  Inference: {s.inference}\n"
                f"  Decision: {s.decision}"
            )
        return "\n".join(parts)


@dataclass
class MemoryEntry:
    entry_id: str
    content: str
    origin: Origin
    session_id: str
    intent_hash: str
    timestamp: float
    is_flagged: bool = False
    dependencies: List[str] = field(default_factory=list)


@dataclass
class ProvenanceLedger:
    entries: Dict[str, Tuple[MCPMessage, str, ReasoningTrace, float]] = field(default_factory=dict)

    def record(self, msg: MCPMessage, intent_sig: str, trace: ReasoningTrace, ts: float):
        self.entries[msg.msg_id] = (msg, intent_sig, trace, ts)

    def lookup(self, msg_id: str) -> Optional[Tuple[MCPMessage, str, ReasoningTrace, float]]:
        return self.entries.get(msg_id)
