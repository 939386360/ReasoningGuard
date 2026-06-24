import json
import os
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit

from src.agent_backbone import AgentBackbone
from src.runtime_audit import audit_event, is_strict_runtime


DEFAULT_PROXY_BASE_URL = "https://llm-api.net/v1/chat/completions"

DEFAULT_MODEL_MAP: Dict[str, str] = {
    "GPT-4o": "gpt-4o",
    "Claude-3.5-Sonnet": "claude-3-5-sonnet-20241022",
    "Gemini-1.5-Pro": "gemini-1.5-pro",
    "Llama-3.1-70B": "meta-llama/Llama-3.1-70B-Instruct",
}

SUPPORTED_API_STYLES = {"auto", "chat", "responses"}


def load_model_map(
    explicit_map: Optional[Mapping[str, str]] = None,
    env_var: str = "LLM_API_MODEL_MAP",
) -> Dict[str, str]:
    model_map = dict(DEFAULT_MODEL_MAP)
    env_value = os.environ.get(env_var)
    if env_value:
        try:
            parsed = json.loads(env_value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{env_var} must be a JSON object") from exc
        if not isinstance(parsed, dict):
            raise ValueError(f"{env_var} must be a JSON object")
        model_map.update({str(k): str(v) for k, v in parsed.items()})
    if explicit_map:
        model_map.update({str(k): str(v) for k, v in explicit_map.items()})
    return model_map


def infer_api_style(base_url: str, api_style: str = "auto") -> str:
    style = api_style.lower()
    if style not in SUPPORTED_API_STYLES:
        raise ValueError(f"Unsupported api_style: {api_style}")
    if style != "auto":
        return style

    path = urlsplit(base_url).path.rstrip("/")
    if path.endswith("/responses"):
        return "responses"
    return "chat"


def normalize_llm_api_url(base_url: str, api_style: str = "chat") -> str:
    style = infer_api_style(base_url, api_style)
    parts = urlsplit(base_url.rstrip("/"))
    path = parts.path.rstrip("/")

    if path.endswith("/chat/completions"):
        root = path[: -len("/chat/completions")]
    elif path.endswith("/responses"):
        root = path[: -len("/responses")]
    else:
        root = path

    if root in ("", "/"):
        root = "/v1"

    endpoint = "/chat/completions" if style == "chat" else "/responses"
    normalized_path = root.rstrip("/") + endpoint
    return urlunsplit((parts.scheme, parts.netloc, normalized_path, parts.query, parts.fragment))


def extract_chat_completion_text(data: Mapping[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    first = choices[0]
    if not isinstance(first, Mapping):
        return ""
    message = first.get("message") or {}
    if isinstance(message, Mapping):
        content = _content_to_text(message.get("content"))
        tool_calls = _native_tool_call_payloads(message)
        refusal = _content_to_text(message.get("refusal"))
        if content or tool_calls or refusal:
            return _compose_agent_response(content, tool_calls, refusal)
    text = first.get("text")
    return text if isinstance(text, str) else ""


def extract_responses_text(data: Mapping[str, Any]) -> str:
    output_text = data.get("output_text")
    chunks: List[str] = [output_text] if isinstance(output_text, str) else []
    tool_calls: List[str] = []
    refusals: List[str] = []
    for item in data.get("output") or []:
        if not isinstance(item, Mapping):
            continue
        item_type = str(item.get("type") or "").lower()
        if item_type in ("function_call", "tool_call"):
            tool_calls.extend(_native_tool_call_payloads(item))
            continue
        if item_type == "refusal":
            refusal = _content_to_text(item.get("refusal") or item.get("content"))
            if refusal:
                refusals.append(refusal)
            continue
        if chunks and isinstance(output_text, str):
            tool_calls.extend(_native_tool_call_payloads(item))
            refusal = _content_to_text(item.get("refusal"))
            if refusal:
                refusals.append(refusal)
            continue
        for content in item.get("content") or []:
            if not isinstance(content, Mapping):
                continue
            content_type = str(content.get("type") or "").lower()
            if content_type == "refusal":
                refusal = _content_to_text(
                    content.get("refusal") or content.get("text")
                )
                if refusal:
                    refusals.append(refusal)
                continue
            text = _content_to_text(content)
            if text:
                chunks.append(text)
        tool_calls.extend(_native_tool_call_payloads(item))
        refusal = _content_to_text(item.get("refusal"))
        if refusal:
            refusals.append(refusal)
    if chunks or tool_calls or refusals:
        return _compose_agent_response(
            "".join(chunks),
            tool_calls,
            "\n".join(refusals),
        )

    return extract_chat_completion_text(data)


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(_content_to_text(part) for part in content)
    if not isinstance(content, Mapping):
        return ""

    text = content.get("text")
    if isinstance(text, str):
        return text
    if isinstance(text, Mapping):
        value = text.get("value")
        if isinstance(value, str):
            return value

    value = content.get("value")
    if isinstance(value, str):
        return value

    nested_content = content.get("content")
    if nested_content is not content:
        nested_text = _content_to_text(nested_content)
        if nested_text:
            return nested_text

    if any(
        key in content
        for key in (
            "tool_call",
            "server",
            "method",
            "params",
            "arguments",
            "parameters",
        )
    ):
        return json.dumps(dict(content), ensure_ascii=False)
    return ""


def _native_tool_call_payloads(container: Mapping[str, Any]) -> List[str]:
    payloads: List[str] = []
    candidates: List[Any] = []

    tool_calls = container.get("tool_calls")
    if isinstance(tool_calls, list):
        candidates.extend(tool_calls)

    function_call = container.get("function_call")
    if isinstance(function_call, Mapping):
        candidates.append(function_call)

    if str(container.get("type") or "").lower() in ("function_call", "tool_call"):
        candidates.append(container)

    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        function = candidate.get("function")
        source = function if isinstance(function, Mapping) else candidate
        arguments = source.get("arguments")
        if isinstance(arguments, str) and arguments.strip():
            payloads.append(arguments.strip())
        elif isinstance(arguments, Mapping):
            payloads.append(json.dumps(dict(arguments), ensure_ascii=False))
    return payloads


def _compose_agent_response(
    content: str,
    tool_calls: List[str],
    refusal: str,
) -> str:
    parts: List[str] = []
    if content.strip():
        parts.append(content.strip())
    for payload in tool_calls:
        parts.append(f"TOOL_CALL:\n{payload}")
    if refusal.strip() and not tool_calls:
        parts.append(f"TOOL_CALL:\nNone\n\nPROVIDER_REFUSAL:\n{refusal.strip()}")
    return "\n\n".join(parts)


class ProxyAgentBackbone(AgentBackbone):
    def __init__(
        self,
        model: str,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_PROXY_BASE_URL,
        api_style: str = "chat",
        mock_mode: bool = True,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        timeout: int = 60,
    ):
        super().__init__(
            provider="proxy",
            model=model,
            api_key=api_key,
            base_url=base_url,
            mock_mode=mock_mode,
        )
        self.api_style = infer_api_style(base_url, api_style)
        self.endpoint_url = normalize_llm_api_url(base_url, self.api_style)
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout

    def _call_llm(self) -> str:
        try:
            if self.api_style == "responses":
                payload = self._responses_payload()
                data = self._post_json(payload)
                text = extract_responses_text(data)
            else:
                payload = self._chat_payload()
                data = self._post_json(payload)
                text = extract_chat_completion_text(data)
        except Exception as exc:
            audit_event(
                "agent",
                "agent.call_failed",
                severity="ERROR",
                message="Proxy agent LLM call failed",
                provider=self.provider,
                model=self.model,
                base_url=self.endpoint_url,
                api_style=self.api_style,
                fallback_used=not is_strict_runtime(),
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            print(f"[ProxyAgentBackbone] LLM call failed: {exc}")
            if is_strict_runtime():
                raise
            return ""
        return self._checked_response_text(text)

    def _checked_response_text(self, text: str) -> str:
        if not text.strip():
            audit_event(
                "agent",
                "agent.empty_response",
                severity="WARNING",
                message="Proxy agent returned an empty response",
                provider=self.provider,
                model=self.model,
                base_url=self.endpoint_url,
                api_style=self.api_style,
                fallback_used=True,
            )
            if is_strict_runtime():
                raise RuntimeError("Proxy agent returned an empty response")
        return text

    def _chat_payload(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "messages": self.conversation_history,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

    def _responses_payload(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "input": self.conversation_history,
            "temperature": self.temperature,
            "max_output_tokens": self.max_tokens,
        }

    def _post_json(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        import requests

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        response = requests.post(
            self.endpoint_url,
            json=dict(payload),
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()


def create_proxy_backbone(
    model_name: str,
    mock_mode: bool = True,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    api_style: str = "chat",
    model_map: Optional[Mapping[str, str]] = None,
    api_key_env: str = "LLM_API_KEY",
    max_tokens: int = 1024,
    temperature: float = 0.0,
    timeout: int = 60,
) -> ProxyAgentBackbone:
    resolved_model_map = load_model_map(model_map)
    model = resolved_model_map.get(model_name, model_name)
    resolved_api_key = api_key or os.environ.get(api_key_env) or os.environ.get("OPENAI_API_KEY")
    resolved_base_url = base_url or os.environ.get("LLM_API_BASE_URL") or DEFAULT_PROXY_BASE_URL

    return ProxyAgentBackbone(
        model=model,
        api_key=resolved_api_key,
        base_url=resolved_base_url,
        api_style=api_style,
        mock_mode=mock_mode,
        max_tokens=max_tokens,
        temperature=temperature,
        timeout=timeout,
    )
