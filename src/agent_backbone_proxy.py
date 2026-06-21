import json
import os
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit

from src.agent_backbone import AgentBackbone


DEFAULT_PROXY_BASE_URL = "https://llm-api.net/v1"

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
        content = message.get("content")
        if isinstance(content, str):
            return content
    text = first.get("text")
    return text if isinstance(text, str) else ""


def extract_responses_text(data: Mapping[str, Any]) -> str:
    output_text = data.get("output_text")
    if isinstance(output_text, str):
        return output_text

    chunks: List[str] = []
    for item in data.get("output") or []:
        if not isinstance(item, Mapping):
            continue
        for content in item.get("content") or []:
            if not isinstance(content, Mapping):
                continue
            text = content.get("text")
            if isinstance(text, str):
                chunks.append(text)
            elif isinstance(text, Mapping) and isinstance(text.get("value"), str):
                chunks.append(text["value"])
    if chunks:
        return "".join(chunks)

    return extract_chat_completion_text(data)


class ProxyAgentBackbone(AgentBackbone):
    def __init__(
        self,
        model: str,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_PROXY_BASE_URL,
        api_style: str = "auto",
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
                return extract_responses_text(data)

            payload = self._chat_payload()
            data = self._post_json(payload)
            return extract_chat_completion_text(data)
        except Exception as exc:
            print(f"[ProxyAgentBackbone] LLM call failed: {exc}")
            return ""

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
    api_style: str = "auto",
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
