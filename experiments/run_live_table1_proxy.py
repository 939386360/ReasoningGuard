import argparse
import json
import os
import sys
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_backbone_proxy import create_proxy_backbone
from src.evaluation import live_table1


def _parse_model_map(value: Optional[str]) -> Optional[Dict[str, str]]:
    if not value:
        return None
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("--agent_model_map must be a JSON object")
    return {str(k): str(v) for k, v in parsed.items()}


def main():
    proxy_parser = argparse.ArgumentParser(add_help=False)
    proxy_parser.add_argument("--agent_base_url", default=os.environ.get("LLM_API_BASE_URL", "https://llm-api.net/v1"))
    proxy_parser.add_argument("--agent_api_style", choices=["auto", "chat", "responses"], default="auto")
    proxy_parser.add_argument("--agent_api_key_env", default="LLM_API_KEY")
    proxy_parser.add_argument("--agent_model_map", default=None)
    proxy_parser.add_argument("--agent_timeout", type=int, default=60)

    proxy_args, remaining = proxy_parser.parse_known_args()
    try:
        model_map = _parse_model_map(proxy_args.agent_model_map)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Invalid --agent_model_map: {exc}") from exc

    def proxy_factory(model_name: str, mock_mode: bool = True, api_key: Optional[str] = None):
        return create_proxy_backbone(
            model_name=model_name,
            mock_mode=mock_mode,
            api_key=api_key,
            base_url=proxy_args.agent_base_url,
            api_style=proxy_args.agent_api_style,
            model_map=model_map,
            api_key_env=proxy_args.agent_api_key_env,
            timeout=proxy_args.agent_timeout,
        )

    live_table1.create_backbone = proxy_factory
    sys.argv = [sys.argv[0]] + remaining
    live_table1.main()


if __name__ == "__main__":
    main()
