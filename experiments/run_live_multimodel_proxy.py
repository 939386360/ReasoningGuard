import argparse
import json
import os
import sys
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_backbone_proxy import create_proxy_backbone
from src.evaluation import live_table1


DEFAULT_MODELS = "GPT-4o,Claude-3.5-Sonnet,Gemini-1.5-Pro,Llama-3.1-70B"


def _parse_model_map(value: Optional[str]) -> Optional[Dict[str, str]]:
    if not value:
        return None
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("--agent_model_map must be a JSON object")
    return {str(k): str(v) for k, v in parsed.items()}


def _parse_models(value: str):
    return [item.strip() for item in value.split(",") if item.strip()]


def main():
    parser = argparse.ArgumentParser(description="Run live multi-model evaluation through an OpenAI-compatible relay.")
    parser.add_argument("--models", default=DEFAULT_MODELS)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--max_scenarios", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--data_dir", default="data/mcptox")
    parser.add_argument("--synthetic", action="store_true")
    parser.add_argument("--agent_mock", action="store_true")
    parser.add_argument("--agent_base_url", default=os.environ.get("LLM_API_BASE_URL", "https://llm-api.net/v1/chat/completions"))
    parser.add_argument("--agent_api_style", choices=["auto", "chat", "responses"], default="chat")
    parser.add_argument("--agent_api_key_env", default="LLM_API_KEY")
    parser.add_argument("--agent_model_map", default=None)
    parser.add_argument("--agent_timeout", type=int, default=60)
    parser.add_argument("--judge_mode", choices=["heuristic", "llm"], default="heuristic")
    parser.add_argument("--judge_provider", default="vllm")
    parser.add_argument("--judge_model", default="models/judge_qwen2.5-7b/final")
    parser.add_argument("--judge_base_url", default=None)
    parser.add_argument("--llamaguard_mock", action="store_true")
    parser.add_argument("--output", default="results/live_multimodel_proxy_results.json")
    args = parser.parse_args()

    try:
        model_map = _parse_model_map(args.agent_model_map)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Invalid --agent_model_map: {exc}") from exc

    def proxy_factory(model_name: str, mock_mode: bool = True, api_key: Optional[str] = None):
        return create_proxy_backbone(
            model_name=model_name,
            mock_mode=mock_mode,
            api_key=api_key,
            base_url=args.agent_base_url,
            api_style=args.agent_api_style,
            model_map=model_map,
            api_key_env=args.agent_api_key_env,
            timeout=args.agent_timeout,
        )

    live_table1.create_backbone = proxy_factory

    results = {}
    for idx, model_name in enumerate(_parse_models(args.models)):
        results[model_name] = live_table1.run_live_table1_multi(
            runs=args.runs,
            model_name=model_name,
            max_scenarios=args.max_scenarios,
            seed=args.seed + idx * max(args.runs, 1),
            use_official=not args.synthetic,
            data_dir=args.data_dir,
            agent_mock=args.agent_mock,
            judge_mode=args.judge_mode,
            judge_provider=args.judge_provider,
            judge_model=args.judge_model,
            judge_base_url=args.judge_base_url,
            llamaguard_mock=args.llamaguard_mock,
        )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"Saved results to {args.output}")


if __name__ == "__main__":
    main()
