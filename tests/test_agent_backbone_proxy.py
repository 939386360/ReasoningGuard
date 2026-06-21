import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_backbone_proxy import (
    ProxyAgentBackbone,
    create_proxy_backbone,
    extract_chat_completion_text,
    extract_responses_text,
    infer_api_style,
    normalize_llm_api_url,
)


class TestAgentBackboneProxy(unittest.TestCase):
    def test_normalize_chat_urls(self):
        self.assertEqual(
            normalize_llm_api_url("https://llm-api.net/v1", "chat"),
            "https://llm-api.net/v1/chat/completions",
        )
        self.assertEqual(
            normalize_llm_api_url("https://llm-api.net/v1/chat/completions", "chat"),
            "https://llm-api.net/v1/chat/completions",
        )
        self.assertEqual(
            normalize_llm_api_url("https://llm-api.net/v1/responses", "chat"),
            "https://llm-api.net/v1/chat/completions",
        )

    def test_normalize_responses_urls(self):
        self.assertEqual(
            normalize_llm_api_url("https://llm-api.net/v1", "responses"),
            "https://llm-api.net/v1/responses",
        )
        self.assertEqual(
            normalize_llm_api_url("https://llm-api.net/v1/chat/completions", "responses"),
            "https://llm-api.net/v1/responses",
        )
        self.assertEqual(
            normalize_llm_api_url("https://llm-api.net/v1/responses", "responses"),
            "https://llm-api.net/v1/responses",
        )

    def test_auto_api_style(self):
        self.assertEqual(infer_api_style("https://llm-api.net/v1", "auto"), "chat")
        self.assertEqual(infer_api_style("https://llm-api.net/v1/chat/completions", "auto"), "chat")
        self.assertEqual(infer_api_style("https://llm-api.net/v1/responses", "auto"), "responses")

    def test_extract_chat_completion_text(self):
        data = {"choices": [{"message": {"content": "hello"}}]}
        self.assertEqual(extract_chat_completion_text(data), "hello")

    def test_extract_responses_text(self):
        self.assertEqual(extract_responses_text({"output_text": "hello"}), "hello")
        data = {
            "output": [
                {"content": [{"type": "output_text", "text": "hello"}, {"type": "output_text", "text": " world"}]}
            ]
        }
        self.assertEqual(extract_responses_text(data), "hello world")

    def test_chat_call_payload_and_response(self):
        agent = ProxyAgentBackbone(model="gpt-4o", base_url="https://llm-api.net/v1", api_style="chat", mock_mode=False)
        agent.conversation_history = [{"role": "user", "content": "hi"}]
        captured = {}

        def fake_post(payload):
            captured.update(payload)
            return {"choices": [{"message": {"content": "ok"}}]}

        agent._post_json = fake_post
        self.assertEqual(agent._call_llm(), "ok")
        self.assertEqual(captured["model"], "gpt-4o")
        self.assertIn("messages", captured)
        self.assertNotIn("input", captured)

    def test_responses_call_payload_and_response(self):
        agent = ProxyAgentBackbone(
            model="gpt-4o",
            base_url="https://llm-api.net/v1/responses",
            api_style="responses",
            mock_mode=False,
        )
        agent.conversation_history = [{"role": "user", "content": "hi"}]
        captured = {}

        def fake_post(payload):
            captured.update(payload)
            return {"output_text": "ok"}

        agent._post_json = fake_post
        self.assertEqual(agent._call_llm(), "ok")
        self.assertEqual(captured["model"], "gpt-4o")
        self.assertIn("input", captured)
        self.assertNotIn("messages", captured)

    def test_create_proxy_backbone_default_model_map(self):
        with patch.dict(os.environ, {"LLM_API_KEY": "test-key"}, clear=False):
            agent = create_proxy_backbone("Claude-3.5-Sonnet", mock_mode=True, base_url="https://llm-api.net/v1")
        self.assertEqual(agent.model, "claude-3-5-sonnet-20241022")
        self.assertEqual(agent.api_key, "test-key")

    def test_create_proxy_backbone_env_model_map_override(self):
        env = {"LLM_API_MODEL_MAP": '{"GPT-4o": "relay-gpt-4o"}', "LLM_API_KEY": "test-key"}
        with patch.dict(os.environ, env, clear=False):
            agent = create_proxy_backbone("GPT-4o", mock_mode=True, base_url="https://llm-api.net/v1")
        self.assertEqual(agent.model, "relay-gpt-4o")


if __name__ == "__main__":
    unittest.main()
