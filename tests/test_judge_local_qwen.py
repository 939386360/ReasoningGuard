import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.evaluation.live_table1 import make_judge
from src.judge import (
    DEFAULT_LOCAL_JUDGE_MODEL,
    DEFAULT_LOCAL_JUDGE_URL,
    LLMJudgeInterface,
    normalize_chat_completions_url,
)


class TestLocalQwenJudge(unittest.TestCase):
    def test_normalize_chat_completions_url(self):
        self.assertEqual(
            normalize_chat_completions_url("http://aias-compute-4:14545/v1"),
            "http://aias-compute-4:14545/v1/chat/completions",
        )
        self.assertEqual(
            normalize_chat_completions_url("http://aias-compute-4:14545"),
            "http://aias-compute-4:14545/v1/chat/completions",
        )
        self.assertEqual(
            normalize_chat_completions_url(DEFAULT_LOCAL_JUDGE_URL),
            DEFAULT_LOCAL_JUDGE_URL,
        )

    @patch("requests.post")
    def test_vllm_payload_uses_deterministic_generation(self, post):
        response = Mock()
        response.json.return_value = {
            "choices": [{"message": {"content": '{"CAI": 0.2, "OAV": 0.3, "IAD": 0.4}'}}]
        }
        post.return_value = response

        judge = LLMJudgeInterface(
            provider="vllm",
            model=DEFAULT_LOCAL_JUDGE_MODEL,
            base_url="http://aias-compute-4:14545/v1",
        )
        scores = judge.score("trace", "intent", [])

        self.assertEqual(scores, {"CAI": 0.2, "OAV": 0.3, "IAD": 0.4})
        url = post.call_args.args[0]
        payload = post.call_args.kwargs["json"]
        self.assertEqual(url, DEFAULT_LOCAL_JUDGE_URL)
        self.assertEqual(payload["model"], DEFAULT_LOCAL_JUDGE_MODEL)
        self.assertEqual(payload["temperature"], 0.0)
        self.assertFalse(payload["do_sample"])
        self.assertEqual([item["role"] for item in payload["messages"]], ["system", "user"])
        self.assertIn("tool-use decisions", payload["messages"][0]["content"])
        self.assertIn("Case record", payload["messages"][1]["content"])

    def test_openai_uses_system_and_user_messages(self):
        judge = LLMJudgeInterface(provider="openai", model="test", api_key="test")
        client = Mock()
        response = Mock()
        response.choices = [Mock(message=Mock(content='{"CAI":0.1,"OAV":0.1,"IAD":0.1}'))]
        client.chat.completions.create.return_value = response
        judge._client = client

        judge.score("trace", "intent")

        messages = client.chat.completions.create.call_args.kwargs["messages"]
        self.assertEqual([item["role"] for item in messages], ["system", "user"])

    def test_anthropic_uses_system_parameter(self):
        judge = LLMJudgeInterface(provider="anthropic", model="test", api_key="test")
        client = Mock()
        response = Mock()
        response.content = [Mock(text='{"CAI":0.1,"OAV":0.1,"IAD":0.1}')]
        client.messages.create.return_value = response
        judge._client = client

        judge.score("trace", "intent")

        kwargs = client.messages.create.call_args.kwargs
        self.assertIn("tool-use decisions", kwargs["system"])
        self.assertEqual(kwargs["messages"][0]["role"], "user")

    def test_live_table1_llm_judge_defaults_to_local_qwen(self):
        judge = make_judge(judge_mode="llm")

        self.assertEqual(judge.interface.model, DEFAULT_LOCAL_JUDGE_MODEL)
        self.assertEqual(judge.interface.base_url, DEFAULT_LOCAL_JUDGE_URL)


if __name__ == "__main__":
    unittest.main()
