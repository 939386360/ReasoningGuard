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

    def test_live_table1_llm_judge_defaults_to_local_qwen(self):
        judge = make_judge(judge_mode="llm")

        self.assertEqual(judge.interface.model, DEFAULT_LOCAL_JUDGE_MODEL)
        self.assertEqual(judge.interface.base_url, DEFAULT_LOCAL_JUDGE_URL)


if __name__ == "__main__":
    unittest.main()
