import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_backbone_proxy import create_proxy_backbone


class TestAgentBackboneProxy(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("LLM_API_KEY"), "Set LLM_API_KEY to run the live relay test")
    def test_llm_api_chat_completions_gpt4o(self):
        agent = create_proxy_backbone(
            "GPT-4o",
            mock_mode=False,
            base_url=os.environ.get("LLM_API_BASE_URL", "https://llm-api.net/v1/chat/completions"),
            api_style="chat",
            max_tokens=20,
            temperature=0.0,
        )
        agent.conversation_history = [
            {"role": "system", "content": "You are a test agent."},
            {"role": "user", "content": "Reply with only the word ok."},
        ]
        response = agent._call_llm()

        self.assertEqual(agent.model, "gpt-4o")
        self.assertEqual(agent.api_style, "chat")
        self.assertEqual(agent.endpoint_url, "https://llm-api.net/v1/chat/completions")
        self.assertTrue(response.strip())
        self.assertIn("ok", response.lower())


if __name__ == "__main__":
    unittest.main()
