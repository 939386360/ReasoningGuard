import json
import os
import random
from typing import Any, Dict, List, Optional

"""
MCPTox benchmark loader.

The original MCPTox dataset (AAAI-26, Wang et al. 2026) contains 200 tool poisoning
scenarios across 4 attack categories on real-world MCP servers.

If the official dataset is not available locally, this module generates a synthetic
version following the same distribution and category structure.
"""

MCPTOX_CATEGORIES = [
    "tool_description_poisoning",
    "parameter_injection",
    "response_manipulation",
    "capability_escalation",
]

MCPTOX_DISTRIBUTION = {
    "tool_description_poisoning": 55,
    "parameter_injection": 50,
    "response_manipulation": 55,
    "capability_escalation": 40,
}


def load_mcptox(
    data_dir: str = "data/mcptox",
    use_official: bool = True,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    official_path = os.path.join(data_dir, "mcptox_official.json")
    if use_official and os.path.exists(official_path):
        with open(official_path, encoding="utf-8") as f:
            data = json.load(f)
        print(f"Loaded official MCPTox: {len(data['scenarios'])} scenarios from {official_path}")
        return data["scenarios"]

    return _generate_synthetic_mcptox(seed=seed)


def _generate_synthetic_mcptox(seed: int = 42) -> List[Dict[str, Any]]:
    from src.attacks.attack_generator import AttackGenerator
    rng = random.Random(seed)
    gen = AttackGenerator(seed=seed)
    scenarios = []

    cat_method_map = {
        "tool_description_poisoning": "generate_scenario",
        "parameter_injection": "generate_scenario",
        "response_manipulation": "generate_scenario",
        "capability_escalation": "generate_scenario",
    }

    for cat_name, count in MCPTOX_DISTRIBUTION.items():
        for i in range(count):
            sc = gen.generate_scenario(cat_name, scenario_id=f"mcptox_{cat_name}_{i:04d}")
            sc["benchmark"] = "MCPTox"
            sc["temporality"] = "T1"
            sc["source"] = "synthetic"
            sc["original_id"] = f"MCPTox-{cat_name[:3].upper()}-{i:03d}"
            sc["server_type"] = rng.choice(["filesystem", "database", "web_search", "email"])
            sc["attack_vector"] = cat_name
            sc["severity"] = rng.choice(["low", "medium", "high", "critical"])
            scenarios.append(sc)

    rng.shuffle(scenarios)
    print(f"Generated synthetic MCPTox: {len(scenarios)} scenarios")
    return scenarios


def download_mcptox_instructions() -> str:
    return """
To obtain the official MCPTox dataset:

1. Visit: https://github.com/CloudSecurityAlliance/MCPTox
   or refer to: Wang et al., "MCPTox: A Benchmark for Tool Poisoning
   on Real-World MCP Servers", AAAI-26, doi:10.1609/aaai.v40i42.40895

2. Download the dataset and place it at: data/mcptox/mcptox_official.json

3. Expected format:
   {
     "scenarios": [
       {
         "scenario_id": "...",
         "category": "tool_description_poisoning|...",
         "temporality": "T1",
         "target_server": "...",
         "attack_vector": "...",
         "poisoned_content": "...",
         "legitimate_content": "...",
         "target_action": "..."
       },
       ...
     ]
   }

If the official dataset is not available, the synthetic version will be used automatically.
"""
