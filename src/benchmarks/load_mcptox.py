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

MCPTOX_DERIVED_OFFICIAL_FILENAME = "mcptox_official_derived_table1_200.json"
MCPTOX_CURATED_OFFICIAL_FILENAME = "mcptox_official_derived_table1_200_curated.json"
MCPTOX_LEGACY_OFFICIAL_FILENAME = "mcptox_official.json"


def load_mcptox(
    data_dir: str = "data/mcptox",
    use_official: bool = True,
    seed: int = 42,
    official_variant: str = "derived",
) -> List[Dict[str, Any]]:
    if use_official:
        filenames = {
            "derived": MCPTOX_DERIVED_OFFICIAL_FILENAME,
            "curated": MCPTOX_CURATED_OFFICIAL_FILENAME,
            "legacy": MCPTOX_LEGACY_OFFICIAL_FILENAME,
        }
        if official_variant not in filenames:
            raise ValueError(
                f"official_variant must be one of {sorted(filenames)}, got {official_variant!r}"
            )
        filename = filenames[official_variant]
        official_path = os.path.join(data_dir, filename)
        if not os.path.exists(official_path):
            raise FileNotFoundError(
                f"Requested MCPTox {official_variant} dataset not found: {official_path}"
            )
        with open(official_path, encoding="utf-8") as f:
            data = json.load(f)
        if official_variant in {"derived", "curated"}:
            if data.get("schema_revision") != 2:
                raise ValueError(
                    "The MCPTox-derived dataset is not schema revision 2. "
                    "Regenerate it with: python -m "
                    "src.benchmarks.adapt_mcptox_benchmark "
                    "--variant derived_table1 --count 200 --seed 42"
                )
            from src.benchmarks.validate_mcptox_derived import validate_dataset

            validate_dataset(data)
        if official_variant == "curated":
            from src.benchmarks.curate_mcptox_derived import validate_curated_dataset

            validate_curated_dataset(data)
        variant = data.get("variant", "legacy_adapted")
        print(
            f"Loaded official MCPTox ({variant}): "
            f"{len(data['scenarios'])} scenarios from {official_path}"
        )
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

2. Download the dataset and place it under third/MCPTox-Benchmark-main/

3. Generate the project-compatible derived Table 1 set:

   python -m src.benchmarks.adapt_mcptox_benchmark --variant derived_table1

   This writes: data/mcptox/mcptox_official_derived_table1_200.json

   The legacy flattened adapter remains available with:

   python -m src.benchmarks.adapt_mcptox_benchmark --variant legacy

4. Expected format:
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
