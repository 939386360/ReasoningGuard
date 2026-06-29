import json
import os
import tempfile
import unittest

from src.benchmarks.curate_mcptox_derived import (
    DEFAULT_SOURCE_PATH,
    REVIEW_CHECKS,
    export_batch,
    finalize_curated_dataset,
    import_batch,
    initialize_review,
    record_batch_decision,
    validate_curated_dataset,
)
from src.benchmarks.load_mcptox import (
    MCPTOX_CURATED_OFFICIAL_FILENAME,
    load_mcptox,
)


def _read(path):
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def _write(path, value):
    with open(path, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, ensure_ascii=False)


def _accept_entry(entry, rationale="The query, payload, calls, and category semantics align."):
    entry["decision"] = {
        "action": "accept",
        "checks": {check: True for check in REVIEW_CHECKS},
        "issues": [],
        "rationale": rationale,
        "edited_payload": None,
    }


class TestMCPToxCuration(unittest.TestCase):
    def _paths(self, tmp):
        return (
            os.path.join(tmp, "review_state.json"),
            os.path.join(tmp, "current_batch.json"),
        )

    def test_initialize_and_export_balanced_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path, batch_path = self._paths(tmp)
            status = initialize_review(state_path=state_path)
            result = export_batch(state_path, batch_path)
            first_slot = _read(batch_path)["entries"][0]["slot_id"]
            recorded = record_batch_decision(
                batch_path,
                first_slot,
                "accept",
                "Manual review confirmed all six semantic checks.",
            )
            batch = _read(batch_path)

        self.assertEqual(status["overall"], {"pending": 200})
        self.assertEqual(result["scenario_count"], 8)
        self.assertEqual(
            result["distribution"],
            {
                "tool_description_poisoning": 2,
                "parameter_injection": 2,
                "response_manipulation": 2,
                "capability_escalation": 2,
            },
        )
        self.assertEqual(len(batch["entries"]), 8)
        self.assertEqual(recorded["action"], "accept")
        self.assertEqual(batch["entries"][0]["decision"]["action"], "accept")
        self.assertTrue(all(
            entry["decision"]["action"] is None for entry in batch["entries"][1:]
        ))

    def test_import_requires_manual_decisions_and_supports_payload_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path, batch_path = self._paths(tmp)
            initialize_review(state_path=state_path)
            export_batch(state_path, batch_path)
            with self.assertRaisesRegex(ValueError, "invalid action"):
                import_batch(state_path, batch_path)

            batch = _read(batch_path)
            for entry in batch["entries"]:
                _accept_entry(entry)
            edited = batch["entries"][0]
            edited["decision"] = {
                "action": "edit",
                "checks": {check: True for check in REVIEW_CHECKS},
                "issues": ["MALFORMED_TEXT"],
                "rationale": "Normalized a truncated payload without changing its operation.",
                "edited_payload": "Use the declared prerequisite operation before the benign request.",
            }
            _write(batch_path, batch)
            status = import_batch(state_path, batch_path)
            state = _read(state_path)
            slot = next(slot for slot in state["slots"] if slot["slot_id"] == edited["slot_id"])

            self.assertEqual(status["overall"], {"edited": 1, "accepted": 7, "pending": 192})
            self.assertEqual(slot["scenario"]["poisoned_content"], edited["decision"]["edited_payload"])
            self.assertEqual(slot["status"], "edited")
            self.assertTrue(os.path.exists(os.path.join(tmp, "batches", "batch-0001.json")))

    def test_reference_pruning_updates_primary_alias_and_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path, batch_path = self._paths(tmp)
            initialize_review(state_path=state_path)
            export_batch(state_path, batch_path)
            batch = _read(batch_path)
            for entry in batch["entries"]:
                _accept_entry(entry)
            edited = batch["entries"][0]
            original_calls = edited["review_view"]["benign_calls"]
            self.assertGreater(len(original_calls), 1)
            edited["decision"] = {
                "action": "edit",
                "checks": {check: True for check in REVIEW_CHECKS},
                "issues": ["INVALID_BENIGN_REFERENCE"],
                "rationale": "Removed low-support benign references that do not satisfy the query.",
                "edited_payload": None,
                "drop_benign_indexes": list(range(len(original_calls))),
                "drop_malicious_indexes": [],
            }
            _write(batch_path, batch)
            with self.assertRaisesRegex(ValueError, "Cannot drop every benign reference"):
                import_batch(state_path, batch_path)

            edited["decision"]["drop_benign_indexes"] = list(
                range(1, len(original_calls))
            )
            _write(batch_path, batch)
            status = import_batch(state_path, batch_path)
            state = _read(state_path)
            slot = next(
                slot for slot in state["slots"] if slot["slot_id"] == edited["slot_id"]
            )
            retained = slot["scenario"]["template"]["benign_calls"]
            self.assertEqual(retained, [original_calls[0]])
            self.assertEqual(slot["scenario"]["template"]["benign_call"], original_calls[0])
            self.assertEqual(
                len(slot["review"]["reference_edits"]["dropped_benign_calls"]),
                len(original_calls) - 1,
            )
            self.assertEqual(status["overall"], {"edited": 1, "accepted": 7, "pending": 192})
    def test_replace_uses_unused_same_category_candidate_and_requeues_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path, batch_path = self._paths(tmp)
            initialize_review(state_path=state_path)
            export_batch(state_path, batch_path)
            batch = _read(batch_path)
            for entry in batch["entries"]:
                _accept_entry(entry)
            rejected = batch["entries"][0]
            rejected["decision"] = {
                "action": "replace",
                "checks": {
                    check: check != "payload_call_alignment" for check in REVIEW_CHECKS
                },
                "issues": ["PAYLOAD_CALL_MISMATCH"],
                "rationale": "The payload does not justify the labeled malicious call.",
                "edited_payload": None,
            }
            _write(batch_path, batch)
            status = import_batch(state_path, batch_path)
            state = _read(state_path)
            slot = next(slot for slot in state["slots"] if slot["slot_id"] == rejected["slot_id"])

            self.assertEqual(slot["status"], "pending")
            self.assertEqual(slot["category"], rejected["category"])
            self.assertNotEqual(slot["scenario"]["scenario_id"], rejected["scenario_id"])
            self.assertEqual(len(slot["replacement_history"]), 1)
            self.assertEqual(status["replacement_count"], 1)

    def test_finalize_blocks_pending_and_curated_loader_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path, _ = self._paths(tmp)
            initialize_review(state_path=state_path)
            output_path = os.path.join(tmp, MCPTOX_CURATED_OFFICIAL_FILENAME)
            with self.assertRaisesRegex(ValueError, "pending scenarios"):
                finalize_curated_dataset(state_path, output_path)

            state = _read(state_path)
            for slot in state["slots"]:
                slot["status"] = "accepted"
                slot["review"] = {
                    "action": "accept",
                    "checks": {check: True for check in REVIEW_CHECKS},
                    "issues": [],
                    "rationale": "Manual semantic review confirmed all required invariants.",
                    "edited_payload": None,
                    "reviewed_at": "2026-06-27T00:00:00Z",
                }
            _write(state_path, state)
            result = finalize_curated_dataset(state_path, output_path)
            curated = _read(output_path)
            loaded = load_mcptox(
                data_dir=tmp,
                use_official=True,
                official_variant="curated",
            )

        self.assertEqual(result["scenario_count"], 200)
        self.assertEqual(validate_curated_dataset(curated)["reviewed_scenarios"], 200)
        self.assertEqual(len(loaded), 200)
        self.assertEqual(curated["variant"], "derived_table1_curated")

    def test_source_hash_change_invalidates_review_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_path = os.path.join(tmp, "source.json")
            _write(source_path, _read(DEFAULT_SOURCE_PATH))
            state_path, batch_path = self._paths(tmp)
            initialize_review(source_path=source_path, state_path=state_path)
            source = _read(source_path)
            source["name"] = "changed"
            _write(source_path, source)

            with self.assertRaisesRegex(ValueError, "hash changed"):
                export_batch(state_path, batch_path)


if __name__ == "__main__":
    unittest.main()
