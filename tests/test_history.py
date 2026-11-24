import json
import tempfile
import unittest
from pathlib import Path

from rule_engine_agent import FamilyDecisionManager


class HistoryTests(unittest.TestCase):
    def test_decision_history_is_persisted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "family_config.yaml"
            config_path.write_text(
                """
decision_mode: majority
default_decision: defer
rules: []
""".strip(),
                encoding="utf-8",
            )

            manager = FamilyDecisionManager(config_path=str(config_path))
            manager.decide({"category": "schedule", "value": "tired"}, actor="parent")
            history = manager.record_decision({"category": "schedule", "value": "tired"}, actor="parent")

            self.assertEqual(history["actor"], "parent")
            self.assertEqual(history["decision"], "defer")

            saved = json.loads((Path(tmpdir) / "decision_history.json").read_text(encoding="utf-8"))
            self.assertEqual(saved[-1]["actor"], "parent")


if __name__ == "__main__":
    unittest.main()
