import sys
import tempfile
import unittest
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rule_engine_agent import FamilyDecisionManager
from api import evaluate_family_decision


class FamilyDecisionManagerTest(unittest.TestCase):
    def test_family_decision_manager_uses_rules_and_external_updates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "family_config.yaml"
            config_path.write_text(
                dedent(
                    """
                    decision_mode: majority
                    weights:
                      parents: 2
                      children: 1
                    thresholds:
                      approve: 2
                      reject: -2
                    default_decision: defer
                    rules:
                      - id: screen_time_limit
                        description: limit screens when tired
                        condition:
                          category: schedule
                          value: tired
                        action: reduce
                        priority: 2
                    """
                ).strip(),
                encoding="utf-8",
            )

            manager = FamilyDecisionManager(config_path=str(config_path))
            decision = manager.decide({"category": "schedule", "value": "tired"}, actor="parent")

            self.assertEqual(decision["decision"], "reduce")
            self.assertEqual(decision["matched_rules"], ["screen_time_limit"])

            updated = manager.update_config({"decision_mode": "consensus"}, persist=False)
            self.assertEqual(updated["decision_mode"], "consensus")

            manager.update_config({"decision_mode": "consensus"}, persist=True)
            reloaded = FamilyDecisionManager(config_path=str(config_path))
            self.assertEqual(reloaded.config["decision_mode"], "consensus")

    def test_ollama_enabled_model_can_override_decision(self):
        manager = FamilyDecisionManager(
            config={
                "decision_mode": "majority",
                "rules": [],
                "llm": {"enabled": True, "provider": "ollama", "model": "llama3.2", "base_url": "http://localhost:11434"},
            }
        )

        def fake_ask(_context, _matched_rules):
            return {"decision": "talk", "reason": "use llm", "confidence": 0.9}

        manager._ask_ollama = fake_ask
        result = manager.decide({"category": "schedule", "value": "tired"}, actor="parent")

        self.assertEqual(result["decision"], "talk")
        self.assertTrue(result["llm"]["used"])

    def test_api_entrypoint_evaluates_family_decision(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "family_config.yaml"
            config_path.write_text(
                dedent(
                    """
                    decision_mode: majority
                    default_decision: defer
                    rules:
                      - id: screen_time_limit
                        description: limit screens when tired
                        condition:
                          category: schedule
                          value: tired
                        action: reduce
                        priority: 2
                    """
                ).strip(),
                encoding="utf-8",
            )

            result = evaluate_family_decision(
                {"category": "schedule", "value": "tired"},
                config_path=str(config_path),
                actor="parent",
            )

            self.assertEqual(result["decision"], "reduce")
            self.assertEqual(result["matched_rules"], ["screen_time_limit"])


if __name__ == "__main__":
    unittest.main()
