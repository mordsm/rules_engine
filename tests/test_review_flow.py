import tempfile
import unittest
from pathlib import Path

from rule_engine_agent import FamilyDecisionManager


class ReviewFlowTests(unittest.TestCase):
    def test_requires_review_when_configured(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "family_config.yaml"
            config_path.write_text(
                """
decision_mode: majority
default_decision: defer
review_required: true
rules: []
""".strip(),
                encoding="utf-8",
            )

            manager = FamilyDecisionManager(config_path=str(config_path))
            result = manager.decide({"category": "schedule", "value": "tired"}, actor="parent")

            self.assertEqual(result["decision"], "defer")
            self.assertTrue(result.get("requires_review", False))


if __name__ == "__main__":
    unittest.main()
