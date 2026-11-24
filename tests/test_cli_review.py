import json
import tempfile
import unittest
from pathlib import Path
from subprocess import PIPE, Popen

from rule_engine_agent import FamilyDecisionManager


class CliReviewTests(unittest.TestCase):
    def test_cli_pending_review_and_approve(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "family_config.yaml"
            config_path.write_text(
                """
decision_mode: majority
review_required: true
rules: []
""".strip(),
                encoding="utf-8",
            )

            python = "python"
            cmd = [python, "-u", "cli.py", "--config", str(config_path), "--context", '{"category": "schedule", "value": "tired"}', "--actor", "parent"]
            process = Popen(cmd, cwd="c:\\workspace\\rules_engine", stdout=PIPE, stderr=PIPE, text=True)
            stdout, stderr = process.communicate(timeout=10)
            self.assertIn('"requires_review": true', stdout)

            manager = FamilyDecisionManager(config_path=str(config_path))
            pending = [item for item in manager.review_queue if item.get("status") == "pending"]
            self.assertEqual(len(pending), 1)
            review_id = pending[0]["review_id"]

            cmd = [python, "-u", "cli.py", "--config", str(config_path), "--approve", review_id, "--reviewer", "manager", "--notes", "ok"]
            process = Popen(cmd, cwd="c:\\workspace\\rules_engine", stdout=PIPE, stderr=PIPE, text=True)
            stdout, stderr = process.communicate(timeout=10)
            self.assertIn('"status": "approved"', stdout)


if __name__ == "__main__":
    unittest.main()
