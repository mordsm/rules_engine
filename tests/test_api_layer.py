import json
import tempfile
import unittest
from pathlib import Path
from threading import Thread
from wsgiref.simple_server import make_server

from api import evaluate_family_decision
from rule_engine_agent import FamilyDecisionManager
from service import app


class RulesEngineApiTests(unittest.TestCase):
    def test_evaluate_family_decision_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "family_config.yaml"
            config_path.write_text(
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
""".strip(),
                encoding="utf-8",
            )

            result = evaluate_family_decision(
                {"category": "schedule", "value": "tired"},
                config_path=str(config_path),
                actor="parent",
            )
            self.assertEqual(result["decision"], "reduce")

    def test_http_service_can_evaluate_and_update_rules(self):
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

            server = make_server("127.0.0.1", 0, app(config_path=str(config_path)))
            port = server.server_port
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                import urllib.request

                payload = json.dumps({"context": {"category": "schedule", "value": "tired"}, "actor": "parent"}).encode("utf-8")
                req = urllib.request.Request(f"http://127.0.0.1:{port}/evaluate", data=payload, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=5) as response:
                    body = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(body["decision"], "defer")

                update_payload = json.dumps({"partial_config": {"decision_mode": "consensus"}}).encode("utf-8")
                update_req = urllib.request.Request(f"http://127.0.0.1:{port}/config", data=update_payload, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(update_req, timeout=5) as update_response:
                    update_body = json.loads(update_response.read().decode("utf-8"))
                    self.assertEqual(update_body["decision_mode"], "consensus")

                add_rule_payload = json.dumps({"rules": [{"id": "new_rule", "description": "new test rule", "condition": {"category": "schedule", "value": "tired"}, "action": "pause", "priority": 1}]}).encode("utf-8")
                add_rule_req = urllib.request.Request(f"http://127.0.0.1:{port}/config", data=add_rule_payload, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(add_rule_req, timeout=5) as add_rule_response:
                    add_rule_body = json.loads(add_rule_response.read().decode("utf-8"))
                    self.assertEqual(add_rule_body["rules"][0]["id"], "new_rule")

                reloaded = FamilyDecisionManager(config_path=str(config_path))
                self.assertEqual(reloaded.config["rules"][0]["id"], "new_rule")
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
