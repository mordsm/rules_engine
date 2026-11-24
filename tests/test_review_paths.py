import json
import tempfile
import unittest
from pathlib import Path
from threading import Thread
from wsgiref.simple_server import make_server

from rule_engine_agent import FamilyDecisionManager
from service import app


class ReviewPathsTests(unittest.TestCase):
    def test_review_queue_is_created_when_required(self):
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

            manager = FamilyDecisionManager(config_path=str(config_path))
            result = manager.decide({"category": "schedule", "value": "tired"}, actor="parent")

            self.assertTrue(result.get("requires_review"))
            manager.record_decision({"category": "schedule", "value": "tired"}, actor="parent")
            self.assertEqual(manager.review_queue[0]["status"], "pending")

    def test_http_review_endpoints(self):
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
                    self.assertTrue(body.get("requires_review"))

                pending_req = urllib.request.Request(f"http://127.0.0.1:{port}/review/pending", method="GET")
                with urllib.request.urlopen(pending_req, timeout=5) as response:
                    pending_body = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(len(pending_body), 1)
                    review_id = pending_body[0]["review_id"]

                approve_payload = json.dumps({"review_id": review_id, "reviewer": "manager", "notes": "ok"}).encode("utf-8")
                approve_req = urllib.request.Request(f"http://127.0.0.1:{port}/review/approve", data=approve_payload, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(approve_req, timeout=5) as approve_response:
                    approve_body = json.loads(approve_response.read().decode("utf-8"))
                    self.assertEqual(approve_body["status"], "approved")

            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
