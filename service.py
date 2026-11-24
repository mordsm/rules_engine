from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from wsgiref.simple_server import make_server

from api import evaluate_family_decision
from compass_rules import (
    RuleEvaluationError,
    evaluate_structured_event,
    get_rule_version_history,
    get_rules_catalog,
    rollback_rule_version,
    update_rule_in_catalog,
)
from rule_engine_agent import FamilyDecisionManager


def app(config_path: Optional[str | Path] = None) -> Callable[[Dict[str, Any], Any], Any]:
    config_path = Path(config_path) if config_path else None

    def handler(environ: Dict[str, Any], start_response: Callable[[str, list[tuple[str, str]]], None]) -> list[bytes]:
        if environ.get("REQUEST_METHOD") == "POST" and environ.get("PATH_INFO") in {"/evaluate", "/api/rules/evaluate", "/api/rules/simulate"}:
            try:
                length = int(environ.get("CONTENT_LENGTH", "0"))
                body = environ["wsgi.input"].read(length).decode("utf-8")
                payload = json.loads(body or "{}")
            except Exception:
                start_response("400 Bad Request", [("Content-Type", "application/json")])
                return [json.dumps({"error": "invalid-json"}).encode("utf-8")]

            context = payload.get("context", {})
            event = payload.get("event")
            if event is None and isinstance(context, dict) and {"event_id", "event_type", "source", "user_id", "payload"}.issubset(context):
                event = context
            if isinstance(event, dict):
                try:
                    result_model = evaluate_structured_event(
                        event,
                        dry_run=bool(payload.get("dry_run", event.get("metadata", {}).get("dry_run", False))),
                        rule_overrides=payload.get("rule_overrides"),
                    )
                except RuleEvaluationError as exc:
                    start_response("422 Unprocessable Entity", [("Content-Type", "application/json")])
                    return [json.dumps({"error": "validation-error", "warnings": exc.warnings}).encode("utf-8")]
                start_response("200 OK", [("Content-Type", "application/json")])
                return [result_model.model_dump_json().encode("utf-8")]

            manager = FamilyDecisionManager(config_path=config_path)
            result = manager.decide(context, actor=payload.get("actor"))
            if result.get("requires_review"):
                manager.record_decision(context, actor=payload.get("actor"))
            start_response("200 OK", [("Content-Type", "application/json")])
            return [json.dumps(result).encode("utf-8")]

        if environ.get("REQUEST_METHOD") == "POST" and environ.get("PATH_INFO") == "/review/approve":
            try:
                length = int(environ.get("CONTENT_LENGTH", "0"))
                body = environ["wsgi.input"].read(length).decode("utf-8")
                payload = json.loads(body or "{}")
            except Exception:
                start_response("400 Bad Request", [("Content-Type", "application/json")])
                return [json.dumps({"error": "invalid-json"}).encode("utf-8")]

            manager = FamilyDecisionManager(config_path=config_path)
            review = manager.approve_review(
                payload.get("review_id", ""),
                reviewer=payload.get("reviewer"),
                notes=payload.get("notes"),
            )
            if review is None:
                start_response("404 Not Found", [("Content-Type", "application/json")])
                return [json.dumps({"error": "review-not-found"}).encode("utf-8")]
            start_response("200 OK", [("Content-Type", "application/json")])
            return [json.dumps(review).encode("utf-8")]

        if environ.get("REQUEST_METHOD") == "POST" and environ.get("PATH_INFO") == "/review/reject":
            try:
                length = int(environ.get("CONTENT_LENGTH", "0"))
                body = environ["wsgi.input"].read(length).decode("utf-8")
                payload = json.loads(body or "{}")
            except Exception:
                start_response("400 Bad Request", [("Content-Type", "application/json")])
                return [json.dumps({"error": "invalid-json"}).encode("utf-8")]

            manager = FamilyDecisionManager(config_path=config_path)
            review = manager.reject_review(
                payload.get("review_id", ""),
                reviewer=payload.get("reviewer"),
                notes=payload.get("notes"),
            )
            if review is None:
                start_response("404 Not Found", [("Content-Type", "application/json")])
                return [json.dumps({"error": "review-not-found"}).encode("utf-8")]
            start_response("200 OK", [("Content-Type", "application/json")])
            return [json.dumps(review).encode("utf-8")]

        if environ.get("REQUEST_METHOD") == "GET" and environ.get("PATH_INFO") == "/review/pending":
            manager = FamilyDecisionManager(config_path=config_path)
            pending = [item for item in manager.review_queue if item.get("status") == "pending"]
            start_response("200 OK", [("Content-Type", "application/json")])
            return [json.dumps(pending).encode("utf-8")]

        if environ.get("REQUEST_METHOD") == "POST" and environ.get("PATH_INFO") == "/config":
            try:
                length = int(environ.get("CONTENT_LENGTH", "0"))
                body = environ["wsgi.input"].read(length).decode("utf-8")
                payload = json.loads(body or "{}")
            except Exception:
                start_response("400 Bad Request", [("Content-Type", "application/json")])
                return [json.dumps({"error": "invalid-json"}).encode("utf-8")]

            manager = FamilyDecisionManager(config_path=config_path)
            partial_config = payload.get("partial_config", {})
            if "rules" in payload:
                manager.config["rules"] = payload["rules"]
                manager.config.update({k: v for k, v in partial_config.items() if k != "rules"})
            else:
                manager.config.update(partial_config)
            if "rules" in payload or "partial_config" in payload:
                if "weights" in partial_config and isinstance(partial_config["weights"], dict):
                    manager.config["weights"] = {**manager.config.get("weights", {}), **partial_config["weights"]}
                if "thresholds" in partial_config and isinstance(partial_config["thresholds"], dict):
                    manager.config["thresholds"] = {**manager.config.get("thresholds", {}), **partial_config["thresholds"]}
                manager.update_config({}, persist=False)
                if config_path is not None:
                    config_path.parent.mkdir(parents=True, exist_ok=True)
                    with config_path.open("w", encoding="utf-8") as handle:
                        import yaml
                        yaml.safe_dump(manager.config, handle, sort_keys=False)
            updated = manager.config
            start_response("200 OK", [("Content-Type", "application/json")])
            return [json.dumps(updated).encode("utf-8")]

        start_response("404 Not Found", [("Content-Type", "application/json")])
        return [json.dumps({"error": "not-found"}).encode("utf-8")]

    return handler


def run_server(host: str = "127.0.0.1", port: int = 8000, config_path: Optional[str | Path] = None) -> None:
    server = make_server(host, port, app(config_path=config_path))
    print(f"Serving rules engine on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
