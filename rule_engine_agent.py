from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import error, request

import yaml


class FamilyDecisionManager:
    """A reusable rule engine agent for family-style decision making.

    The manager can be configured from a YAML file, updated externally, and used by
    other agents in different projects through a small importable API.
    """

    def __init__(self, config_path: Optional[str | Path] = None, config: Optional[Dict[str, Any]] = None):
        self.config_path = Path(config_path) if config_path else None
        self.config = self._load_config(config)
        self.history_path = self.config_path.with_name("decision_history.json") if self.config_path is not None else None
        self.history = self._load_history()
        self.review_queue_path = self.config_path.with_name("review_queue.json") if self.config_path is not None else None
        self.review_queue = self._load_review_queue()

    def _load_config(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if config is not None:
            return self._normalize_config(config)

        if self.config_path is None:
            return self._default_config()

        if not self.config_path.exists():
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(yaml.safe_dump(self._default_config(), sort_keys=False), encoding="utf-8")

        with self.config_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}

        return self._normalize_config(raw)

    def _default_config(self) -> Dict[str, Any]:
        return {
            "decision_mode": "majority",
            "weights": {"parents": 2, "children": 1},
            "thresholds": {"approve": 2, "reject": -2},
            "default_decision": "defer",
            "review_required": False,
            "rules": [],
            "llm": {
                "provider": "ollama",
                "enabled": False,
                "model": os.getenv("OLLAMA_MODEL", "llama3.2"),
                "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
                "timeout_seconds": 30,
                "fallback_to_llm": True,
            },
        }

    def _normalize_config(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        config = self._default_config()
        if not isinstance(raw, dict):
            return config

        for key, value in raw.items():
            if key == "rules" and isinstance(value, list):
                config["rules"] = value
            elif key in {"decision_mode", "default_decision"} and isinstance(value, str):
                config[key] = value
            elif key == "weights" and isinstance(value, dict):
                config[key] = value
            elif key == "thresholds" and isinstance(value, dict):
                config[key] = value
            elif key == "review_required" and isinstance(value, bool):
                config[key] = value
            elif key in {"llm", "ollama"} and isinstance(value, dict):
                config["llm"] = {**config.get("llm", {}), **self._normalize_llm_config(value)}
        return config

    def _normalize_llm_config(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        defaults = self._default_config()["llm"]
        normalized = {**defaults}
        if not isinstance(raw, dict):
            return normalized
        for key, value in raw.items():
            if key in {"provider", "model", "base_url"} and isinstance(value, str):
                normalized[key] = value
            elif key == "enabled" and isinstance(value, bool):
                normalized[key] = value
            elif key == "timeout_seconds" and isinstance(value, int):
                normalized[key] = value
            elif key == "fallback_to_llm" and isinstance(value, bool):
                normalized[key] = value
        return normalized

    def update_config(self, partial_config: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
        self.config.update(partial_config)
        if "weights" in partial_config and isinstance(partial_config["weights"], dict):
            self.config["weights"] = {**self.config.get("weights", {}), **partial_config["weights"]}
        if "thresholds" in partial_config and isinstance(partial_config["thresholds"], dict):
            self.config["thresholds"] = {**self.config.get("thresholds", {}), **partial_config["thresholds"]}
        if "llm" in partial_config and isinstance(partial_config["llm"], dict):
            self.config["llm"] = {**self.config.get("llm", {}), **self._normalize_llm_config(partial_config["llm"])}
        if persist and self.config_path is not None:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with self.config_path.open("w", encoding="utf-8") as handle:
                yaml.safe_dump(self.config, handle, sort_keys=False)
        return self.config

    def decide(self, context: Dict[str, Any], actor: Optional[str] = None) -> Dict[str, Any]:
        matched_rules = [rule for rule in self.config.get("rules", []) if self._rule_matches(rule, context)]
        result: Dict[str, Any]

        if matched_rules:
            chosen_rule = self._select_rule(matched_rules, context)
            result = {
                "decision": chosen_rule.get("action") or chosen_rule.get("decision") or self.config.get("default_decision", "defer"),
                "matched_rules": [chosen_rule.get("id") or chosen_rule.get("description") or "rule"],
                "actor": actor,
                "context": context,
                "config": self.config,
            }
        else:
            result = {
                "decision": self.config.get("default_decision", "defer"),
                "matched_rules": [],
                "actor": actor,
                "context": context,
                "config": self.config,
            }

        if self.config.get("review_required", False):
            result["requires_review"] = True

        llm_config = self._llm_config()
        if llm_config.get("enabled") and (not matched_rules or llm_config.get("fallback_to_llm", True)):
            llm_result = self._ask_ollama(context, matched_rules)
            if llm_result is not None:
                result["llm"] = {
                    "used": True,
                    "provider": llm_config.get("provider", "ollama"),
                    "model": llm_config.get("model"),
                    "reason": llm_result.get("reason"),
                }
                if llm_result.get("decision"):
                    result["decision"] = llm_result["decision"]
        return result

    def _select_rule(self, matched_rules: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
        if not matched_rules:
            return {}

        return sorted(
            matched_rules,
            key=lambda rule: (-(int(rule.get("priority", rule.get("priority_num", 0)))), rule.get("id") or rule.get("rule_id") or rule.get("description") or ""),
        )[0]

    def _rule_matches(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        if isinstance(rule.get("condition"), dict):
            return self._match_simple_condition(rule["condition"], context)
        if isinstance(rule.get("conditions"), dict):
            return self._match_complex_condition(rule["conditions"], context)
        return False

    def _match_simple_condition(self, condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
        for field_name, expected_value in condition.items():
            if context.get(field_name) != expected_value:
                return False
        return True

    def _match_complex_condition(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        operator = str(conditions.get("operator", "AND")).upper()
        criteria = conditions.get("criteria", [])
        if not isinstance(criteria, list):
            return False
        if operator == "OR":
            return any(self._match_criterion(criterion, context) for criterion in criteria)
        return all(self._match_criterion(criterion, context) for criterion in criteria)

    def _match_criterion(self, criterion: Dict[str, Any], context: Dict[str, Any]) -> bool:
        field = criterion.get("field")
        operator = str(criterion.get("operator", "EQUALS")).upper()
        expected_value = criterion.get("value")
        actual_value = context.get(field) if field is not None else None

        if operator == "EQUALS":
            return actual_value == expected_value
        if operator == "IN":
            if isinstance(expected_value, list):
                return actual_value in expected_value
            return actual_value == expected_value
        if operator == "GREATER_THAN":
            return actual_value is not None and actual_value > expected_value
        if operator == "LESS_THAN":
            return actual_value is not None and actual_value < expected_value
        if operator == "CONTAINS_ANY":
            if not isinstance(actual_value, str):
                return False
            if isinstance(expected_value, list):
                needle_values = [str(item).lower() for item in expected_value]
                return any(item.lower() in actual_value.lower() for item in needle_values)
            return str(expected_value).lower() in actual_value.lower()
        return False

    def _llm_config(self) -> Dict[str, Any]:
        llm_config = self.config.get("llm", {})
        if isinstance(llm_config, dict):
            return self._normalize_llm_config(llm_config)
        return self._default_config()["llm"]

    def _ask_ollama(self, context: Dict[str, Any], matched_rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        llm_config = self._llm_config()
        if not llm_config.get("enabled") or llm_config.get("provider", "ollama") != "ollama":
            return None

        base_url = str(llm_config.get("base_url", "http://localhost:11434")).rstrip("/")
        model = str(llm_config.get("model", "llama3.2"))
        timeout_seconds = int(llm_config.get("timeout_seconds", 30))
        prompt = (
            "You are a family decision assistant. "
            f"Context: {json.dumps(context, ensure_ascii=False)}\n"
            f"Matched rules: {json.dumps([rule.get('rule_id') or rule.get('id') or rule.get('description') or 'rule' for rule in matched_rules], ensure_ascii=False)}\n"
            "Return valid JSON with keys: decision, reason, confidence."
        )
        payload = {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0}}
        url = f"{base_url}/api/generate"
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with request.urlopen(req, timeout=timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except (error.URLError, error.HTTPError, TimeoutError, OSError):
            return None

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return None

        response_text = parsed.get("response", "")
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            return {"decision": None, "reason": response_text, "confidence": 0.0}

    def _load_history(self) -> List[Dict[str, Any]]:
        if self.history_path is None or not self.history_path.exists():
            return []
        try:
            with self.history_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, list):
                    return data
        except (json.JSONDecodeError, OSError):
            return []
        return []

    def _load_review_queue(self) -> List[Dict[str, Any]]:
        if self.review_queue_path is None or not self.review_queue_path.exists():
            return []
        try:
            with self.review_queue_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, list):
                    return data
        except (json.JSONDecodeError, OSError):
            return []
        return []

    def _persist_review_queue(self) -> None:
        if self.review_queue_path is None:
            return
        self.review_queue_path.parent.mkdir(parents=True, exist_ok=True)
        with self.review_queue_path.open("w", encoding="utf-8") as handle:
            json.dump(self.review_queue, handle, ensure_ascii=False, indent=2)

    def record_decision(self, context: Dict[str, Any], actor: Optional[str] = None) -> Dict[str, Any]:
        result = self.decide(context, actor=actor)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "actor": actor,
            "context": context,
            "decision": result.get("decision"),
            "matched_rules": result.get("matched_rules", []),
            "requires_review": result.get("requires_review", False),
        }
        self.history.append(entry)
        if self.history_path is not None:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            with self.history_path.open("w", encoding="utf-8") as handle:
                json.dump(self.history, handle, ensure_ascii=False, indent=2)
        if result.get("requires_review"):
            self.review_queue.append({
                "review_id": str(uuid.uuid4()),
                "timestamp": entry["timestamp"],
                "context": context,
                "actor": actor,
                "decision": result.get("decision"),
                "matched_rules": entry["matched_rules"],
                "status": "pending",
                "review_notes": None,
            })
            self._persist_review_queue()
        return entry

    def approve_review(self, review_id: str, reviewer: Optional[str] = None, notes: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self._resolve_review(review_id, "approved", reviewer, notes)

    def reject_review(self, review_id: str, reviewer: Optional[str] = None, notes: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self._resolve_review(review_id, "rejected", reviewer, notes)

    def _resolve_review(self, review_id: str, status: str, reviewer: Optional[str], notes: Optional[str]) -> Optional[Dict[str, Any]]:
        for item in self.review_queue:
            if item.get("review_id") == review_id and item.get("status") == "pending":
                item["status"] = status
                item["reviewer"] = reviewer
                item["review_notes"] = notes
                item["reviewed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                self._persist_review_queue()
                return item
        return None

    def export_config(self) -> str:
        return json.dumps(self.config, ensure_ascii=False, indent=2)


__all__ = ["FamilyDecisionManager"]
