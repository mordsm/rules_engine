from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

from api import evaluate_family_decision
from rule_engine_agent import FamilyDecisionManager


def parse_context_argument(value: str) -> dict:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            raise ValueError("context must be valid JSON")


def main() -> None:
    parser = argparse.ArgumentParser(description="Rules engine CLI")
    parser.add_argument("--config", default="family_config.yaml", help="Path to YAML config")
    parser.add_argument("--context", help="JSON context payload")
    parser.add_argument("--actor", default="cli", help="Optional actor name")
    parser.add_argument("--update", help="JSON partial config payload to persist")
    parser.add_argument("--approve", help="Approve a pending review by review_id")
    parser.add_argument("--reject", help="Reject a pending review by review_id")
    parser.add_argument("--reviewer", help="Name of the reviewer")
    parser.add_argument("--notes", help="Optional review notes")
    parser.add_argument("--pending-reviews", action="store_true", help="Show pending reviews")
    args = parser.parse_args()

    config_path = Path(args.config)
    manager = FamilyDecisionManager(config_path=config_path)

    if args.update:
        payload = parse_context_argument(args.update)
        manager.update_config(payload, persist=True)
        print(json.dumps(manager.config, ensure_ascii=False, indent=2))
        return

    if args.approve:
        review = manager.approve_review(args.approve, reviewer=args.reviewer, notes=args.notes)
        if review is None:
            raise SystemExit("Review not found or already resolved")
        print(json.dumps(review, ensure_ascii=False, indent=2))
        return

    if args.reject:
        review = manager.reject_review(args.reject, reviewer=args.reviewer, notes=args.notes)
        if review is None:
            raise SystemExit("Review not found or already resolved")
        print(json.dumps(review, ensure_ascii=False, indent=2))
        return

    if args.pending_reviews:
        pending = [item for item in manager.review_queue if item.get("status") == "pending"]
        print(json.dumps(pending, ensure_ascii=False, indent=2))
        return

    context = parse_context_argument(args.context or "{}")
    result = manager.decide(context, actor=args.actor)
    if result.get("requires_review"):
        manager.record_decision(context, actor=args.actor)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
