from __future__ import annotations

from datetime import datetime, timezone
import unittest

from compass_rules import RuleEvaluationError, evaluate_structured_event


def assessment_event(**payload_overrides):
    payload = {
        "domain": "fitness",
        "finding_type": "aerobic_fitness_gap",
        "severity": "medium",
        "confidence": 0.87,
        "current_state": "low",
        "evidence": ["low endurance score"],
        "recommended_capability": "fitness_planning",
    }
    payload.update(payload_overrides)
    return {
        "event_id": "evt_assessment_104",
        "event_type": "assessment_finding_created",
        "event_version": "1.0",
        "source": "personal_Assessment",
        "user_id": "moshe",
        "occurred_at": datetime(2026, 8, 6, 10, 0, tzinfo=timezone.utc).isoformat(),
        "payload": payload,
        "metadata": {"dry_run": True},
        "idempotency_key": "evt_assessment_104",
    }


def finance_event(**payload_overrides):
    payload = {
        "source_system": "mail_manager",
        "received_at": datetime(2026, 9, 28, 9, 0, tzinfo=timezone.utc).isoformat(),
        "document_ref": "doc_fin_001",
        "document_kind_hint": "invoice",
        "vendor_name": "Acme Supplies",
        "amount": 1200.0,
        "currency": "USD",
        "due_date": "2026-10-15",
        "confidence_hint": 0.94,
    }
    payload.update(payload_overrides)
    return {
        "event_id": "evt_finance_001",
        "event_type": "finance_document.classify",
        "event_version": "1.0",
        "source": "sharons",
        "user_id": "sharon",
        "occurred_at": datetime(2026, 9, 28, 9, 1, tzinfo=timezone.utc).isoformat(),
        "payload": payload,
        "metadata": {"dry_run": True, "trace_id": "trace_finance_001"},
        "idempotency_key": "evt_finance_001",
    }


def inbound_email_event(**payload_overrides):
    payload = {
        "source_mailbox": "inbox",
        "message_id": "msg_001",
        "received_at": datetime(2026, 9, 28, 10, 0, tzinfo=timezone.utc).isoformat(),
        "from_address": "partner@example.com",
        "to_addresses": ["sharon@example.com"],
        "subject": "Please send board update by Tuesday",
        "body_excerpt_redacted": "Can you send the redacted board update by Tuesday?",
        "attachments": [],
        "sender_relationship": "trusted",
        "extracted_deadline": "2026-09-29",
        "confidence_hint": 0.92,
    }
    payload.update(payload_overrides)
    return {
        "event_id": "evt_email_001",
        "event_type": "inbound_email.route",
        "event_version": "1.0",
        "source": "mail_manager",
        "user_id": "sharon",
        "occurred_at": datetime(2026, 9, 28, 10, 1, tzinfo=timezone.utc).isoformat(),
        "payload": payload,
        "metadata": {"dry_run": True, "trace_id": "trace_email_001"},
        "idempotency_key": "evt_email_001",
    }


class CompassRulesTests(unittest.TestCase):
    def test_valid_aerobic_fitness_finding_requires_approval_and_routes_to_self_manage(self):
        result = evaluate_structured_event(assessment_event())

        self.assertEqual(result.final_decision, "require_approval")
        self.assertEqual(result.risk_level, "medium")
        self.assertIn("AEROBIC_FITNESS_GAP", result.reason_codes)
        self.assertIn("ROUTE_TO_SELF_MANAGE", result.reason_codes)
        self.assertTrue(any(route.component == "self_manage" for route in result.routes))
        self.assertTrue(any(action.component == "self_manage" for action in result.approval_required_actions))

    def test_valid_mental_skill_finding_requires_approval_and_routes_to_self_manage(self):
        result = evaluate_structured_event(
            assessment_event(
                domain="mental",
                finding_type="self_regulation_gap",
                current_state="strained",
                recommended_capability="mental_training",
            )
        )

        self.assertEqual(result.final_decision, "require_approval")
        self.assertEqual(result.risk_level, "medium")
        self.assertIn("MENTAL_SKILL_GAP", result.reason_codes)
        self.assertIn("ROUTE_TO_SELF_MANAGE", result.reason_codes)
        self.assertTrue(any(route.component == "self_manage" and route.capability == "mental_training" for route in result.routes))
        self.assertTrue(any(action.component == "self_manage" for action in result.approval_required_actions))

    def test_low_confidence_finding_requires_review_without_route(self):
        result = evaluate_structured_event(assessment_event(confidence=0.62))

        self.assertEqual(result.final_decision, "require_approval")
        self.assertIn("LOW_CONFIDENCE_HEALTH_DATA", result.reason_codes)
        self.assertFalse(result.routes)

    def test_high_severity_finding_raises_risk(self):
        result = evaluate_structured_event(assessment_event(severity="high"))

        self.assertEqual(result.risk_level, "high")
        self.assertIn("HIGH_SEVERITY_HEALTH_FINDING", result.reason_codes)

    def test_low_current_fitness_blocks_high_intensity_action(self):
        result = evaluate_structured_event(assessment_event(current_state="low"))

        self.assertTrue(
            any(
                action.action_type == "create_high_intensity_plan"
                and action.reason_code == "LOW_CURRENT_AEROBIC_FITNESS"
                for action in result.blocked_actions
            )
        )

    def test_dry_run_is_reflected_in_result(self):
        result = evaluate_structured_event(assessment_event(), dry_run=True)

        self.assertTrue(result.dry_run)
        self.assertTrue(result.evaluation_id.startswith("eval_"))

    def test_invalid_payload_returns_validation_error(self):
        event = assessment_event(confidence=1.2)

        with self.assertRaises(RuleEvaluationError):
            evaluate_structured_event(event)

    def test_payable_invoice_requires_approval_and_finance_route(self):
        result = evaluate_structured_event(finance_event())

        self.assertEqual(result.final_decision, "require_approval")
        self.assertEqual(result.risk_level, "medium")
        self.assertIn("PAYABLE_INVOICE_REQUIRES_APPROVAL", result.reason_codes)
        self.assertTrue(any(route.component == "sharons_finance" for route in result.routes))
        self.assertTrue(any(action.action_type == "create_approval_request" for action in result.approval_required_actions))

    def test_paid_receipt_allows_internal_file_proposal(self):
        result = evaluate_structured_event(
            finance_event(
                document_kind_hint="receipt",
                paid_at="2026-09-27",
                payment_method="card",
                due_date=None,
            )
        )

        self.assertEqual(result.final_decision, "allow_read_only")
        self.assertIn("PAID_RECEIPT_SAFE_TO_FILE", result.reason_codes)
        self.assertTrue(any(action.action_type == "create_file_link_proposal" for action in result.allowed_actions))

    def test_finance_missing_document_reference_blocks(self):
        result = evaluate_structured_event(finance_event(document_ref=None))

        self.assertEqual(result.final_decision, "block")
        self.assertIn("INSUFFICIENT_FINANCE_DOCUMENT_DATA", result.reason_codes)
        self.assertTrue(any(action.reason_code == "INSUFFICIENT_FINANCE_DOCUMENT_DATA" for action in result.blocked_actions))
        self.assertFalse(result.approval_required_actions)

    def test_low_confidence_finance_document_routes_to_review(self):
        result = evaluate_structured_event(finance_event(document_kind_hint="subscription", confidence_hint=0.4))

        self.assertEqual(result.final_decision, "require_approval")
        self.assertIn("LOW_CONFIDENCE_FINANCE_DOCUMENT", result.reason_codes)
        self.assertTrue(any(route.component == "human_review" for route in result.routes))

    def test_trusted_email_with_deadline_proposes_task(self):
        result = evaluate_structured_event(inbound_email_event())

        self.assertEqual(result.final_decision, "allow_read_only")
        self.assertIn("TRUSTED_EMAIL_DEADLINE_TASK_PROPOSAL", result.reason_codes)
        self.assertTrue(any(action.action_type == "create_task_proposal" for action in result.allowed_actions))

    def test_email_attachment_without_action_proposes_file_link(self):
        result = evaluate_structured_event(
            inbound_email_event(
                subject="Receipt attached",
                body_excerpt_redacted="FYI",
                attachments=["receipt.pdf"],
                extracted_deadline=None,
            )
        )

        self.assertEqual(result.final_decision, "allow_read_only")
        self.assertIn("EMAIL_ATTACHMENT_FILE_PROPOSAL", result.reason_codes)
        self.assertTrue(any(action.action_type == "create_file_link_proposal" for action in result.allowed_actions))

    def test_sensitive_email_requires_owner_review(self):
        result = evaluate_structured_event(inbound_email_event(sensitivity_hint="legal"))

        self.assertEqual(result.final_decision, "require_approval")
        self.assertEqual(result.risk_level, "high")
        self.assertIn("SENSITIVE_EMAIL_REQUIRES_HUMAN_REVIEW", result.reason_codes)
        self.assertTrue(any(route.component == "owner_review" for route in result.routes))

    def test_email_without_usable_content_blocks(self):
        result = evaluate_structured_event(inbound_email_event(subject=None, body_excerpt_redacted=None))

        self.assertEqual(result.final_decision, "block")
        self.assertIn("INSUFFICIENT_EMAIL_ROUTING_DATA", result.reason_codes)
        self.assertTrue(any(action.reason_code == "INSUFFICIENT_EMAIL_ROUTING_DATA" for action in result.blocked_actions))


if __name__ == "__main__":
    unittest.main()
