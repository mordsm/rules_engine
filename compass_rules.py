from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, ValidationError, field_validator


Decision = Literal[
    "block",
    "require_approval",
    "allow_with_redaction",
    "allow_read_only",
    "allow",
    "recommendation_only",
]
RiskLevel = Literal["low", "medium", "high", "critical"]
RuleCategory = Literal[
    "hard_policy",
    "privacy_policy",
    "risk",
    "approval",
    "routing",
    "workflow_selection",
    "automation",
    "recommendation",
]
RuleStatus = Literal["proposed", "validated", "approved", "active", "disabled", "rejected", "superseded"]
ConditionOperator = Literal[
    "equals",
    "not_equals",
    "greater_than",
    "greater_than_or_equal",
    "less_than",
    "less_than_or_equal",
    "contains",
    "not_contains",
    "in",
    "not_in",
    "exists",
    "not_exists",
    "starts_with",
    "ends_with",
]
EffectType = Literal[
    "allow",
    "block",
    "require_approval",
    "allow_read_only",
    "allow_with_redaction",
    "set_risk",
    "route_to",
    "require_capability",
    "select_workflow",
    "propose_action",
    "add_reason",
    "redact_field",
    "stop_processing",
]

DECISION_PRECEDENCE: dict[str, int] = {
    "recommendation_only": 0,
    "allow": 1,
    "allow_read_only": 2,
    "allow_with_redaction": 3,
    "require_approval": 4,
    "block": 5,
}
RISK_PRECEDENCE: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class EventMetadata(BaseModel):
    trace_id: str | None = None
    dry_run: bool = False
    requested_actions: list[dict[str, Any]] = Field(default_factory=list)


class AssessmentFindingCreatedPayload(BaseModel):
    domain: str
    finding_type: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: float = Field(ge=0.0, le=1.0)
    current_state: str | None = None
    evidence: list[str] = Field(default_factory=list)
    recommended_capability: str | None = None


class FitnessPlanProposedPayload(BaseModel):
    sessions_per_week: int = Field(ge=0)
    session_duration_minutes: int = Field(ge=0)
    intensity: str
    activities: list[str] = Field(default_factory=list)
    related_finding_id: str | None = None


class UnpaidBillDetectedPayload(BaseModel):
    vendor: str
    invoice_id: str
    amount: float = Field(ge=0)
    currency: str = "ILS"
    due_date: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    source_message_id: str


class SpendingAnomalyDetectedPayload(BaseModel):
    amount: float | None = None
    severity: str = "medium"
    category: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class TaskOverduePayload(BaseModel):
    task_id: str
    title: str
    days_overdue: int = Field(ge=0)


class CalendarConflictDetectedPayload(BaseModel):
    event_id: str
    conflicting_event_id: str
    severity: str = "medium"


class ObligationDetectedPayload(BaseModel):
    title: str
    institution: str | None = None
    due_date: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class MailReplyRequiredPayload(BaseModel):
    subject: str
    from_email: str
    source_message_id: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class FinanceDocumentClassifyPayload(BaseModel):
    source_system: str
    received_at: datetime
    document_ref: str | None = None
    document_kind_hint: str | None = None
    vendor_name: str | None = None
    amount: float | None = Field(default=None, ge=0)
    currency: str = "USD"
    due_date: str | None = None
    paid_at: str | None = None
    payment_method: str | None = None
    account_hint: str | None = None
    project_or_household_context: str | None = None
    requester: str | None = None
    confidence_hint: float = Field(default=1.0, ge=0.0, le=1.0)


class InboundEmailRoutePayload(BaseModel):
    source_mailbox: str
    message_id: str
    received_at: datetime
    from_address: str
    to_addresses: list[str] = Field(default_factory=list)
    cc_addresses: list[str] = Field(default_factory=list)
    subject: str | None = None
    body_excerpt_redacted: str | None = None
    attachments: list[str] = Field(default_factory=list)
    thread_id: str | None = None
    detected_language: str | None = None
    sender_relationship: str | None = None
    sensitivity_hint: str | None = None
    extracted_deadline: str | None = None
    classification_hint: str | None = None
    confidence_hint: float = Field(default=1.0, ge=0.0, le=1.0)


PAYLOAD_MODELS: dict[str, type[BaseModel]] = {
    "assessment_finding_created": AssessmentFindingCreatedPayload,
    "fitness_plan_proposed": FitnessPlanProposedPayload,
    "unpaid_bill_detected": UnpaidBillDetectedPayload,
    "spending_anomaly_detected": SpendingAnomalyDetectedPayload,
    "task_overdue": TaskOverduePayload,
    "calendar_conflict_detected": CalendarConflictDetectedPayload,
    "obligation_detected": ObligationDetectedPayload,
    "mail_reply_required": MailReplyRequiredPayload,
    "finance_document.classify": FinanceDocumentClassifyPayload,
    "inbound_email.route": InboundEmailRoutePayload,
}


class StructuredEvent(BaseModel):
    event_id: str
    event_type: str
    event_version: str = "1.0"
    source: str
    user_id: str
    occurred_at: datetime
    subject_type: str | None = None
    subject_id: str | None = None
    payload: dict[str, Any]
    metadata: EventMetadata = Field(default_factory=EventMetadata)
    idempotency_key: str

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    def typed_payload(self) -> BaseModel:
        model = PAYLOAD_MODELS.get(self.event_type)
        if model is None:
            return BaseModel.model_validate({})
        return model.model_validate(self.payload)


class Condition(BaseModel):
    field: str
    operator: ConditionOperator
    value: Any = None


class Effect(BaseModel):
    effect_type: EffectType
    parameters: dict[str, Any] = Field(default_factory=dict)


class Rule(BaseModel):
    rule_id: str
    name: str
    domain: str
    category: RuleCategory
    priority: int = 0
    version: int = 1
    status: RuleStatus = "active"
    enabled: bool = True
    event_types: list[str] = Field(default_factory=list)
    conditions: list[Condition] = Field(default_factory=list)
    effects: list[Effect] = Field(default_factory=list)
    stop_processing: bool = False

    def executable(self) -> bool:
        return self.status == "active" and self.enabled


class MatchedRule(BaseModel):
    rule_id: str
    name: str
    category: str
    priority: int
    version: int
    effects: list[str] = Field(default_factory=list)


class PlannedAction(BaseModel):
    action_type: str
    title: str | None = None
    component: str | None = None
    purpose: str | None = None
    due_date: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class BlockedAction(BaseModel):
    action_type: str
    reason_code: str
    title: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class RouteDecision(BaseModel):
    component: str
    capability: str | None = None
    purpose: str | None = None


class WorkflowSelection(BaseModel):
    workflow_id: str
    name: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class Redaction(BaseModel):
    field: str
    reason_code: str


class EvaluationResult(BaseModel):
    evaluation_id: str
    event_id: str
    final_decision: Decision
    risk_level: RiskLevel
    matched_rules: list[MatchedRule] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    allowed_actions: list[PlannedAction] = Field(default_factory=list)
    approval_required_actions: list[PlannedAction] = Field(default_factory=list)
    blocked_actions: list[BlockedAction] = Field(default_factory=list)
    routes: list[RouteDecision] = Field(default_factory=list)
    selected_workflow: WorkflowSelection | None = None
    redactions: list[Redaction] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    dry_run: bool = False
    explanation: str = ""

    @property
    def decision(self) -> str:
        return self.final_decision


class RuleEvaluationError(ValueError):
    def __init__(self, warnings: list[str]) -> None:
        super().__init__("; ".join(warnings))
        self.warnings = warnings


def evaluate_structured_event(event_data: dict[str, Any], *, dry_run: bool | None = None) -> EvaluationResult:
    try:
        event = StructuredEvent.model_validate(event_data)
        event.typed_payload()
    except ValidationError as exc:
        raise RuleEvaluationError([f"VALIDATION_ERROR:{err['loc']}:{err['msg']}" for err in exc.errors()]) from exc

    effective_dry_run = event.metadata.dry_run if dry_run is None else dry_run
    rules = initial_rules()
    matched = [rule for rule in rules if rule.executable() and _rule_matches_event(rule, event)]
    matched.sort(key=lambda rule: (-rule.priority, rule.rule_id))

    state = _EvaluationState(
        evaluation_id=f"eval_{uuid4().hex[:12]}",
        event=event,
        final_decision="recommendation_only",
        risk_level="low",
        dry_run=effective_dry_run,
    )

    for rule in matched:
        state.matched_rules.append(
            MatchedRule(
                rule_id=rule.rule_id,
                name=rule.name,
                category=rule.category,
                priority=rule.priority,
                version=rule.version,
                effects=[effect.effect_type for effect in rule.effects],
            )
        )
        for effect in rule.effects:
            _apply_effect(state, effect)
        if rule.stop_processing:
            break

    state.reason_codes = _unique(state.reason_codes)
    explanation = (
        f"{state.final_decision} because {', '.join(state.reason_codes)}"
        if state.reason_codes
        else f"{state.final_decision}; no specific policy reason matched"
    )
    return EvaluationResult(
        evaluation_id=state.evaluation_id,
        event_id=event.event_id,
        final_decision=state.final_decision,  # type: ignore[arg-type]
        risk_level=state.risk_level,  # type: ignore[arg-type]
        matched_rules=state.matched_rules,
        reason_codes=state.reason_codes,
        allowed_actions=_dedupe_models(state.allowed_actions),
        approval_required_actions=_dedupe_models(state.approval_required_actions),
        blocked_actions=_dedupe_models(state.blocked_actions),
        routes=_dedupe_models(state.routes),
        selected_workflow=state.selected_workflow,
        redactions=state.redactions,
        warnings=[],
        dry_run=effective_dry_run,
        explanation=explanation,
    )


class _EvaluationState:
    def __init__(self, *, evaluation_id: str, event: StructuredEvent, final_decision: str, risk_level: str, dry_run: bool) -> None:
        self.evaluation_id = evaluation_id
        self.event = event
        self.final_decision = final_decision
        self.risk_level = risk_level
        self.dry_run = dry_run
        self.matched_rules: list[MatchedRule] = []
        self.reason_codes: list[str] = []
        self.allowed_actions: list[PlannedAction] = []
        self.approval_required_actions: list[PlannedAction] = []
        self.blocked_actions: list[BlockedAction] = []
        self.routes: list[RouteDecision] = []
        self.selected_workflow: WorkflowSelection | None = None
        self.redactions: list[Redaction] = []


def _rule_matches_event(rule: Rule, event: StructuredEvent) -> bool:
    if rule.event_types and event.event_type not in rule.event_types:
        return False
    return all(_condition_matches(condition, event) for condition in rule.conditions)


def _condition_matches(condition: Condition, event: StructuredEvent) -> bool:
    missing = object()
    actual = _field_value(event.model_dump(mode="json"), condition.field, missing)
    operator = condition.operator
    expected = condition.value
    if operator == "exists":
        return actual is not missing
    if operator == "not_exists":
        return actual is missing
    if actual is missing:
        return False
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "greater_than":
        return _compare(actual, expected, lambda a, b: a > b)
    if operator == "greater_than_or_equal":
        return _compare(actual, expected, lambda a, b: a >= b)
    if operator == "less_than":
        return _compare(actual, expected, lambda a, b: a < b)
    if operator == "less_than_or_equal":
        return _compare(actual, expected, lambda a, b: a <= b)
    if operator == "contains":
        return _contains(actual, expected)
    if operator == "not_contains":
        return not _contains(actual, expected)
    if operator == "in":
        return isinstance(expected, list) and actual in expected
    if operator == "not_in":
        return isinstance(expected, list) and actual not in expected
    if operator == "starts_with":
        return isinstance(actual, str) and isinstance(expected, str) and actual.startswith(expected)
    if operator == "ends_with":
        return isinstance(actual, str) and isinstance(expected, str) and actual.endswith(expected)
    return False


def _field_value(data: dict[str, Any], path: str, missing: object) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return missing
        current = current[part]
    return current


def _compare(actual: Any, expected: Any, operation: Any) -> bool:
    try:
        return bool(operation(actual, expected))
    except TypeError:
        return False


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str):
        return str(expected) in actual
    if isinstance(actual, list):
        return expected in actual
    return False


def _apply_effect(state: _EvaluationState, effect: Effect) -> None:
    params = effect.parameters
    effect_type = effect.effect_type
    if effect_type == "block" and params.get("action_type") and not params.get("block_event", False):
        pass
    elif effect_type in DECISION_PRECEDENCE:
        _raise_decision(state, effect_type)
    elif effect_type == "set_risk":
        _raise_risk(state, params.get("risk_level", "low"))
    elif effect_type == "route_to":
        state.routes.append(RouteDecision(**params))
    elif effect_type == "require_capability":
        state.routes.append(
            RouteDecision(
                component=str(params.get("preferred_component") or params.get("component") or ""),
                capability=params.get("capability"),
                purpose=params.get("purpose"),
            )
        )
    elif effect_type == "select_workflow":
        state.selected_workflow = WorkflowSelection(**params)
    elif effect_type == "propose_action":
        action = PlannedAction(**params)
        if state.final_decision == "require_approval" or params.get("requires_approval"):
            state.approval_required_actions.append(action)
        else:
            state.allowed_actions.append(action)
    elif effect_type == "add_reason":
        if reason := params.get("reason_code"):
            state.reason_codes.append(str(reason))
    elif effect_type == "redact_field":
        state.redactions.append(
            Redaction(field=str(params.get("field", "")), reason_code=str(params.get("reason_code", "REDACTION_REQUIRED")))
        )
    elif effect_type == "stop_processing":
        return

    if effect_type == "block":
        state.blocked_actions.append(
            BlockedAction(
                action_type=str(params.get("action_type", "unspecified_action")),
                reason_code=str(params.get("reason_code", "BLOCKED_BY_POLICY")),
                title=params.get("title"),
                parameters={key: value for key, value in params.items() if key not in {"action_type", "reason_code", "title"}},
            )
        )
    if effect_type == "require_approval" and params.get("action_type"):
        state.approval_required_actions.append(PlannedAction(**params))


def _raise_decision(state: _EvaluationState, decision: str) -> None:
    if DECISION_PRECEDENCE[decision] > DECISION_PRECEDENCE[state.final_decision]:
        state.final_decision = decision


def _raise_risk(state: _EvaluationState, risk_level: str) -> None:
    if risk_level in RISK_PRECEDENCE and RISK_PRECEDENCE[risk_level] > RISK_PRECEDENCE[state.risk_level]:
        state.risk_level = risk_level


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _dedupe_models(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for value in values:
        key = value.model_dump_json() if hasattr(value, "model_dump_json") else str(value)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def initial_rules() -> list[Rule]:
    return [
        Rule(
            rule_id="finance_missing_document_ref_blocks",
            name="Finance documents without a document reference are blocked",
            domain="finance",
            category="hard_policy",
            priority=130,
            event_types=["finance_document.classify"],
            conditions=[Condition(field="payload.document_ref", operator="equals", value=None)],
            effects=[
                Effect(
                    effect_type="block",
                    parameters={
                        "action_type": "classify_finance_document",
                        "reason_code": "INSUFFICIENT_FINANCE_DOCUMENT_DATA",
                        "block_event": True,
                    },
                ),
                Effect(effect_type="set_risk", parameters={"risk_level": "medium"}),
                Effect(effect_type="add_reason", parameters={"reason_code": "INSUFFICIENT_FINANCE_DOCUMENT_DATA"}),
            ],
            stop_processing=True,
        ),
        Rule(
            rule_id="finance_payable_invoice_requires_approval",
            name="Payable invoices require approval",
            domain="finance",
            category="approval",
            priority=110,
            event_types=["finance_document.classify"],
            conditions=[
                Condition(field="payload.document_kind_hint", operator="equals", value="invoice"),
                Condition(field="payload.amount", operator="exists"),
            ],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(effect_type="set_risk", parameters={"risk_level": "medium"}),
                Effect(
                    effect_type="route_to",
                    parameters={
                        "component": "sharons_finance",
                        "capability": "invoice_review",
                        "purpose": "approve_payable_invoice",
                    },
                ),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "create_approval_request",
                        "component": "sharons_governance",
                        "title": "Review payable invoice",
                        "purpose": "human_invoice_approval",
                        "requires_approval": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "PAYABLE_INVOICE_REQUIRES_APPROVAL"}),
            ],
        ),
        Rule(
            rule_id="finance_paid_receipt_allows_filing",
            name="Paid receipts may be filed internally",
            domain="finance",
            category="routing",
            priority=90,
            event_types=["finance_document.classify"],
            conditions=[
                Condition(field="payload.document_kind_hint", operator="equals", value="receipt"),
                Condition(field="payload.paid_at", operator="not_equals", value=None),
            ],
            effects=[
                Effect(effect_type="allow_read_only"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "create_file_link_proposal",
                        "component": "sharons_files",
                        "title": "File paid receipt",
                        "purpose": "safe_internal_filing",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "PAID_RECEIPT_SAFE_TO_FILE"}),
            ],
        ),
        Rule(
            rule_id="finance_low_confidence_routes_to_review",
            name="Low confidence finance documents route to review",
            domain="finance",
            category="approval",
            priority=100,
            event_types=["finance_document.classify"],
            conditions=[Condition(field="payload.confidence_hint", operator="less_than", value=0.75)],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(
                    effect_type="route_to",
                    parameters={"component": "human_review", "capability": "finance_triage", "purpose": "resolve_ambiguous_finance_document"},
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "LOW_CONFIDENCE_FINANCE_DOCUMENT"}),
            ],
        ),
        Rule(
            rule_id="email_missing_content_blocks",
            name="Inbound email without usable content is blocked",
            domain="mail",
            category="hard_policy",
            priority=130,
            event_types=["inbound_email.route"],
            conditions=[
                Condition(field="payload.subject", operator="equals", value=None),
                Condition(field="payload.body_excerpt_redacted", operator="equals", value=None),
            ],
            effects=[
                Effect(
                    effect_type="block",
                    parameters={
                        "action_type": "route_inbound_email",
                        "reason_code": "INSUFFICIENT_EMAIL_ROUTING_DATA",
                        "block_event": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "INSUFFICIENT_EMAIL_ROUTING_DATA"}),
            ],
            stop_processing=True,
        ),
        Rule(
            rule_id="email_sensitive_or_commitment_requires_approval",
            name="Sensitive or commitment-bearing emails require approval",
            domain="mail",
            category="approval",
            priority=120,
            event_types=["inbound_email.route"],
            conditions=[
                Condition(field="payload.sensitivity_hint", operator="in", value=["legal", "financial", "external_commitment", "sensitive"]),
            ],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(effect_type="set_risk", parameters={"risk_level": "high"}),
                Effect(
                    effect_type="route_to",
                    parameters={"component": "owner_review", "capability": "approval", "purpose": "review_sensitive_email"},
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "SENSITIVE_EMAIL_REQUIRES_HUMAN_REVIEW"}),
            ],
        ),
        Rule(
            rule_id="email_trusted_deadline_proposes_task",
            name="Trusted emails with deadlines propose tasks",
            domain="mail",
            category="workflow_selection",
            priority=90,
            event_types=["inbound_email.route"],
            conditions=[
                Condition(field="payload.sender_relationship", operator="in", value=["trusted", "known"]),
                Condition(field="payload.extracted_deadline", operator="not_equals", value=None),
            ],
            effects=[
                Effect(effect_type="allow_read_only"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "create_task_proposal",
                        "component": "sharons_operations",
                        "title": "Draft task from inbound email",
                        "purpose": "executive_assistant_triage",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "TRUSTED_EMAIL_DEADLINE_TASK_PROPOSAL"}),
            ],
        ),
        Rule(
            rule_id="email_attachment_without_action_proposes_file_link",
            name="Emails with attachments but no action request propose file links",
            domain="mail",
            category="routing",
            priority=80,
            event_types=["inbound_email.route"],
            conditions=[
                Condition(field="payload.attachments", operator="not_equals", value=[]),
                Condition(field="payload.extracted_deadline", operator="equals", value=None),
            ],
            effects=[
                Effect(effect_type="allow_read_only"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "create_file_link_proposal",
                        "component": "sharons_files",
                        "title": "File inbound email attachment",
                        "purpose": "safe_internal_filing",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "EMAIL_ATTACHMENT_FILE_PROPOSAL"}),
            ],
        ),
        Rule(
            rule_id="assessment_aerobic_fitness_gap_risk",
            name="Aerobic fitness gaps are medium risk",
            domain="fitness",
            category="risk",
            priority=90,
            event_types=["assessment_finding_created"],
            conditions=[
                Condition(field="payload.finding_type", operator="equals", value="aerobic_fitness_gap"),
                Condition(field="payload.confidence", operator="greater_than_or_equal", value=0.75),
            ],
            effects=[
                Effect(effect_type="set_risk", parameters={"risk_level": "medium"}),
                Effect(effect_type="add_reason", parameters={"reason_code": "AEROBIC_FITNESS_GAP"}),
            ],
        ),
        Rule(
            rule_id="assessment_low_confidence_requires_review",
            name="Low confidence assessment findings require review",
            domain="health",
            category="approval",
            priority=100,
            event_types=["assessment_finding_created"],
            conditions=[Condition(field="payload.confidence", operator="less_than", value=0.75)],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(effect_type="set_risk", parameters={"risk_level": "medium"}),
                Effect(effect_type="add_reason", parameters={"reason_code": "LOW_CONFIDENCE_HEALTH_DATA"}),
            ],
        ),
        Rule(
            rule_id="assessment_high_severity_requires_approval",
            name="High severity findings require approval",
            domain="health",
            category="approval",
            priority=95,
            event_types=["assessment_finding_created"],
            conditions=[Condition(field="payload.severity", operator="in", value=["high", "critical"])],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(effect_type="set_risk", parameters={"risk_level": "high"}),
                Effect(effect_type="add_reason", parameters={"reason_code": "HIGH_SEVERITY_HEALTH_FINDING"}),
            ],
        ),
        Rule(
            rule_id="fitness_gap_routes_to_self_manage",
            name="Route aerobic fitness gaps to self_manage",
            domain="fitness",
            category="routing",
            priority=80,
            event_types=["assessment_finding_created"],
            conditions=[
                Condition(field="payload.finding_type", operator="equals", value="aerobic_fitness_gap"),
                Condition(field="payload.confidence", operator="greater_than_or_equal", value=0.75),
            ],
            effects=[
                Effect(
                    effect_type="route_to",
                    parameters={
                        "component": "self_manage",
                        "capability": "fitness_planning",
                        "purpose": "create_gradual_fitness_plan",
                    },
                ),
                Effect(
                    effect_type="propose_action",
                    parameters={"action_type": "propose_goal", "title": "Improve aerobic fitness"},
                ),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "invoke_component",
                        "component": "self_manage",
                        "purpose": "create_gradual_fitness_plan",
                        "requires_approval": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "ROUTE_TO_SELF_MANAGE"}),
            ],
        ),
        Rule(
            rule_id="assessment_mental_skill_gap_risk",
            name="Mental skill gaps are medium risk",
            domain="mental",
            category="risk",
            priority=90,
            event_types=["assessment_finding_created"],
            conditions=[
                Condition(
                    field="payload.finding_type",
                    operator="in",
                    value=[
                        "mental_skill_gap",
                        "self_regulation_gap",
                        "functional_resilience_gap",
                        "stress_regulation_gap",
                        "sense_of_control_gap",
                    ],
                ),
                Condition(field="payload.confidence", operator="greater_than_or_equal", value=0.75),
            ],
            effects=[
                Effect(effect_type="set_risk", parameters={"risk_level": "medium"}),
                Effect(effect_type="add_reason", parameters={"reason_code": "MENTAL_SKILL_GAP"}),
            ],
        ),
        Rule(
            rule_id="mental_skill_gap_routes_to_self_manage",
            name="Route mental skill gaps to self_manage",
            domain="mental",
            category="routing",
            priority=80,
            event_types=["assessment_finding_created"],
            conditions=[
                Condition(
                    field="payload.finding_type",
                    operator="in",
                    value=[
                        "mental_skill_gap",
                        "self_regulation_gap",
                        "functional_resilience_gap",
                        "stress_regulation_gap",
                        "sense_of_control_gap",
                    ],
                ),
                Condition(field="payload.confidence", operator="greater_than_or_equal", value=0.75),
            ],
            effects=[
                Effect(
                    effect_type="route_to",
                    parameters={
                        "component": "self_manage",
                        "capability": "mental_training",
                        "purpose": "select_existing_mental_exercise",
                    },
                ),
                Effect(
                    effect_type="propose_action",
                    parameters={"action_type": "propose_goal", "title": "Improve mental self-regulation"},
                ),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "invoke_component",
                        "component": "self_manage",
                        "purpose": "select_existing_mental_exercise",
                        "requires_approval": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "ROUTE_TO_SELF_MANAGE"}),
            ],
        ),
        Rule(
            rule_id="mental_training_requires_approval",
            name="New mental training plans require approval",
            domain="mental",
            category="approval",
            priority=85,
            event_types=["assessment_finding_created"],
            conditions=[
                Condition(field="payload.recommended_capability", operator="equals", value="mental_training"),
            ],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "invoke_component",
                        "component": "self_manage",
                        "purpose": "select_existing_mental_exercise",
                        "requires_approval": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "NEW_MENTAL_TRAINING_REQUIRES_APPROVAL"}),
            ],
        ),
        Rule(
            rule_id="fitness_plan_requires_approval",
            name="New fitness plans require approval",
            domain="fitness",
            category="approval",
            priority=85,
            event_types=["assessment_finding_created", "fitness_plan_proposed"],
            conditions=[
                Condition(field="payload.recommended_capability", operator="equals", value="fitness_planning"),
            ],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "invoke_component",
                        "component": "self_manage",
                        "purpose": "create_gradual_fitness_plan",
                        "requires_approval": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "NEW_TRAINING_PLAN_REQUIRES_APPROVAL"}),
            ],
        ),
        Rule(
            rule_id="low_current_fitness_blocks_high_intensity",
            name="Low current fitness blocks high intensity plans",
            domain="fitness",
            category="hard_policy",
            priority=110,
            event_types=["assessment_finding_created"],
            conditions=[
                Condition(field="payload.finding_type", operator="equals", value="aerobic_fitness_gap"),
                Condition(field="payload.current_state", operator="equals", value="low"),
            ],
            effects=[
                Effect(
                    effect_type="block",
                    parameters={
                        "action_type": "create_high_intensity_plan",
                        "reason_code": "LOW_CURRENT_AEROBIC_FITNESS",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "HIGH_INTENSITY_BLOCKED"}),
            ],
        ),
    ]
