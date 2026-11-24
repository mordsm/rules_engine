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
    "recommendation_only",
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


class _GenericPayload(BaseModel):
    model_config = {"extra": "allow"}


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
        model = PAYLOAD_MODELS.get(self.event_type, _GenericPayload)
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
    description: str = ""
    domain: str
    category: RuleCategory
    priority: int = 0
    version: int = 1
    status: RuleStatus = "active"
    enabled: bool = True
    approval_required: bool = False
    trigger: str = ""
    explanation_template: str = ""
    updated_at: str = "2026-11-24T00:00:00Z"
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
    conflicts_resolved: list[dict[str, Any]] = Field(default_factory=list)
    alternatives_considered: list[dict[str, Any]] = Field(default_factory=list)
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


_RUNTIME_RULE_OVERRIDES: dict[str, dict[str, Any]] = {}
_RUNTIME_RULE_VERSIONS: dict[str, list[dict[str, Any]]] = {}


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def reset_rule_catalog_for_tests() -> None:
    _RUNTIME_RULE_OVERRIDES.clear()
    _RUNTIME_RULE_VERSIONS.clear()


def get_effective_rules(rule_overrides: dict[str, dict[str, Any]] | None = None) -> list[Rule]:
    base_rules = initial_rules()
    merged_overrides = {**_RUNTIME_RULE_OVERRIDES, **(rule_overrides or {})}
    effective: list[Rule] = []
    for rule in base_rules:
        data = rule.model_dump(mode="json")
        if not data.get("trigger") and data.get("event_types"):
            data["trigger"] = ", ".join(data["event_types"])
        if not data.get("description"):
            data["description"] = data["name"]
        if not data.get("explanation_template"):
            data["explanation_template"] = f"Rule {data['rule_id']} ({data['name']}) triggered on {data['trigger']}."
        has_req_approval = any(e.get("effect_type") == "require_approval" for e in data.get("effects", []))
        if has_req_approval and "approval_required" not in merged_overrides.get(rule.rule_id, {}):
            data["approval_required"] = True
        override = merged_overrides.get(rule.rule_id)
        if override:
            for key, val in override.items():
                if key in data and val is not None:
                    data[key] = val
        effective.append(Rule.model_validate(data))
    return effective


def get_rules_catalog(rule_overrides: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rules = get_effective_rules(rule_overrides)
    catalog: list[dict[str, Any]] = []
    for r in rules:
        d = r.model_dump(mode="json")
        d["actions"] = d.get("effects", [])
        catalog.append(d)
    return catalog


def get_rule_version_history(rule_id: str) -> list[dict[str, Any]]:
    base_map = {r.rule_id: r for r in get_effective_rules({})}
    if rule_id not in base_map:
        raise KeyError(f"Rule not found: {rule_id}")
    history = _RUNTIME_RULE_VERSIONS.get(rule_id)
    if not history:
        base_dump = base_map[rule_id].model_dump(mode="json")
        return [
            {
                "rule_id": rule_id,
                "version": 1,
                "updated_at": base_dump.get("updated_at", "2026-11-24T00:00:00Z"),
                "updated_by": "system_seed",
                "change_note": "Initial catalog version",
                "snapshot": base_dump,
            }
        ]
    return list(history)


def update_rule_in_catalog(rule_id: str, patch: dict[str, Any], actor: str = "user") -> dict[str, Any]:
    current_map = {r.rule_id: r for r in get_effective_rules()}
    if rule_id not in current_map:
        raise KeyError(f"Rule not found: {rule_id}")
    current_rule = current_map[rule_id]
    history = get_rule_version_history(rule_id)
    next_version = max(item["version"] for item in history) + 1
    now = _utc_iso()

    updated_data = current_rule.model_dump(mode="json")
    allowed_fields = {
        "name",
        "description",
        "priority",
        "enabled",
        "status",
        "approval_required",
        "explanation_template",
        "conditions",
        "effects",
        "event_types",
        "stop_processing",
    }
    for k, v in patch.items():
        if k in allowed_fields and v is not None:
            updated_data[k] = v
    updated_data["version"] = next_version
    updated_data["updated_at"] = now

    validated = Rule.model_validate(updated_data)
    snapshot = validated.model_dump(mode="json")
    _RUNTIME_RULE_OVERRIDES[rule_id] = snapshot
    history.append(
        {
            "rule_id": rule_id,
            "version": next_version,
            "updated_at": now,
            "updated_by": actor,
            "change_note": str(patch.get("change_note") or "Rule updated via Control Center"),
            "snapshot": snapshot,
        }
    )
    _RUNTIME_RULE_VERSIONS[rule_id] = history
    snapshot["actions"] = snapshot.get("effects", [])
    return snapshot


def rollback_rule_version(rule_id: str, target_version: int, actor: str = "user") -> dict[str, Any]:
    history = get_rule_version_history(rule_id)
    target_entry = next((item for item in history if int(item["version"]) == int(target_version)), None)
    if not target_entry:
        raise ValueError(f"Version {target_version} not found for rule {rule_id}")
    restored_snapshot = dict(target_entry["snapshot"])
    now = _utc_iso()
    next_version = max(item["version"] for item in history) + 1
    restored_snapshot["version"] = next_version
    restored_snapshot["updated_at"] = now
    validated = Rule.model_validate(restored_snapshot)
    snapshot = validated.model_dump(mode="json")
    _RUNTIME_RULE_OVERRIDES[rule_id] = snapshot
    history.append(
        {
            "rule_id": rule_id,
            "version": next_version,
            "updated_at": now,
            "updated_by": actor,
            "change_note": f"Rollback to version {target_version}",
            "restored_from_version": target_version,
            "snapshot": snapshot,
        }
    )
    _RUNTIME_RULE_VERSIONS[rule_id] = history
    snapshot["actions"] = snapshot.get("effects", [])
    return snapshot


def _rule_primary_decision(rule: Rule) -> str:
    best = "recommendation_only"
    for eff in rule.effects:
        if eff.effect_type == "block" and eff.parameters.get("action_type") and not eff.parameters.get("block_event", False):
            continue
        if eff.effect_type in DECISION_PRECEDENCE:
            if DECISION_PRECEDENCE[eff.effect_type] > DECISION_PRECEDENCE[best]:
                best = eff.effect_type
    if rule.approval_required and DECISION_PRECEDENCE["require_approval"] > DECISION_PRECEDENCE[best]:
        best = "require_approval"
    return best


def evaluate_structured_event(
    event_data: dict[str, Any],
    *,
    dry_run: bool | None = None,
    rule_overrides: dict[str, dict[str, Any]] | None = None,
) -> EvaluationResult:
    try:
        event = StructuredEvent.model_validate(event_data)
        event.typed_payload()
    except ValidationError as exc:
        raise RuleEvaluationError([f"VALIDATION_ERROR:{err['loc']}:{err['msg']}" for err in exc.errors()]) from exc

    effective_dry_run = event.metadata.dry_run if dry_run is None else dry_run
    rules = get_effective_rules(rule_overrides)
    matched = [rule for rule in rules if rule.executable() and _rule_matches_event(rule, event)]
    matched.sort(key=lambda rule: (-rule.priority, rule.rule_id))

    state = _EvaluationState(
        evaluation_id=f"eval_{uuid4().hex[:12]}",
        event=event,
        final_decision="recommendation_only",
        risk_level="low",
        dry_run=effective_dry_run,
    )

    alternatives_considered: list[dict[str, Any]] = []
    conflicts_resolved: list[dict[str, Any]] = []

    for rule in matched:
        rule_decision = _rule_primary_decision(rule)
        alternatives_considered.append(
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "version": rule.version,
                "priority": rule.priority,
                "candidate_decision": rule_decision,
                "effects": [effect.effect_type for effect in rule.effects],
            }
        )
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
        if rule.approval_required:
            _raise_decision(state, "require_approval")
        for effect in rule.effects:
            _apply_effect(state, effect)
        if rule.stop_processing:
            break

    if len(alternatives_considered) > 1:
        distinct_decisions = {item["candidate_decision"] for item in alternatives_considered}
        winner = max(
            alternatives_considered,
            key=lambda item: (DECISION_PRECEDENCE.get(item["candidate_decision"], 0), item["priority"]),
        )
        for alt in alternatives_considered:
            if alt["rule_id"] != winner["rule_id"] and (
                len(distinct_decisions) > 1 or alt["priority"] != winner["priority"]
            ):
                conflicts_resolved.append(
                    {
                        "winning_rule_id": winner["rule_id"],
                        "winning_version": winner["version"],
                        "winning_priority": winner["priority"],
                        "winning_decision": state.final_decision,
                        "overridden_rule_id": alt["rule_id"],
                        "overridden_version": alt["version"],
                        "overridden_priority": alt["priority"],
                        "overridden_decision": alt["candidate_decision"],
                        "resolution_reason": (
                            f"Resolved in favor of {winner['rule_id']} (priority={winner['priority']}, "
                            f"decision={state.final_decision}) over {alt['rule_id']} "
                            f"(priority={alt['priority']}, decision={alt['candidate_decision']}) "
                            "by deterministic decision precedence and priority order."
                        ),
                    }
                )

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
        conflicts_resolved=conflicts_resolved,
        alternatives_considered=alternatives_considered,
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
        # --- 20 Initial Proactive Personal Development Rules (Section 16) ---
        Rule(
            rule_id="FROG-001",
            name="בדוק בערב אם קיימות לפחות ארבע צפרדעים",
            description="בבדיקת ערב, כאשר מספר הצפרדעים הפעילות יורד מתחת ל-4, בקש מהמשתמש להשלים את המאגר מבלי להמציא צפרדעים.",
            domain="frogs",
            category="automation",
            priority=100,
            trigger="evening_review.frogs_check",
            event_types=["evening_review.frogs_check"],
            conditions=[Condition(field="payload.active_frogs_count", operator="less_than", value=4)],
            effects=[
                Effect(effect_type="recommendation_only"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "request_user_frog_pool_replenishment",
                        "component": "compass",
                        "title": "השלמת מאגר צפרדעים ל-4 צפרדעים פעילות",
                        "purpose": "maintain_minimum_frog_pool_without_inventing",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "FROG_POOL_BELOW_MINIMUM_4"}),
            ],
            explanation_template="מאגר הצפרדעים מכיל פחות מ-4 צפרדעים פעילות; המערכת מבקשת השלמה מהמשתמש ואינה ממציאה צפרדעים.",
        ),
        Rule(
            rule_id="FROG-002",
            name="בחר צפרדע מתאימה לבוקר",
            description="בחר צפרדע יומית מוקדם ביום לפי חשיבות, התנגדות, דחיפות, זמן זמין ואנרגיה.",
            domain="frogs",
            category="workflow_selection",
            priority=95,
            trigger="morning_plan.select_frog",
            event_types=["morning_plan.select_frog", "daily_plan.evaluate"],
            conditions=[Condition(field="payload.active_frogs_count", operator="greater_than_or_equal", value=1)],
            effects=[
                Effect(effect_type="allow"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "schedule_daily_frog_early",
                        "component": "compass",
                        "title": "שיבוץ צפרדע יומית מוקדם ביום",
                        "purpose": "eat_that_frog_morning_priority",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "DAILY_FROG_SELECTED_FOR_MORNING"}),
            ],
            explanation_template="נבחרה צפרדע יומית לשיבוץ מוקדם בהתאם לחשיבות, התנגדות, זמן זמין ואנרגיה.",
        ),
        Rule(
            rule_id="FROG-003",
            name="הסר צפרדע חד-פעמית לאחר השלמה",
            description="צפרדע חד-פעמית שהושלמה נסגרת אוטומטית מהמאגר הפעיל.",
            domain="frogs",
            category="automation",
            priority=105,
            trigger="frog.completed",
            event_types=["frog.completed"],
            conditions=[Condition(field="payload.frog_type", operator="equals", value="one_time")],
            effects=[
                Effect(effect_type="allow"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "close_completed_one_time_frog",
                        "component": "compass",
                        "title": "סגירת צפרדע חד-פעמית שהושלמה",
                        "purpose": "close_one_time_frog",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "ONE_TIME_FROG_COMPLETED_AND_CLOSED"}),
            ],
            explanation_template="צפרדע חד-פעמית הושלמה ולכן נסגרה מהמאגר הפעיל.",
        ),
        Rule(
            rule_id="FROG-004",
            name="הסרת צפרדע מתמשכת דורשת אישור",
            description="צפרדע מתמשכת נשארת במאגר גם לאחר ביצוע; הסרתה מהמאגר דורשת אישור משתמש מפורש.",
            domain="frogs",
            category="approval",
            priority=120,
            approval_required=True,
            trigger="frog.remove_requested",
            event_types=["frog.remove_requested"],
            conditions=[Condition(field="payload.frog_type", operator="equals", value="ongoing")],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "remove_ongoing_frog",
                        "component": "compass",
                        "title": "אישור הסרת צפרדע מתמשכת ממאגר הצפרדעים",
                        "purpose": "confirm_ongoing_frog_no_longer_triggers_resistance",
                        "requires_approval": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "ONGOING_FROG_REMOVAL_REQUIRES_APPROVAL"}),
            ],
            explanation_template="הסרת צפרדע מתמשכת מחייבת אישור מפורש של המשתמש כי אינה מעוררת עוד התנגדות.",
        ),
        Rule(
            rule_id="HABIT-001",
            name="הצע גרסה מינימלית כאשר קיימת התנגדות",
            description="כאשר מדווחת התנגדות גבוהה או אנרגיה נמוכה, הצע גרסה מינימלית של ההרגל לשמירה על רצף ללא ענישה.",
            domain="habits",
            category="recommendation",
            priority=95,
            trigger="routine.resistance_detected",
            event_types=["routine.resistance_detected", "daily_plan.evaluate"],
            conditions=[Condition(field="payload.resistance_level", operator="greater_than_or_equal", value=7)],
            effects=[
                Effect(effect_type="allow"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "activate_minimum_viable_routine",
                        "component": "self_manage",
                        "title": "הפעלת גרסה מינימלית של השגרה",
                        "purpose": "reduce_activation_resistance",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "HIGH_RESISTANCE_MINIMUM_VIABLE_HABIT"}),
            ],
            explanation_template="זוהתה התנגדות גבוהה; המערכת מציעה גרסה מינימלית של השגרה כדי להקל על התחלת הפעולה.",
        ),
        Rule(
            rule_id="MENTAL-001",
            name="הצע הכנה קצרה לפני אירוע מאתגר",
            description="לפני פעולה או אירוע המעוררים מתח מקדים, הפעל פרוטוקול הכנה קצר בן 6 שלבים.",
            domain="mental",
            category="recommendation",
            priority=95,
            trigger="event.challenging_upcoming",
            event_types=["event.challenging_upcoming", "frog.starting"],
            conditions=[Condition(field="payload.expected_resistance", operator="greater_than_or_equal", value=6)],
            effects=[
                Effect(effect_type="allow"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "run_pre_action_preparation_protocol",
                        "component": "compass",
                        "title": "פרוטוקול הכנה קצר (30–60 שניות) לפני פעולה מאתגרת",
                        "purpose": "pre_event_mental_preparation",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "PRE_EVENT_PREPARATION_RECOMMENDED"}),
            ],
            explanation_template="לפני אירוע או צפרדע עם התנגדות גבוהה מופעל פרוטוקול הכנה קצר להפחתת מתח מקדים.",
        ),
        Rule(
            rule_id="MENTAL-002",
            name="אפשר תיעוד מהיר לאחר אירוע",
            description="לאחר אירוע רגשי או מנטלי, אפשר תיעוד מהיר (כולל דיווח חלקי שבו שדה חסר אינו נחשב כאפס).",
            domain="mental",
            category="workflow_selection",
            priority=90,
            trigger="mental_event.occurred",
            event_types=["mental_event.occurred"],
            conditions=[],
            effects=[
                Effect(effect_type="allow"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "capture_quick_post_event_reflection",
                        "component": "compass",
                        "title": "תיעוד מהיר של אירוע מנטלי (דיווח מלא או חלקי)",
                        "purpose": "post_event_processing",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "POST_EVENT_QUICK_CAPTURE_ENABLED"}),
            ],
            explanation_template="אירוע מנטלי הסתיים; מופעל תיעוד מהיר התומך בדיווח חלקי ובשמירת פרטיות.",
        ),
        Rule(
            rule_id="MENTAL-003",
            name="בדוק הצלחות שקטות אחת לשבוע",
            description="אחת לשבוע בדוק ותעד מצבים שבעבר עוררו תגובה חריגה והפעם עברו בשקט.",
            domain="mental",
            category="automation",
            priority=90,
            trigger="weekly_review.silent_wins_check",
            event_types=["weekly_review.silent_wins_check"],
            conditions=[Condition(field="payload.days_since_silent_wins_check", operator="greater_than_or_equal", value=7)],
            effects=[
                Effect(effect_type="recommendation_only"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "prompt_weekly_silent_wins_check",
                        "component": "compass",
                        "title": "בדיקת הצלחות שקטות שבועית",
                        "purpose": "prevent_negative_reporting_bias",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "WEEKLY_SILENT_WINS_CHECK_DUE"}),
            ],
            explanation_template="חלף שבוע מאז בדיקת ההצלחות השקטות האחרונה; מופעלת בדיקה למניעת הטיית מדידה שלילית.",
        ),
        Rule(
            rule_id="ASSESS-001",
            name="הפק הערכה חודשית",
            description="אחת לחודש הפק הערכת מגמות מנטלית והתנהגותית ב-Personal Assessment.",
            domain="assessment",
            category="routing",
            priority=85,
            trigger="monthly_review.due",
            event_types=["monthly_review.due"],
            conditions=[Condition(field="payload.days_since_last_monthly_review", operator="greater_than_or_equal", value=28)],
            effects=[
                Effect(effect_type="allow_read_only"),
                Effect(
                    effect_type="route_to",
                    parameters={
                        "component": "personal_Assessment",
                        "capability": "monthly_mental_review",
                        "purpose": "generate_monthly_trend_assessment",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "MONTHLY_ASSESSMENT_DUE"}),
            ],
            explanation_template="הגיע מועד ההערכה החודשית; הבקשה מנותבת אל Personal Assessment.",
        ),
        Rule(
            rule_id="ASSESS-002",
            name="אל תסיק מגמה כשאין מספיק נתונים",
            description="חסום הסקת מגמת שיפור או נסיגה כאשר מספר האירועים המתועדים נמוך מסף המינימום (5 אירועים).",
            domain="assessment",
            category="hard_policy",
            priority=130,
            trigger="assessment.trend_requested",
            event_types=["assessment.trend_requested"],
            conditions=[Condition(field="payload.event_count", operator="less_than", value=5)],
            effects=[
                Effect(
                    effect_type="block",
                    parameters={
                        "action_type": "infer_mental_trend",
                        "reason_code": "INSUFFICIENT_MENTAL_EVENT_DATA",
                        "block_event": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "INSUFFICIENT_MENTAL_EVENT_DATA"}),
            ],
            stop_processing=True,
            explanation_template="כמות הנתונים נמוכה מסף המינימום (5 אירועים); נחסמה הסקת מגמה בלתי מבוססת.",
        ),
        Rule(
            rule_id="GROWTH-001",
            name="תעדף תחומי ליבה",
            description="תעדף את תחומי הליבה (מנטלי, פיזי, AI מקצועי) על פני תחומי העשרה בתוכנית היומית.",
            domain="growth",
            category="workflow_selection",
            priority=100,
            trigger="daily_plan.evaluate",
            event_types=["daily_plan.evaluate"],
            conditions=[Condition(field="payload.core_domains_scheduled_count", operator="equals", value=0)],
            effects=[
                Effect(effect_type="allow"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "prioritize_core_growth_domain",
                        "component": "compass",
                        "title": "הוספת פעילות ליבה (מנטלי / פיזי / AI) לתוכנית היומית",
                        "purpose": "ensure_core_domain_priority",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "CORE_GROWTH_DOMAIN_PRIORITIZED"}),
            ],
            explanation_template="תחומי הליבה (מנטלי, פיזי, AI) מתועדפים לפני תחומי העשרה בתוכנית היומית.",
        ),
        Rule(
            rule_id="GROWTH-002",
            name="זהה תחום שלא התקדם",
            description="זהה תחום ליבה שלא נרשמה בו פעילות מעבר לסף הימים המוגדר והצע התערבות מתאימה.",
            domain="growth",
            category="recommendation",
            priority=95,
            trigger="growth_domain.check",
            event_types=["growth_domain.check"],
            conditions=[
                Condition(field="payload.tier", operator="equals", value="core"),
                Condition(field="payload.days_since_last_activity", operator="greater_than_or_equal", value=7),
            ],
            effects=[
                Effect(effect_type="recommendation_only"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "propose_neglected_core_domain_intervention",
                        "component": "compass",
                        "title": "הצעת התערבות לתחום ליבה שלא התקדם",
                        "purpose": "prevent_core_domain_neglect",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "NEGLECTED_CORE_DOMAIN_DETECTED"}),
            ],
            explanation_template="תחום ליבה לא התקדם במשך 7 ימים או יותר; נוצרה הצעת התערבות.",
        ),
        Rule(
            rule_id="CHALLENGE-001",
            name="התאם אתגר לפי ביצועים ומגבלות",
            description="בחן התקדמות, דריכה במקום או עומס והצע התאמת רמת קושי של האתגר.",
            domain="challenges",
            category="recommendation",
            priority=90,
            trigger="challenge.evaluate",
            event_types=["challenge.evaluate"],
            conditions=[Condition(field="payload.pain_or_limitation", operator="equals", value=False)],
            effects=[
                Effect(effect_type="allow"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "adjust_challenge_within_approved_bounds",
                        "component": "compass",
                        "title": "התאמת רמת קושי אתגר בגבולות המאושרים",
                        "purpose": "adaptive_challenge_progression",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "ADAPTIVE_CHALLENGE_EVALUATED"}),
            ],
            explanation_template="האתגר נבחן מול ביצועי המשתמש ומגבלותיו להצעת התאמת רמת קושי.",
        ),
        Rule(
            rule_id="CHALLENGE-002",
            name="אל תעלה קושי מעבר לגבולות המאושרים",
            description="חסום העלאת עומס או קושי כאשר קיימת מגבלת בטיחות/כאב או חריגה מתקרת הקושי שהמשתמש אישר.",
            domain="challenges",
            category="hard_policy",
            priority=135,
            trigger="challenge.evaluate",
            event_types=["challenge.evaluate"],
            conditions=[Condition(field="payload.exceeds_safety_or_approved_bounds", operator="equals", value=True)],
            effects=[
                Effect(
                    effect_type="block",
                    parameters={
                        "action_type": "increase_challenge_difficulty",
                        "reason_code": "CHALLENGE_BOUNDS_OR_SAFETY_LIMIT_EXCEEDED",
                        "block_event": True,
                    },
                ),
                Effect(effect_type="set_risk", parameters={"risk_level": "high"}),
                Effect(effect_type="add_reason", parameters={"reason_code": "CHALLENGE_BOUNDS_OR_SAFETY_LIMIT_EXCEEDED"}),
            ],
            stop_processing=True,
            explanation_template="נחסמה העלאת רמת קושי עקב דיווח על כאב/מגבלת בטיחות או חריגה מהגבול המאושר.",
        ),
        Rule(
            rule_id="PLAN-001",
            name="התאם תוכנית לזמן ולאנרגיה",
            description="כאשר רמת האנרגיה נמוכה (1–2), התאם את התוכנית היומית לגרסה קלה ומדורגת.",
            domain="planning",
            category="workflow_selection",
            priority=105,
            trigger="daily_plan.evaluate",
            event_types=["daily_plan.evaluate"],
            conditions=[Condition(field="payload.energy_level", operator="less_than_or_equal", value=2)],
            effects=[
                Effect(effect_type="allow"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "scale_down_plan_for_low_energy",
                        "component": "compass",
                        "title": "התאמת תוכנית יומית לאנרגיה נמוכה (גרסאות מינימליות)",
                        "purpose": "energy_aware_daily_planning",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "LOW_ENERGY_PLAN_ADAPTED"}),
            ],
            explanation_template="רמת האנרגיה נמוכה; התוכנית היומית הותאמה לעומס מופחת וגרסאות מינימליות.",
        ),
        Rule(
            rule_id="PLAN-002",
            name="מנע עומס מופרז",
            description="כאשר סך הדקות המתוכננות עולה על הזמן הזמין של המשתמש, דרוש אישור או צמצום לפני הפעלת התוכנית.",
            domain="planning",
            category="approval",
            priority=125,
            approval_required=True,
            trigger="daily_plan.evaluate",
            event_types=["daily_plan.evaluate"],
            conditions=[Condition(field="payload.is_overloaded", operator="equals", value=True)],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(effect_type="set_risk", parameters={"risk_level": "medium"}),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "trim_or_approve_overloaded_daily_plan",
                        "component": "compass",
                        "title": "תוכנית יומית חורגת מהזמן הזמין – נדרש צמצום או אישור",
                        "purpose": "prevent_impossible_daily_plan",
                        "requires_approval": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "DAILY_PLAN_EXCEEDS_AVAILABLE_TIME"}),
            ],
            explanation_template="זמן הפעילויות המתוכנן עולה על הזמן הזמין; התוכנית נשמרה כממתינה לאישור כדי למנוע עומס בלתי אפשרי.",
        ),
        Rule(
            rule_id="AI-001",
            name="העדף פתרון דטרמיניסטי",
            description="חסום קריאה למודל שפה (LLM) כאשר קיים פתרון דטרמיניסטי באמצעות כללים או חישוב.",
            domain="ai_governance",
            category="hard_policy",
            priority=130,
            trigger="ai.invocation_requested",
            event_types=["ai.invocation_requested"],
            conditions=[Condition(field="payload.deterministic_available", operator="equals", value=True)],
            effects=[
                Effect(
                    effect_type="block",
                    parameters={
                        "action_type": "invoke_llm",
                        "reason_code": "DETERMINISTIC_SOLUTION_AVAILABLE",
                        "block_event": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "DETERMINISTIC_SOLUTION_AVAILABLE"}),
            ],
            stop_processing=True,
            explanation_template="קיים פתרון דטרמיניסטי לפעולה זו; הקריאה למודל השפה נחסמה לחיסכון בעלויות ושמירה על עקביות.",
        ),
        Rule(
            rule_id="AI-002",
            name="תעד כל קריאה למודל",
            description="כל הפעלה של מודל שפה או תמלול/הקראה חייבת להירשם ביומן השימוש עם סיבה, סוג ועלות.",
            domain="ai_governance",
            category="automation",
            priority=100,
            trigger="ai.invocation_requested",
            event_types=["ai.invocation_requested"],
            conditions=[Condition(field="payload.deterministic_available", operator="equals", value=False)],
            effects=[
                Effect(effect_type="allow"),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "log_ai_model_invocation",
                        "component": "compass",
                        "title": "תיעוד קריאה למודל AI ביומן העלויות",
                        "purpose": "track_ai_usage_and_cost",
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "AI_INVOCATION_LOGGED"}),
            ],
            explanation_template="אין פתרון דטרמיניסטי מספק; הקריאה למודל מאושרת ומתועדת ביומן השימוש והעלויות.",
        ),
        Rule(
            rule_id="CONTROL-001",
            name="שינוי מדיניות דורש אישור",
            description="כל שינוי מהותי במדיניות, מטרות ליבה או גבולות אוטונומיה דורש אישור מפורש של המשתמש בתפקיד המתכנן.",
            domain="control",
            category="approval",
            priority=140,
            approval_required=True,
            trigger="policy.change_requested",
            event_types=["policy.change_requested"],
            conditions=[Condition(field="payload.is_material_change", operator="equals", value=True)],
            effects=[
                Effect(effect_type="require_approval"),
                Effect(effect_type="set_risk", parameters={"risk_level": "high"}),
                Effect(
                    effect_type="propose_action",
                    parameters={
                        "action_type": "approve_policy_change",
                        "component": "compass",
                        "title": "אישור שינוי מדיניות או גבולות אוטונומיה",
                        "purpose": "protect_user_policy_sovereignty",
                        "requires_approval": True,
                    },
                ),
                Effect(effect_type="add_reason", parameters={"reason_code": "MATERIAL_POLICY_CHANGE_REQUIRES_APPROVAL"}),
            ],
            explanation_template="שינוי מהותי במדיניות או בגבולות האוטונומיה מחייב אישור מפורש של המשתמש.",
        ),
        Rule(
            rule_id="CONTROL-002",
            name="כל החלטה משמעותית ניתנת להסבר",
            description="כל החלטה משמעותית מתועדת עם הכלל שהופעל, גרסתו, הנתונים בפועל והחלופות שנבדקו.",
            domain="control",
            category="automation",
            priority=90,
            trigger="decision.recorded",
            event_types=["decision.recorded", "daily_plan.evaluate"],
            conditions=[],
            effects=[
                Effect(effect_type="allow"),
                Effect(effect_type="add_reason", parameters={"reason_code": "DECISION_AUDIT_AND_EXPLANATION_RECORDED"}),
            ],
            explanation_template="ההחלטה תועדה ביומן ההחלטות עם הכלל, גרסתו, הנתונים שהוזנו והחלופות שנבדקו.",
        ),
    ]
