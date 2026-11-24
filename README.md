# rules_engine

This project provides a reusable rule engine agent that can be imported by other agents and projects.

## Family decision manager

The first implementation is a family decision manager that can:

- read rules from a YAML configuration file
- be updated externally by other agents or tools
- persist updates back to disk
- expose a simple Python API for decision making

## Quick start

```python
from rule_engine_agent import FamilyDecisionManager

manager = FamilyDecisionManager(config_path="family_config.yaml")
result = manager.decide({"category": "schedule", "value": "tired"}, actor="parent")
print(result)
```

## External configuration

You can update the agent externally by passing partial data:

```python
manager.update_config({"decision_mode": "consensus"})
```

Or by editing the YAML file directly; the next initialization will load the latest values.

## Review workflow

The engine supports manual review for higher-risk decisions. Enable it in the YAML config with:

```yaml
review_required: true
```

When a decision is marked for review, the result includes `requires_review: true` and the item is persisted in `review_queue.json`.

The HTTP service exposes review operations:

- `POST /review/approve` with `review_id`, `reviewer`, and optional `notes`
- `POST /review/reject` with `review_id`, `reviewer`, and optional `notes`
- `GET /review/pending` to list pending review items

Example using `curl`:

```bash
curl -X POST http://127.0.0.1:8000/review/approve \
  -H "Content-Type: application/json" \
  -d '{"review_id": "<review_id>", "reviewer": "manager", "notes": "approved after manual review"}'
```

## Using from other agents

Other agents should use the shared API entrypoint to evaluate context and receive structured decision results.

```python
from api import evaluate_family_decision

result = evaluate_family_decision(
    {"category": "schedule", "value": "tired"},
    config_path="family_config.yaml",
    actor="parent",
)
if result.get("requires_review"):
    # route to manual review instead of auto-applying
    print("Decision needs review")
else:
    print("Apply decision:", result["decision"])
```

When review is required, the result includes `requires_review: true`, allowing other agents to defer action and trigger a separate review workflow.

Other agents can also use the HTTP service directly:

```python
import requests

payload = {
    "context": {"category": "schedule", "value": "tired"},
    "actor": "parent",
}
response = requests.post("http://127.0.0.1:8000/evaluate", json=payload)
result = response.json()
if result.get("requires_review"):
    print("Decision needs review")
else:
    print("Apply decision:", result["decision"])
```

The CLI supports review tasks:

- `--pending-reviews` to show pending reviews
- `--approve <review_id>` to approve an item
- `--reject <review_id>` to reject an item
- `--reviewer <name>` and `--notes <text>` to annotate the review action

Example:

```bash
python cli.py --config family_config.yaml --context '{"category": "schedule", "value": "tired"}' --actor parent

python cli.py --config family_config.yaml --pending-reviews

python cli.py --config family_config.yaml --approve <review_id> --reviewer manager --notes "approved after manual review"
```

## Service-style call example

Other agents can call the rules engine through the shared entrypoint:

```python
from api import evaluate_family_decision

result = evaluate_family_decision(
    {"category": "schedule", "value": "tired"},
    config_path="family_config.yaml",
    actor="parent",
)
print(result)
```