from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from rule_engine_agent import FamilyDecisionManager


def evaluate_family_decision(
    context: Dict[str, Any],
    config_path: Optional[str | Path] = None,
    actor: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Reusable entrypoint for other agents to evaluate a family decision."""
    manager = FamilyDecisionManager(config_path=config_path, config=config)
    return manager.decide(context=context, actor=actor)
