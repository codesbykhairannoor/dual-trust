"""CrewAI and AutoGen tool wrapper for DualTrust policy enforcement."""

import functools
from typing import Any, Callable, Dict, Optional

from dualtrust.engine import DualTrust
from dualtrust.models import HumanTier


def guard_crewai_tool(
    tool: Any,
    dualtrust: DualTrust,
    user_id: str,
    agent_id: str,
    min_human_score: int = 600,
    min_agent_score: float = 0.50,
    required_tier: Optional[HumanTier] = None,
    cost_credits: int = 0,
) -> Any:
    """Wrap a CrewAI BaseTool instance or callable with DualTrust pre-execution gating.

    Args:
        tool: A CrewAI BaseTool instance, an object with a `_run` method, or a plain callable.
        dualtrust: The DualTrust engine instance.
        user_id: Human principal requesting the action.
        agent_id: CrewAI agent executing the tool.
        min_human_score: Required social credit threshold.
        min_agent_score: Required agent trust score.
        required_tier: Optional minimum clearance tier.
        cost_credits: Credits consumed on execution.

    Returns:
        The tool with its execution method securely intercepted.
    """
    def _evaluate_and_run(original_method: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        verdict = dualtrust.evaluate(
            user_id=user_id,
            agent_id=agent_id,
            min_human_score=min_human_score,
            min_agent_score=min_agent_score,
            required_tier=required_tier,
            cost_credits=cost_credits,
            deduct_cost=True,
        )

        if not verdict.authorized:
            reasons = "; ".join(verdict.reasons)
            dualtrust.ledger.append(
                event_type="CREWAI_TOOL_BLOCKED",
                entity_id=agent_id,
                payload={"tool_class": tool.__class__.__name__, "reasons": verdict.reasons},
            )
            raise PermissionError(f"[DualTrust Security Block] CrewAI tool execution denied: {reasons}")

        return original_method(*args, **kwargs)

    # If it is a CrewAI BaseTool object with _run method
    if hasattr(tool, "_run") and callable(getattr(tool, "_run")):
        orig_run = tool._run

        @functools.wraps(orig_run)
        def wrapped_run(*args: Any, **kwargs: Any) -> Any:
            return _evaluate_and_run(orig_run, *args, **kwargs)

        tool._run = wrapped_run
        return tool

    # Plain callable
    if callable(tool):
        @functools.wraps(tool)
        def wrapped_callable(*args: Any, **kwargs: Any) -> Any:
            return _evaluate_and_run(tool, *args, **kwargs)

        return wrapped_callable

    return tool
