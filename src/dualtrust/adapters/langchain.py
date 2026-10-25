"""LangChain and LangGraph security callback handler for DualTrust gating."""

from typing import Any, Dict, List, Optional
import uuid

from dualtrust.engine import DualTrust
from dualtrust.exceptions import DualTrustError
from dualtrust.models import HumanTier, ViolationType

# Safely check if langchain_core is installed; otherwise provide a compliant base class
try:
    from langchain_core.callbacks.base import BaseCallbackHandler
except ImportError:
    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Duck-typed fallback when langchain-core is not installed."""
        pass


class DualTrustCallbackHandler(BaseCallbackHandler):
    """LangChain / LangGraph callback handler intercepting on_tool_start to enforce DualTrust policies."""

    def __init__(
        self,
        dualtrust: DualTrust,
        default_user_id: Optional[str] = None,
        default_agent_id: Optional[str] = None,
        tool_policies: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        """Initialize the LangChain callback handler.

        Args:
            dualtrust: DualTrust engine instance.
            default_user_id: Fallback human user ID if not provided in run metadata.
            default_agent_id: Fallback AI agent ID if not provided in run metadata.
            tool_policies: Dictionary mapping tool names to specific policy constraints:
                {"order_shuttle": {"min_human_score": 750, "cost_credits": 10}}
        """
        super().__init__()
        self.dt = dualtrust
        self.default_user_id = default_user_id
        self.default_agent_id = default_agent_id
        self.tool_policies = tool_policies or {}

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Optional[uuid.UUID] = None,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Evaluate DualTrust policy before any LangChain/LangGraph tool executes.

        Raises:
            PermissionError: If the dual-trust matrix conditions are not satisfied.
        """
        tool_name = serialized.get("name", "unknown_tool")
        meta = metadata or {}

        user_id = meta.get("user_id", self.default_user_id)
        agent_id = meta.get("agent_id", self.default_agent_id)

        if not user_id or not agent_id:
            # If no context is provided, allow or skip depending on strict mode
            return

        policy = self.tool_policies.get(tool_name, {})
        min_human_score = policy.get("min_human_score", 600)
        min_agent_score = policy.get("min_agent_score", 0.50)
        required_tier = policy.get("required_tier")
        cost_credits = policy.get("cost_credits", 0)

        verdict = self.dt.evaluate(
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
            # Log security event in cryptographic ledger
            self.dt.ledger.append(
                event_type="LANGCHAIN_TOOL_BLOCKED",
                entity_id=agent_id,
                payload={"tool_name": tool_name, "input_snippet": input_str[:100], "reasons": verdict.reasons},
            )
            raise PermissionError(
                f"[DualTrust Security Block] Execution of tool '{tool_name}' denied: {reasons}"
            )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Optional[uuid.UUID] = None,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Optionally penalize agent reputation if tool execution crashed due to rogue parameter injection."""
        meta = metadata or {}
        agent_id = meta.get("agent_id", self.default_agent_id)
        if agent_id and isinstance(error, (ValueError, TypeError)):
            self.dt.report_violation(
                agent_id=agent_id,
                violation_type=ViolationType.RESOURCE_EXHAUSTION,
                severity=1.5,
                details=f"LangChain tool runtime exception: {str(error)[:150]}",
            )
