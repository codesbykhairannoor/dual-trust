"""OpenAI and LiteLLM function/tool calling security dispatcher for DualTrust."""

import json
from typing import Any, Callable, Dict, List, Optional, Union

from dualtrust.engine import DualTrust
from dualtrust.models import HumanTier


class OpenAIToolDispatcher:
    """Safe interceptor and dispatcher for OpenAI-style function/tool calling payloads."""

    def __init__(self, dualtrust: DualTrust) -> None:
        """Initialize dispatcher with a DualTrust engine instance."""
        self.dt = dualtrust
        self._registry: Dict[str, Callable[..., Any]] = {}
        self._policies: Dict[str, Dict[str, Any]] = {}

    def register_tool(
        self,
        name: str,
        handler: Callable[..., Any],
        min_human_score: int = 600,
        min_agent_score: float = 0.50,
        required_tier: Optional[HumanTier] = None,
        cost_credits: int = 0,
    ) -> None:
        """Register a local Python callable and associated DualTrust execution policies."""
        self._registry[name] = handler
        self._policies[name] = {
            "min_human_score": min_human_score,
            "min_agent_score": min_agent_score,
            "required_tier": required_tier,
            "cost_credits": cost_credits,
        }

    def dispatch_single(
        self,
        tool_call: Any,
        user_id: str,
        agent_id: str,
    ) -> Dict[str, Any]:
        """Intercept a single tool call, evaluate policies, execute if authorized, and format tool message."""
        # Handle both SDK object (`tool_call.function.name`) and raw dict (`tool_call["function"]["name"]`)
        if hasattr(tool_call, "function"):
            tool_id = getattr(tool_call, "id", "call_default")
            name = tool_call.function.name
            raw_args = tool_call.function.arguments
        elif isinstance(tool_call, dict):
            tool_id = tool_call.get("id", "call_default")
            fn = tool_call.get("function", {})
            name = fn.get("name", "unknown")
            raw_args = fn.get("arguments", "{}")
        else:
            return {
                "role": "tool",
                "tool_call_id": "unknown",
                "content": json.dumps({"status": "ERROR", "error": "Invalid tool_call object format."}),
            }

        # Check registration
        if name not in self._registry:
            return {
                "role": "tool",
                "tool_call_id": tool_id,
                "content": json.dumps({"status": "ERROR", "error": f"Tool '{name}' is not registered."}),
            }

        policy = self._policies.get(name, {})
        verdict = self.dt.evaluate(
            user_id=user_id,
            agent_id=agent_id,
            min_human_score=policy.get("min_human_score", 600),
            min_agent_score=policy.get("min_agent_score", 0.50),
            required_tier=policy.get("required_tier"),
            cost_credits=policy.get("cost_credits", 0),
            deduct_cost=True,
        )

        if not verdict.authorized:
            reasons = "; ".join(verdict.reasons)
            self.dt.ledger.append(
                event_type="OPENAI_TOOL_BLOCKED",
                entity_id=agent_id,
                payload={"tool_name": name, "tool_id": tool_id, "reasons": verdict.reasons},
            )
            return {
                "role": "tool",
                "tool_call_id": tool_id,
                "content": json.dumps({"status": "DENIED", "reasons": reasons}),
            }

        # Parse JSON arguments safely
        if isinstance(raw_args, str):
            try:
                parsed_args = json.loads(raw_args)
            except json.JSONDecodeError as err:
                return {
                    "role": "tool",
                    "tool_call_id": tool_id,
                    "content": json.dumps({"status": "ERROR", "error": f"Failed to parse arguments JSON: {err}"}),
                }
        elif isinstance(raw_args, dict):
            parsed_args = raw_args
        else:
            parsed_args = {}

        # Execute registered handler
        handler = self._registry[name]
        try:
            result = handler(**parsed_args)
            content_str = result if isinstance(result, str) else json.dumps(result)
            return {
                "role": "tool",
                "tool_call_id": tool_id,
                "content": content_str,
            }
        except Exception as exc:
            return {
                "role": "tool",
                "tool_call_id": tool_id,
                "content": json.dumps({"status": "EXECUTION_EXCEPTION", "error": str(exc)}),
            }

    def dispatch_all(
        self,
        tool_calls: List[Any],
        user_id: str,
        agent_id: str,
    ) -> List[Dict[str, Any]]:
        """Dispatch a list of parallel tool calls and return all corresponding tool message responses."""
        return [self.dispatch_single(tc, user_id=user_id, agent_id=agent_id) for tc in tool_calls]
