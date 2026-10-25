"""Anthropic Model Context Protocol (MCP) Security Gateway and JSON-RPC Interceptor for DualTrust."""

import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from dualtrust.engine import DualTrust
from dualtrust.exceptions import (
    AgentQuarantinedError,
    AuthorizationDeniedError,
    ChallengeVerificationError,
    DualTrustError,
    HumanApprovalRequiredError,
    InsufficientCreditsError,
)
from dualtrust.models import ChallengeStatus, HumanApprovalChallenge, HumanTier, TrustVerdict


class DualTrustMCPGateway:
    """Enterprise Security Gateway and Policy Enforcement Interceptor for Anthropic Model Context Protocol (MCP).

    Operates as transparent middleware over standard MCP JSON-RPC 2.0 messages (tools/list and tools/call),
    enforcing agent reputation thresholds, human social credit, credit allowances, and NIST SP 800-63B
    stepped human approval challenges before tool execution.
    """

    def __init__(
        self,
        dualtrust: DualTrust,
        default_user_id: str = "default_user",
        default_agent_id: str = "default_agent",
    ) -> None:
        """Initialize the MCP Gateway with an underlying DualTrust engine instance.

        Args:
            dualtrust: Configured DualTrust governance engine.
            default_user_id: Fallback human principal ID if not specified in request metadata.
            default_agent_id: Fallback AI agent ID if not specified in request metadata.
        """
        self.dt = dualtrust
        self.default_user_id = default_user_id
        self.default_agent_id = default_agent_id

        self._tools: Dict[str, Dict[str, Any]] = {}
        self._handlers: Dict[str, Callable[..., Any]] = {}

    def register_tool(
        self,
        name: str,
        handler: Callable[..., Any],
        description: str = "",
        input_schema: Optional[Dict[str, Any]] = None,
        min_human_score: int = 600,
        min_agent_score: float = 0.50,
        required_tier: Optional[HumanTier] = None,
        cost_credits: int = 0,
        require_human_confirmation: bool = False,
        challenge_ttl_seconds: float = 300.0,
    ) -> None:
        """Register an MCP tool with explicit DualTrust governance policies.

        Args:
            name: Unique name of the tool as exposed in tools/list.
            handler: Callable to execute when the tool is invoked and authorized.
            description: Tool description presented to LLMs.
            input_schema: JSON Schema definition for tool parameters.
            min_human_score: Minimum required human social credit.
            min_agent_score: Minimum required agent reputation score.
            required_tier: Minimum required human clearance tier.
            cost_credits: Spendable credit cost per execution.
            require_human_confirmation: Whether tool requires stepped human approval.
            challenge_ttl_seconds: Validity lifetime for generated approval tokens.
        """
        self._handlers[name] = handler
        self._tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": input_schema or {"type": "object", "properties": {}},
            "policy": {
                "min_human_score": min_human_score,
                "min_agent_score": min_agent_score,
                "required_tier": required_tier,
                "cost_credits": cost_credits,
                "require_human_confirmation": require_human_confirmation,
                "challenge_ttl_seconds": challenge_ttl_seconds,
            },
        }

    def handle_json_rpc(
        self,
        raw_message: Union[str, Dict[str, Any]],
        override_user_id: Optional[str] = None,
        override_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process an incoming MCP JSON-RPC 2.0 message and return compliant response.

        Args:
            raw_message: Serialized JSON string or Python dictionary payload.
            override_user_id: Optional human user ID overriding request metadata.
            override_agent_id: Optional AI agent ID overriding request metadata.

        Returns:
            JSON-RPC 2.0 compliant dictionary response.
        """
        # Parse payload
        if isinstance(raw_message, str):
            try:
                request = json.loads(raw_message)
            except json.JSONDecodeError as err:
                return self._make_rpc_error(None, -32700, f"Parse error: Invalid JSON ({err})")
        elif isinstance(raw_message, dict):
            request = raw_message
        else:
            return self._make_rpc_error(None, -32600, "Invalid Request: Expected JSON object.")

        if not isinstance(request, dict):
            return self._make_rpc_error(None, -32600, "Invalid Request: Expected JSON object.")

        req_id = request.get("id")
        jsonrpc_version = request.get("jsonrpc")
        method = request.get("method")
        params = request.get("params", {})

        if jsonrpc_version != "2.0":
            return self._make_rpc_error(req_id, -32600, "Invalid Request: 'jsonrpc' must be exactly '2.0'.")

        if not isinstance(method, str):
            return self._make_rpc_error(req_id, -32600, "Invalid Request: 'method' must be a string.")

        # Dispatch method
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return self._handle_tools_list(req_id, params, override_user_id, override_agent_id)

        if method == "tools/call":
            return self._handle_tools_call(req_id, params, override_user_id, override_agent_id)

        return self._make_rpc_error(req_id, -32601, f"Method not found: '{method}' is not supported.")

    def _handle_tools_list(
        self,
        req_id: Any,
        params: Dict[str, Any],
        override_user_id: Optional[str] = None,
        override_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Handle 'tools/list' request, returning registered tools and governance metadata."""
        tools_list = []
        for name, spec in self._tools.items():
            policy = spec["policy"]
            tool_entry = {
                "name": spec["name"],
                "description": spec["description"],
                "inputSchema": spec["inputSchema"],
                "governance": {
                    "cost_credits": policy["cost_credits"],
                    "min_agent_score": policy["min_agent_score"],
                    "requires_human_approval": policy["require_human_confirmation"],
                },
            }
            if policy["required_tier"]:
                tool_entry["governance"]["required_tier"] = policy["required_tier"].value
            tools_list.append(tool_entry)

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": tools_list,
            },
        }

    def _handle_tools_call(
        self,
        req_id: Any,
        params: Dict[str, Any],
        override_user_id: Optional[str] = None,
        override_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Handle 'tools/call' with full DualTrust policy gating, HITL tokens, and error propagation."""
        if not isinstance(params, dict):
            return self._make_rpc_error(req_id, -32602, "Invalid params: Expected object.")

        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return self._make_rpc_error(req_id, -32602, "Invalid params: 'arguments' must be an object.")

        if not tool_name or tool_name not in self._tools:
            return self._make_rpc_error(req_id, -32601, f"Tool not found: '{tool_name}' is not registered.")

        # Extract principal identifiers and challenge token
        dualtrust_meta = params.get("_dualtrust", {})
        user_id = override_user_id or dualtrust_meta.get("user_id") or self.default_user_id
        agent_id = override_agent_id or dualtrust_meta.get("agent_id") or self.default_agent_id
        challenge_id = dualtrust_meta.get("challenge_id") or params.get("challenge_id")

        tool_spec = self._tools[tool_name]
        handler = self._handlers[tool_name]
        policy = tool_spec["policy"]

        # Step 1: Stepped Human Approval Challenge Check (NIST SP 800-63B)
        if policy["require_human_confirmation"]:
            if not challenge_id:
                # Issue new challenge token
                challenge = self.dt.create_human_challenge(
                    user_id=user_id,
                    agent_id=agent_id,
                    action_name=tool_name,
                    arguments=arguments,
                    cost_credits=policy["cost_credits"],
                    ttl_seconds=policy["challenge_ttl_seconds"],
                )
                self.dt.ledger.append(
                    event_type="MCP_CHALLENGE_ISSUED",
                    entity_id=challenge.challenge_id,
                    payload={"tool_name": tool_name, "agent_id": agent_id, "user_id": user_id},
                )
                # Return MCP tool execution failure with challenge details for LLM context injection
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"[DUALTRUST_HUMAN_APPROVAL_REQUIRED] Tool '{tool_name}' paused awaiting human approval.\n"
                                    f"Challenge ID: {challenge.challenge_id}\n"
                                    f"Required Credit Cost: {challenge.cost_credits}\n"
                                    f"Expires in: {policy['challenge_ttl_seconds']}s\n"
                                    "Present this challenge to the human supervisor to obtain authorization."
                                ),
                            }
                        ],
                        "isError": True,
                        "_dualtrust": {
                            "status": "CHALLENGE_REQUIRED",
                            "challenge_id": challenge.challenge_id,
                            "action_name": tool_name,
                            "arguments_hash": challenge.arguments_hash,
                            "expires_at": challenge.expires_at,
                        },
                    },
                }
            else:
                # Verify existing challenge token
                ch = self.dt.get_challenge(challenge_id)
                if not ch:
                    return self._make_tool_error_result(
                        req_id,
                        f"[DUALTRUST_CHALLENGE_ERROR] Challenge '{challenge_id}' not found.",
                        status="CHALLENGE_NOT_FOUND",
                    )
                if ch.is_expired():
                    return self._make_tool_error_result(
                        req_id,
                        f"[DUALTRUST_CHALLENGE_ERROR] Challenge '{challenge_id}' has expired.",
                        status="CHALLENGE_EXPIRED",
                    )
                if ch.status != ChallengeStatus.APPROVED:
                    return self._make_tool_error_result(
                        req_id,
                        f"[DUALTRUST_CHALLENGE_ERROR] Challenge '{challenge_id}' is not approved (status: {ch.status.value}).",
                        status="CHALLENGE_UNAPPROVED",
                    )
                # Verify payload against tampering
                canonical_args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
                import hashlib
                if ch.arguments_hash != hashlib.sha256(canonical_args.encode("utf-8")).hexdigest():
                    return self._make_tool_error_result(
                        req_id,
                        "[DUALTRUST_SECURITY_ALERT] Payload tampering detected: Arguments do not match approved challenge.",
                        status="TAMPERING_DETECTED",
                    )

        # Step 2: Policy Evaluation (Quarantine, Trust Score, Social Credit, Tier, Credits)
        verdict = self.dt.evaluate(
            user_id=user_id,
            agent_id=agent_id,
            min_human_score=policy["min_human_score"],
            min_agent_score=policy["min_agent_score"],
            required_tier=policy["required_tier"],
            cost_credits=policy["cost_credits"],
            deduct_cost=True,
        )

        if not verdict.authorized:
            standing = self.dt.get_agent_standing(agent_id)
            reasons_str = "; ".join(verdict.reasons)
            self.dt.ledger.append(
                event_type="MCP_TOOL_BLOCKED",
                entity_id=agent_id,
                payload={
                    "tool_name": tool_name,
                    "user_id": user_id,
                    "reasons": verdict.reasons,
                    "agent_score": verdict.agent_score,
                },
            )
            # Return MCP application error (isError=True) so the LLM sees it and can self-reflect
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"[DUALTRUST_BLOCKED] Execution of '{tool_name}' denied by DualTrust Matrix.\n"
                                f"Reasons: {reasons_str}\n"
                                f"Current Trust Standing: {standing.trust_score:.2f} ({standing.status.value})\n"
                                "Do not retry this action without resolving permission requirements."
                            ),
                        }
                    ],
                    "isError": True,
                    "_dualtrust": {
                        "status": "DENIED",
                        "reasons": verdict.reasons,
                        "composite_score": verdict.composite_score,
                        "agent_status": verdict.agent_status.value,
                    },
                },
            }

        # Step 3: Execute the registered handler
        try:
            raw_result = handler(**arguments)
            # Format result content
            if isinstance(raw_result, str):
                content_text = raw_result
            else:
                content_text = json.dumps(raw_result, default=str)

            self.dt.ledger.append(
                event_type="MCP_TOOL_EXECUTED",
                entity_id=agent_id,
                payload={
                    "tool_name": tool_name,
                    "user_id": user_id,
                    "cost_credits": verdict.cost_deducted,
                },
            )

            if self.dt.watchdog is not None:
                self.dt.watchdog.record_call_success(agent_id=str(agent_id), cost_credits=verdict.cost_deducted)

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": content_text,
                        }
                    ],
                    "isError": False,
                    "_dualtrust": {
                        "status": "AUTHORIZED",
                        "composite_score": verdict.composite_score,
                        "cost_deducted": verdict.cost_deducted,
                        "signature": verdict.signature,
                    },
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"[TOOL_RUNTIME_EXCEPTION] {type(exc).__name__}: {str(exc)}",
                        }
                    ],
                    "isError": True,
                    "_dualtrust": {
                        "status": "RUNTIME_ERROR",
                        "error_type": type(exc).__name__,
                    },
                },
            }

    @staticmethod
    def _make_rpc_error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
        """Construct a standard JSON-RPC 2.0 protocol error response."""
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": message,
            },
        }

    @staticmethod
    def _make_tool_error_result(req_id: Any, message: str, status: str) -> Dict[str, Any]:
        """Construct an MCP tool execution failure result (isError: True) for LLM visibility."""
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": message,
                    }
                ],
                "isError": True,
                "_dualtrust": {
                    "status": status,
                },
            },
        }
