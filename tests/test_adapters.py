"""Unit tests for third-party multi-agent framework adapters (LangChain, OpenAI, CrewAI)."""

import json
from types import SimpleNamespace
import unittest
from dualtrust.adapters.crewai import guard_crewai_tool
from dualtrust.adapters.langchain import DualTrustCallbackHandler
from dualtrust.adapters.openai import OpenAIToolDispatcher
from dualtrust.engine import DualTrust


class TestMultiAgentAdapters(unittest.TestCase):
    """Verify integration adapters for LangChain, OpenAI tool calls, and CrewAI tools."""

    def setUp(self) -> None:
        self.dt = DualTrust()
        self.dt.register_human("user_chief", social_credit=850, credits_balance=100)
        self.dt.register_agent("agent_prime", initial_trust=0.90)

    # =========================================================================
    # 1. LangChain / LangGraph Adapter Tests
    # =========================================================================

    def test_langchain_callback_authorized(self) -> None:
        """LangChain on_tool_start allows compliant tool calls."""
        handler = DualTrustCallbackHandler(
            dualtrust=self.dt,
            default_user_id="user_chief",
            default_agent_id="agent_prime",
            tool_policies={"fetch_analytics": {"min_human_score": 700, "cost_credits": 5}},
        )

        # Should execute cleanly without raising PermissionError
        handler.on_tool_start(
            serialized={"name": "fetch_analytics"},
            input_str="quarterly_q3",
            metadata={"user_id": "user_chief", "agent_id": "agent_prime"},
        )

        human = self.dt.get_or_create_human("user_chief")
        self.assertEqual(human.credits_balance, 95)

    def test_langchain_callback_blocked_raises_permission_error(self) -> None:
        """LangChain on_tool_start blocks unauthorized tool calls with PermissionError."""
        handler = DualTrustCallbackHandler(
            dualtrust=self.dt,
            default_user_id="user_chief",
            default_agent_id="agent_prime",
            tool_policies={"launch_shuttle": {"min_human_score": 950}},  # Requires 950+
        )

        with self.assertRaises(PermissionError) as ctx:
            handler.on_tool_start(
                serialized={"name": "launch_shuttle"},
                input_str="payload_mars_1",
                metadata={"user_id": "user_chief", "agent_id": "agent_prime"},
            )
        self.assertIn("DualTrust Security Block", str(ctx.exception))

    # =========================================================================
    # 2. OpenAI / LiteLLM Tool Dispatcher Tests
    # =========================================================================

    def test_openai_dispatcher_authorized_single(self) -> None:
        """OpenAI tool dispatcher intercepts, approves, executes, and formats response."""
        dispatcher = OpenAIToolDispatcher(self.dt)

        def calculate_velocity(distance_km: float, time_hours: float) -> str:
            return json.dumps({"velocity_kmh": distance_km / time_hours})

        dispatcher.register_tool(
            name="calculate_velocity",
            handler=calculate_velocity,
            min_human_score=700,
            cost_credits=10,
        )

        # Mock OpenAI SDK ToolCall object
        mock_tool_call = SimpleNamespace(
            id="call_abc123",
            function=SimpleNamespace(
                name="calculate_velocity",
                arguments=json.dumps({"distance_km": 1000.0, "time_hours": 2.0}),
            ),
        )

        response = dispatcher.dispatch_single(
            mock_tool_call, user_id="user_chief", agent_id="agent_prime"
        )

        self.assertEqual(response["role"], "tool")
        self.assertEqual(response["tool_call_id"], "call_abc123")
        payload = json.loads(response["content"])
        self.assertEqual(payload["velocity_kmh"], 500.0)

    def test_openai_dispatcher_denied_returns_structured_denial(self) -> None:
        """OpenAI tool dispatcher formats security denial as tool message when unauthorized."""
        dispatcher = OpenAIToolDispatcher(self.dt)
        dispatcher.register_tool(
            name="classified_scan",
            handler=lambda: "secret",
            min_human_score=999,  # User only has 850
        )

        raw_dict_call = {
            "id": "call_denied_99",
            "function": {"name": "classified_scan", "arguments": "{}"},
        }

        response = dispatcher.dispatch_single(
            raw_dict_call, user_id="user_chief", agent_id="agent_prime"
        )
        self.assertEqual(response["role"], "tool")
        payload = json.loads(response["content"])
        self.assertEqual(payload["status"], "DENIED")
        self.assertIn("reasons", payload)

    # =========================================================================
    # 3. CrewAI Tool Wrapper Tests
    # =========================================================================

    def test_crewai_basetool_wrapping(self) -> None:
        """CrewAI BaseTool _run method is intercepted and protected by policy."""
        class MockCrewTool:
            def __init__(self) -> None:
                self.executed = False

            def _run(self, query: str) -> str:
                self.executed = True
                return f"Processed {query}"

        tool = MockCrewTool()
        guarded_tool = guard_crewai_tool(
            tool=tool,
            dualtrust=self.dt,
            user_id="user_chief",
            agent_id="agent_prime",
            min_human_score=700,
            cost_credits=5,
        )

        result = guarded_tool._run(query="satellite_telemetry")
        self.assertEqual(result, "Processed satellite_telemetry")
        self.assertTrue(tool.executed)

    def test_crewai_blocked_raises_permission_error(self) -> None:
        """CrewAI tool raises PermissionError if agent is quarantined."""
        self.dt.quarantine_agent("agent_prime")

        class MockCrewTool:
            def _run(self) -> str:
                return "Should not run"

        tool = MockCrewTool()
        guarded_tool = guard_crewai_tool(
            tool=tool,
            dualtrust=self.dt,
            user_id="user_chief",
            agent_id="agent_prime",
        )

        with self.assertRaises(PermissionError):
            guarded_tool._run()


if __name__ == "__main__":
    unittest.main()
