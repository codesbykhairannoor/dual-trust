"""Tests for DualTrust Automated Reputation Watchdog (Sliding Window Velocity & Drift Slashing)."""

import time
import unittest

from dualtrust.adapters.mcp import DualTrustMCPGateway
from dualtrust.engine import DualTrust
from dualtrust.exceptions import AgentQuarantinedError, VelocityLimitExceededError
from dualtrust.models import AgentStatus, AnomalyType, ViolationType
from dualtrust.storage import MemoryStorage
from dualtrust.watchdog import AgentWatchdog


class TestAgentWatchdog(unittest.TestCase):
    """Test suite validating sliding-window velocity tracking, burst rate throttling, and auto-quarantine."""

    def setUp(self) -> None:
        self.dt = DualTrust(storage=MemoryStorage(), secret_key="watchdog-test-secret")
        self.dt.register_human(user_id="user_admin", social_credit=850, credits_balance=5000)
        self.dt.register_agent(agent_id="bot_worker", initial_trust=0.90)

    def test_sliding_window_burst_throttling_and_auto_quarantine(self) -> None:
        """Rapid tool call bursts exceeding sliding window limit trigger throttle and auto-quarantine."""
        # Enable watchdog with max 5 calls per 10-second window
        self.dt.enable_watchdog(
            window_seconds=10.0,
            max_calls_per_window=5,
            auto_quarantine_on_burst=True,
        )

        @self.dt.gate()
        def process_task(user_id: str, agent_id: str, item_id: int) -> str:
            return f"Processed {item_id}"

        # 5 calls in rapid succession must all succeed
        for i in range(5):
            res = process_task(user_id="user_admin", agent_id="bot_worker", item_id=i)
            self.assertEqual(res, f"Processed {i}")

        # 6th call exceeds burst limit -> raises VelocityLimitExceededError
        with self.assertRaises(VelocityLimitExceededError) as ctx:
            process_task(user_id="user_admin", agent_id="bot_worker", item_id=6)

        self.assertIn("Call velocity burst limit exceeded", str(ctx.exception))

        # Because auto_quarantine_on_burst=True, agent must now be quarantined
        agent = self.dt.get_agent("bot_worker")
        self.assertEqual(agent.status, AgentStatus.QUARANTINED)

        # Subsequent calls blocked by quarantine
        with self.assertRaises(AgentQuarantinedError):
            process_task(user_id="user_admin", agent_id="bot_worker", item_id=7)

    def test_sliding_window_time_expiration_pruning(self) -> None:
        """Telemetry outside the sliding window is pruned, restoring capacity without false blocks."""
        watchdog = AgentWatchdog(window_seconds=5.0, max_calls_per_window=3)
        dt = DualTrust(storage=MemoryStorage(), watchdog=watchdog)
        dt.register_human("user_admin", social_credit=800, credits_balance=1000)
        dt.register_agent("bot_burst", initial_trust=0.90)

        t0 = 1000.0
        # 3 calls recorded at t0
        for _ in range(3):
            watchdog.record_call_success("bot_burst", cost_credits=0, current_time=t0)

        # Immediate 4th call at t0 is blocked
        v_blocked = watchdog.inspect_pre_call("bot_burst", cost_credits=0, current_time=t0 + 1.0)
        self.assertFalse(v_blocked.action_permitted)
        self.assertTrue(v_blocked.action_throttled)

        # After window_seconds expires (t0 + 6.0), old calls are pruned
        v_allowed = watchdog.inspect_pre_call("bot_burst", cost_credits=0, current_time=t0 + 6.0)
        self.assertTrue(v_allowed.action_permitted)
        self.assertFalse(v_allowed.action_throttled)

    def test_credit_drain_velocity_limiting(self) -> None:
        """Rapid credit drain exceeding window velocity threshold is throttled."""
        self.dt.enable_watchdog(
            window_seconds=30.0,
            max_credit_burn_per_window=100,
            auto_quarantine_on_burst=False,
        )

        @self.dt.gate(cost_credits=60)
        def heavy_query(user_id: str, agent_id: str, query: str) -> str:
            return f"Queried {query}"

        # 1st call drains 60 credits (total burn: 60/100) -> allowed
        res = heavy_query(user_id="user_admin", agent_id="bot_worker", query="SELECT 1")
        self.assertEqual(res, "Queried SELECT 1")

        # 2nd call attempts to drain another 60 credits (projected: 120/100) -> throttled
        with self.assertRaises(VelocityLimitExceededError) as ctx:
            heavy_query(user_id="user_admin", agent_id="bot_worker", query="SELECT 2")

        self.assertIn("Credit drain velocity exceeded", str(ctx.exception))

    def test_infraction_velocity_escalating_penalties(self) -> None:
        """Clustered infractions within the sliding window scale penalties exponentially and auto-quarantine."""
        # 1.5x multiplier per recent violation, auto-quarantine at 3 violations in window
        self.dt.enable_watchdog(
            window_seconds=60.0,
            max_violations_per_window=3,
            velocity_slashing_multiplier=2.0,
        )

        initial_trust = self.dt.get_agent("bot_worker").trust_score

        # Violation 1 (isolated): 2.0^0 = 1.0x multiplier
        v1 = self.dt.report_violation(
            agent_id="bot_worker",
            violation_type=ViolationType.RESOURCE_EXHAUSTION,
            severity=1.0,
            is_system_verified=True,
        )
        p1 = v1.penalty_applied

        # Violation 2 (rapid cluster): 2.0^1 = 2.0x multiplier
        v2 = self.dt.report_violation(
            agent_id="bot_worker",
            violation_type=ViolationType.RESOURCE_EXHAUSTION,
            severity=1.0,
            is_system_verified=True,
        )
        p2 = v2.penalty_applied
        self.assertGreater(p2, p1)

        # Violation 3 (reaches limit 3 in window) -> triggers automatic escalating quarantine!
        v3 = self.dt.report_violation(
            agent_id="bot_worker",
            violation_type=ViolationType.RESOURCE_EXHAUSTION,
            severity=1.0,
            is_system_verified=True,
        )
        agent = self.dt.get_agent("bot_worker")
        self.assertEqual(agent.status, AgentStatus.QUARANTINED)

    def test_semantic_drift_detection(self) -> None:
        """Watchdog correctly identifies semantic drift exceeding tolerance threshold."""
        watchdog = AgentWatchdog()
        # Normal drift below threshold
        v1 = watchdog.record_semantic_drift("bot_worker", drift_distance=0.30, threshold=0.75)
        self.assertFalse(v1.is_anomalous)
        self.assertTrue(v1.action_permitted)

        # High drift anomaly
        v2 = watchdog.record_semantic_drift("bot_worker", drift_distance=0.88, threshold=0.75)
        self.assertTrue(v2.is_anomalous)
        self.assertEqual(v2.anomaly_type, AnomalyType.SEMANTIC_DRIFT)
        self.assertFalse(v2.action_permitted)
        self.assertIn("Semantic drift anomaly", v2.reason)

    def test_real_time_telemetry_reporting(self) -> None:
        """Agent activity metrics and velocity rates are accurately computed."""
        self.dt.enable_watchdog(window_seconds=60.0, max_calls_per_window=20)

        @self.dt.gate(cost_credits=10)
        def run_op(user_id: str, agent_id: str) -> str:
            return "ok"

        for _ in range(4):
            run_op(user_id="user_admin", agent_id="bot_worker")

        telemetry = self.dt.get_watchdog_telemetry("bot_worker")
        self.assertIsNotNone(telemetry)
        self.assertEqual(telemetry.agent_id, "bot_worker")
        self.assertEqual(telemetry.calls_in_window, 4)
        self.assertEqual(telemetry.credits_burned_in_window, 40)
        self.assertAlmostEqual(telemetry.call_rate_per_sec, 4.0 / 60.0, places=3)
        self.assertFalse(telemetry.is_throttled)
        self.assertIn("Calls: 4", telemetry.describe())

    def test_mcp_gateway_burst_throttling(self) -> None:
        """Anthropic MCP Gateway intercepts runaway loops and returns isError=true for LLM Reflexion."""
        self.dt.enable_watchdog(
            window_seconds=10.0,
            max_calls_per_window=3,
            auto_quarantine_on_burst=True,
        )
        gateway = DualTrustMCPGateway(
            dualtrust=self.dt,
            default_user_id="user_admin",
            default_agent_id="bot_worker",
        )
        gateway.register_tool(
            name="ping_database",
            handler=lambda: "pong",
            description="Ping database connection",
        )

        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ping_database", "arguments": {}},
        }

        # 3 calls pass
        for _ in range(3):
            res = gateway.handle_json_rpc(req)
            self.assertFalse(res["result"]["isError"])

        # 4th call throttled by watchdog
        res4 = gateway.handle_json_rpc(req)
        result4 = res4["result"]
        self.assertTrue(result4["isError"])
        self.assertIn("[DUALTRUST_BLOCKED]", result4["content"][0]["text"])
        self.assertIn("Call velocity burst limit exceeded", result4["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
