"""Unit tests for asynchronous coroutine execution under the DualTrust @gate decorator."""

import asyncio
import unittest
from dualtrust.engine import DualTrust
from dualtrust.exceptions import AgentQuarantinedError, InsufficientHumanScoreError


class TestAsyncDecorators(unittest.IsolatedAsyncioTestCase):
    """Test policy gating on native async def functions."""

    def setUp(self) -> None:
        self.dt = DualTrust()
        self.dt.register_human("async_human", social_credit=850, credits_balance=100)
        self.dt.register_agent("async_agent", initial_trust=0.90)

    async def test_async_function_successful_execution(self) -> None:
        """Asynchronous coroutine guarded by @gate executes and awaits correctly."""

        @self.dt.gate(min_human_score=750, min_agent_score=0.70, cost_credits=5)
        async def fetch_teleportation_status(user_id: str, agent_id: str, item_id: str) -> str:
            await asyncio.sleep(0.01)  # Simulate async IO / network call
            return f"Item {item_id} teleported successfully."

        result = await fetch_teleportation_status(
            user_id="async_human",
            agent_id="async_agent",
            item_id="nanobot_batch_42",
        )
        self.assertIn("nanobot_batch_42 teleported", result)

        human = self.dt.get_or_create_human("async_human")
        self.assertEqual(human.credits_balance, 95)

    async def test_async_function_blocked_by_quarantined_agent(self) -> None:
        """Async function must be blocked if agent is quarantined."""
        self.dt.quarantine_agent("async_agent", reason="Rogue behavior detected")

        @self.dt.gate()
        async def emergency_override(user_id: str, agent_id: str) -> str:
            return "Overridden"

        with self.assertRaises(AgentQuarantinedError):
            await emergency_override(user_id="async_human", agent_id="async_agent")


if __name__ == "__main__":
    unittest.main()
