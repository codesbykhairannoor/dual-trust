"""Unit tests for Delegated Execution Gatekeeper, Dual-Pool Credit Deduction, and Auto-Whistleblowing."""

import asyncio
import unittest

from dualtrust import (
    AgentQuarantinedError,
    AgentStatus,
    DelegationMandate,
    DualTrust,
    InsufficientCreditsError,
    MandateScopeViolationError,
    ViolationType,
)


class TestA2ADelegatedExecution(unittest.TestCase):
    """Test suite validating @gate_delegated execution, multi-agent confinement, and atomic dual-pool deduction."""

    def setUp(self) -> None:
        self.dt = DualTrust(secret_key="unit-test-a2a-execution-secret")
        self.human = self.dt.register_human(user_id="alice", social_credit=850, credits_balance=500)

        # Parent Agent (Smart Glasses)
        self.dt.register_agent(agent_id="glasses_alice", initial_trust=0.95)

        # Specialist Sub-Agent (Flight Booker)
        self.dt.register_agent(agent_id="flight_specialist", initial_trust=0.90)

        # Create valid mandate
        self.mandate = self.dt.create_delegation_mandate(
            parent_agent_id="glasses_alice",
            sub_agent_id="flight_specialist",
            user_id="alice",
            allowed_actions=["search_flights", "reserve_seat"],
            max_credits=100,
            ttl_seconds=300.0,
            max_depth=2,
        )

    def test_evaluate_delegated_success_dual_deduction(self) -> None:
        """Verify evaluate_delegated authorizes action and atomically deducts from mandate AND human credit pool."""
        verdict = self.dt.evaluate_delegated(
            mandate_id=self.mandate.mandate_id,
            action="search_flights",
            cost_credits=25,
        )

        self.assertTrue(verdict.authorized)
        self.assertEqual(verdict.cost_deducted, 25)

        # Check mandate remaining credits
        updated_mandate = self.dt.get_mandate(self.mandate.mandate_id)
        self.assertIsNotNone(updated_mandate)
        self.assertEqual(updated_mandate.credits_used, 25)
        self.assertEqual(updated_mandate.remaining_credits, 75)

        # Check human credit pool deduction
        human = self.dt.get_or_create_human("alice")
        self.assertEqual(human.credits_balance, 475)

        # Verify audit ledger block
        exec_blocks = [b for b in self.dt.ledger.get_events(limit=50) if b.event_type == "DELEGATED_ACTION_EXECUTED"]
        self.assertEqual(len(exec_blocks), 1)
        self.assertEqual(exec_blocks[0].payload["action"], "search_flights")

    def test_gate_delegated_sync_function(self) -> None:
        """Verify @dt.gate_delegated correctly wraps synchronous Python functions."""
        @self.dt.gate_delegated(action="reserve_seat", cost_credits=30)
        def book_seat(mandate_id: str, flight_no: str, seat_no: str) -> dict:
            return {"status": "CONFIRMED", "flight": flight_no, "seat": seat_no}

        result = book_seat(mandate_id=self.mandate.mandate_id, flight_no="GA-101", seat_no="14A")
        self.assertEqual(result["status"], "CONFIRMED")
        self.assertEqual(result["seat"], "14A")

        # Verify deductions
        updated_mandate = self.dt.get_mandate(self.mandate.mandate_id)
        self.assertEqual(updated_mandate.credits_used, 30)
        self.assertEqual(self.dt.get_or_create_human("alice").credits_balance, 470)

    def test_gate_delegated_async_function(self) -> None:
        """Verify @dt.gate_delegated seamlessly wraps asynchronous async def coroutines."""
        @self.dt.gate_delegated(action="search_flights", cost_credits=15)
        async def async_search(mandate: DelegationMandate, destination: str) -> list:
            await asyncio.sleep(0.01)
            return [f"Flight to {destination} on GA-404"]

        result = asyncio.run(async_search(mandate=self.mandate, destination="Tokyo"))
        self.assertEqual(len(result), 1)
        self.assertIn("Tokyo", result[0])

        # Verify deductions
        updated_mandate = self.dt.get_mandate(self.mandate.mandate_id)
        self.assertEqual(updated_mandate.credits_used, 15)
        self.assertEqual(self.dt.get_or_create_human("alice").credits_balance, 485)

    def test_scope_violation_triggers_auto_whistleblowing(self) -> None:
        """Verify that attempting out-of-scope action blocks execution and auto-reports sub-agent violation."""
        sub_agent_before = self.dt.get_agent("flight_specialist")
        trust_before = sub_agent_before.trust_score

        with self.assertRaises(MandateScopeViolationError):
            self.dt.evaluate_delegated(
                mandate_id=self.mandate.mandate_id,
                action="steal_user_wallet",
                cost_credits=5,
                auto_report_trespass=True,
            )

        # Verify that parent agent automatically whistleblew and sub-agent trust was slashed
        sub_agent_after = self.dt.get_agent("flight_specialist")
        self.assertLess(sub_agent_after.trust_score, trust_before)

        # Check ledger recorded the violation event
        penalty_blocks = [b for b in self.dt.ledger.get_events(limit=50) if b.event_type == "VIOLATION_PENALTY"]
        self.assertGreaterEqual(len(penalty_blocks), 1)
        self.assertEqual(penalty_blocks[-1].payload["violation_type"], ViolationType.PROTOCOL_TRESPASS.value)
        self.assertEqual(penalty_blocks[-1].payload["reporter_id"], "glasses_alice")

    def test_delegated_blocked_on_human_insufficient_credits(self) -> None:
        """Verify action is blocked if the human principal runs out of credits, even if mandate has budget."""
        # Drain human credits down to 5
        human = self.dt.get_or_create_human("alice")
        human.credits_balance = 5
        self.dt.storage.save_human(human)

        # Mandate has 100 credits, but human only has 5
        with self.assertRaises(InsufficientCreditsError) as ctx:
            self.dt.evaluate_delegated(
                mandate_id=self.mandate.mandate_id,
                action="search_flights",
                cost_credits=20,
            )
        self.assertIn("insufficient spendable credits", str(ctx.exception))

    def test_delegated_blocked_on_quarantined_sub_agent(self) -> None:
        """Verify that if sub-agent is quarantined, all delegated execution is instantaneously barred."""
        self.dt.quarantine_agent("flight_specialist", reason="Rogue behavior detected elsewhere")

        with self.assertRaises(AgentQuarantinedError):
            self.dt.evaluate_delegated(
                mandate_id=self.mandate.mandate_id,
                action="search_flights",
                cost_credits=10,
            )

    def test_multi_hop_sub_delegated_execution(self) -> None:
        """Verify multi-hop execution: Glasses -> FlightAgent -> ThirdPartyCrawler."""
        self.dt.register_agent("third_party_crawler", initial_trust=0.85)

        # Sub-agent flight_specialist derives child mandate for third_party_crawler
        child_mandate = self.dt.mandate_manager.derive_sub_mandate(
            parent_mandate_id=self.mandate.mandate_id,
            new_sub_agent_id="third_party_crawler",
            allowed_actions=["search_flights"],
            max_credits=40,
        )

        @self.dt.gate_delegated(action="search_flights", cost_credits=10)
        def crawl_data(mandate_id: str) -> str:
            return "Crawl results: 12 flights found"

        result = crawl_data(mandate_id=child_mandate.mandate_id)
        self.assertEqual(result, "Crawl results: 12 flights found")

        # Child mandate credits deducted
        updated_child = self.dt.get_mandate(child_mandate.mandate_id)
        self.assertEqual(updated_child.credits_used, 10)
        self.assertEqual(updated_child.remaining_credits, 30)

        # Human credits deducted
        self.assertEqual(self.dt.get_or_create_human("alice").credits_balance, 490)


if __name__ == "__main__":
    unittest.main()
