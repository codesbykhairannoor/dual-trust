"""Unit and SLA assertions for microsecond latency overhead under zero-hallucination protocol."""

import os
import time
import unittest
from dualtrust.crypto_ledger import MerkleTree
from dualtrust.engine import DualTrust
from dualtrust.models import HumanTier


class TestMicrosecondBenchmarks(unittest.TestCase):
    """Enforce microsecond SLA bounds on policy evaluation and cryptographic routines."""

    def setUp(self) -> None:
        self.dt = DualTrust()
        self.dt.register_human("perf_user", social_credit=850, credits_balance=1000)
        self.dt.register_agent("perf_agent", initial_trust=0.85)

    def test_evaluate_policy_median_sla(self) -> None:
        """Core policy evaluation median latency must remain strictly below 0.5 ms (500 us)."""
        iterations = 500
        latencies_us = []

        # Warm-up
        for _ in range(50):
            self.dt.evaluate(user_id="perf_user", agent_id="perf_agent")

        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            _ = self.dt.evaluate(user_id="perf_user", agent_id="perf_agent")
            t1 = time.perf_counter_ns()
            latencies_us.append((t1 - t0) / 1000.0)

        latencies_us.sort()
        p50 = latencies_us[int(0.50 * iterations)]
        p99 = latencies_us[int(0.99 * iterations)]

        # Target SLA: p50 < 200 us, p99 < 2000 us (2 ms)
        self.assertLess(
            p50,
            200.0,
            f"Median evaluation overhead ({p50:.2f} us) breached SLA limit of 200 us.",
        )
        self.assertLess(
            p99,
            2000.0,
            f"Worst-case p99 tail latency ({p99:.2f} us) breached SLA limit of 2000 us.",
        )

    def test_gate_decorator_overhead(self) -> None:
        """The @gate decorator must introduce less than 250 us median latency."""
        @self.dt.gate(min_human_score=600, min_agent_score=0.50)
        def target_action(user_id: str, agent_id: str) -> str:
            return "ok"

        iterations = 500
        latencies_us = []

        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            res = target_action(user_id="perf_user", agent_id="perf_agent")
            t1 = time.perf_counter_ns()
            latencies_us.append((t1 - t0) / 1000.0)
            self.assertEqual(res, "ok")

        latencies_us.sort()
        p50 = latencies_us[int(0.50 * iterations)]
        self.assertLess(p50, 250.0, f"Decorator overhead p50 ({p50:.2f} us) breached 250 us SLA.")

    def test_merkle_verification_latency(self) -> None:
        """Merkle inclusion proof verification must execute in under 100 us."""
        leaves = [f"audit_{i:04d}" for i in range(64)]
        tree = MerkleTree(leaves)
        proof = tree.get_proof(17)

        iterations = 500
        latencies_us = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            valid = MerkleTree.verify_proof(leaves[17], proof, tree.root)
            t1 = time.perf_counter_ns()
            latencies_us.append((t1 - t0) / 1000.0)
            self.assertTrue(valid)

        latencies_us.sort()
        p50 = latencies_us[int(0.50 * iterations)]
        self.assertLess(p50, 100.0, f"Merkle verification p50 ({p50:.2f} us) breached 100 us SLA.")


    def test_a2a_mandate_verification_latency(self) -> None:
        """A2A cryptographic HMAC mandate verification must complete in under 50 us."""
        mandate = self.dt.create_delegation_mandate(
            parent_agent_id="perf_agent",
            sub_agent_id="sub_perf_agent",
            user_id="perf_user",
            allowed_actions=["fast_action"],
            max_credits=5000,
            require_handshake=False,
        )

        iterations = 500
        latencies_us = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            is_valid, _ = self.dt.mandate_manager.verify_mandate(mandate, action="fast_action", cost_credits=1)
            t1 = time.perf_counter_ns()
            latencies_us.append((t1 - t0) / 1000.0)
            self.assertTrue(is_valid)

        latencies_us.sort()
        p50 = latencies_us[int(0.50 * iterations)]
        self.assertLess(p50, 50.0, f"A2A mandate verification p50 ({p50:.2f} us) breached 50 us SLA.")

    def test_gate_delegated_overhead(self) -> None:
        """The @gate_delegated decorator must introduce less than 150 us median latency."""
        self.dt.register_agent("bench_sub_agent", initial_trust=0.88)
        mandate = self.dt.create_delegation_mandate(
            parent_agent_id="perf_agent",
            sub_agent_id="bench_sub_agent",
            user_id="perf_user",
            allowed_actions=["bench_action"],
            max_credits=100000,
            require_handshake=False,
        )

        @self.dt.gate_delegated(action="bench_action", cost_credits=1)
        def target_action(mandate_id: str) -> str:
            return "ok"

        iterations = 500
        latencies_us = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            res = target_action(mandate_id=mandate.mandate_id)
            t1 = time.perf_counter_ns()
            latencies_us.append((t1 - t0) / 1000.0)
            self.assertEqual(res, "ok")

        latencies_us.sort()
        p50 = latencies_us[int(0.50 * iterations)]
        self.assertLess(p50, 150.0, f"@gate_delegated overhead p50 ({p50:.2f} us) breached 150 us SLA.")


if __name__ == "__main__":
    unittest.main()

