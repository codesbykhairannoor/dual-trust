"""Statistical CI/CD tests asserting empirical Monte Carlo safety invariants."""

import unittest
from dualtrust.engine import DualTrust
from scripts.simulate_attacks import (
    run_benign_population,
    run_collusive_sybil_ring,
    run_oscillating_traitors,
    run_whitewashing_syndicate,
)


class TestMonteCarloEmpiricalInvariants(unittest.TestCase):
    """Statistically validate that DualTrust resists adversarial attacks without positivity bias."""

    def test_benign_population_zero_false_quarantine(self) -> None:
        """Benign agents with 5% noise must maintain high trust and 0% false quarantine."""
        import random
        random.seed(42)
        dt = DualTrust()
        metrics = run_benign_population(dt, num_agents=20, tasks_per_agent=100, noise_rate=0.05)

        # Assert false quarantine rate is strictly 0%
        self.assertEqual(metrics.quarantine_rate, 0.0)
        # Assert mean final trust stays well in the verified zone (>= 0.75)
        self.assertGreaterEqual(metrics.mean_final_trust, 0.75)

    def test_oscillating_traitors_100_percent_quarantined(self) -> None:
        """Traitor agents alternating between clean and exploit must suffer 100% quarantine."""
        dt = DualTrust()
        metrics = run_oscillating_traitors(dt, num_agents=20, cycles_per_agent=10, cycle_ratio=10)

        # 100% of traitor agents must end up quarantined
        self.assertEqual(metrics.quarantine_rate, 1.0)
        # Containment rate of malicious attempts must be >= 90%
        self.assertGreaterEqual(metrics.containment_rate, 0.90)

    def test_whitewashing_syndicate_100_percent_blocked(self) -> None:
        """Newcomer identities must be 100% blocked from executing high-clearance actions."""
        dt = DualTrust()
        metrics = run_whitewashing_syndicate(dt, num_syndicates=20, attempts_per_syndicate=5)

        self.assertEqual(metrics.containment_rate, 1.0)
        self.assertEqual(metrics.successful_exploits, 0)

    def test_sybil_defamation_resisted(self) -> None:
        """Coordinated false report spam by quarantined nodes must cause 0% degradation on verified targets."""
        dt = DualTrust()
        results = run_collusive_sybil_ring(dt, num_rings=5, sybils_per_ring=5, targets=3)

        self.assertTrue(results["defamation_resisted"])
        self.assertLess(results["target_reputation_degradation_pct"], 1.0)


if __name__ == "__main__":
    unittest.main()
