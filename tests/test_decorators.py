"""Unit tests for the DualTrust @gate decorator."""

import unittest
from dualtrust.engine import DualTrust
from dualtrust.exceptions import AgentQuarantinedError, InsufficientHumanScoreError


class TestDualTrustDecorators(unittest.TestCase):
    """Test policy enforcement via the @dualtrust.gate decorator."""

    def setUp(self) -> None:
        self.dt = DualTrust()
        self.dt.register_human("human_prime", social_credit=850, credits_balance=100)
        self.dt.register_agent("agent_prime", initial_trust=0.90)

    def test_decorator_successful_execution(self) -> None:
        """Guarded function executes normally when dual-trust matrix conditions pass."""

        @self.dt.gate(min_human_score=750, min_agent_score=0.70, cost_credits=10)
        def request_flying_car(user_id: str, agent_id: str, destination: str) -> str:
            return f"Sky-cab en route to {destination}"

        result = request_flying_car(
            user_id="human_prime",
            agent_id="agent_prime",
            destination="Sky-Port Neo-7",
        )
        self.assertEqual(result, "Sky-cab en route to Sky-Port Neo-7")
        self.assertIn("Sky-Port Neo-7", result)

        # Confirm 10 credits deducted
        human = self.dt.get_or_create_human("human_prime")
        self.assertEqual(human.credits_balance, 90)

    def test_decorator_blocked_by_human_score(self) -> None:
        """Guarded function raises InsufficientHumanScoreError if human credit is low."""
        self.dt.register_human("human_low", social_credit=550)

        @self.dt.gate(min_human_score=700)
        def enter_high_security_vault(user_id: str, agent_id: str) -> str:
            return "Vault unlocked"

        with self.assertRaises(InsufficientHumanScoreError):
            enter_high_security_vault(user_id="human_low", agent_id="agent_prime")

    def test_decorator_blocked_by_quarantined_agent(self) -> None:
        """Guarded function raises AgentQuarantinedError if agent is flagged rogue."""
        self.dt.register_agent("rogue_bot", initial_trust=0.80)
        self.dt.flag_protocol_trespass(
            "rogue_bot", target_system="defense_grid", severity=5.0
        )

        @self.dt.gate()
        def access_subsystem(user_id: str, agent_id: str) -> str:
            return "Accessed"

        with self.assertRaises(AgentQuarantinedError):
            access_subsystem(user_id="human_prime", agent_id="rogue_bot")

    def test_decorator_missing_id_parameters_raises_value_error(self) -> None:
        """Decorator must raise ValueError if wrapped function signature omits identifiers."""

        @self.dt.gate()
        def bad_function(param_a: str) -> str:
            return param_a

        with self.assertRaises(ValueError):
            bad_function(param_a="test")


if __name__ == "__main__":
    unittest.main()
