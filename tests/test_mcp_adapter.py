"""Tests for Anthropic Model Context Protocol (MCP) Security Gateway and JSON-RPC Interceptor."""

import json
import unittest

from dualtrust.adapters.mcp import DualTrustMCPGateway
from dualtrust.engine import DualTrust
from dualtrust.models import AgentStatus, HumanTier
from dualtrust.storage import MemoryStorage


class TestMCPGateway(unittest.TestCase):
    """Test suite validating Anthropic MCP JSON-RPC 2.0 tool execution security and HITL governance."""

    def setUp(self) -> None:
        self.dt = DualTrust(storage=MemoryStorage(), secret_key="mcp-test-secret-key")
        self.dt.register_human(user_id="supervisor_alice", social_credit=850, credits_balance=100)
        self.dt.register_agent(agent_id="claude_assistant", initial_trust=0.90)

        self.gateway = DualTrustMCPGateway(
            dualtrust=self.dt,
            default_user_id="supervisor_alice",
            default_agent_id="claude_assistant",
        )

        # Register sample tools
        def calc_tax(income: float, rate: float = 0.2) -> float:
            return income * rate

        def restart_node(node_id: str) -> str:
            return f"Node {node_id} successfully restarted."

        def wipe_database(db_name: str) -> str:
            return f"Database {db_name} purged."

        def failing_tool() -> None:
            raise ValueError("Corrupted data pipeline")

        self.gateway.register_tool(
            name="calculate_tax",
            handler=calc_tax,
            description="Calculate tax liability for given income and tax rate.",
            input_schema={
                "type": "object",
                "properties": {
                    "income": {"type": "number"},
                    "rate": {"type": "number", "default": 0.2},
                },
                "required": ["income"],
            },
            cost_credits=5,
        )

        self.gateway.register_tool(
            name="restart_node",
            handler=restart_node,
            description="Restart a compute node in the cluster.",
            input_schema={
                "type": "object",
                "properties": {"node_id": {"type": "string"}},
                "required": ["node_id"],
            },
            required_tier=HumanTier.STANDARD,
            cost_credits=10,
        )

        self.gateway.register_tool(
            name="wipe_database",
            handler=wipe_database,
            description="Irreversibly delete a production database (Requires Human Confirmation).",
            input_schema={
                "type": "object",
                "properties": {"db_name": {"type": "string"}},
                "required": ["db_name"],
            },
            require_human_confirmation=True,
            cost_credits=20,
        )

        self.gateway.register_tool(
            name="failing_tool",
            handler=failing_tool,
            description="A tool that encounters a runtime crash.",
        )

    def test_mcp_ping(self) -> None:
        """Verify standard JSON-RPC 2.0 ping request."""
        req = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        res = self.gateway.handle_json_rpc(req)
        self.assertEqual(res["jsonrpc"], "2.0")
        self.assertEqual(res["id"], 1)
        self.assertEqual(res["result"], {})

    def test_tools_list_spec_and_governance(self) -> None:
        """Verify tools/list outputs schema and DualTrust security parameters."""
        req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        res = self.gateway.handle_json_rpc(req)
        self.assertIn("result", res)
        tools = res["result"]["tools"]
        self.assertEqual(len(tools), 4)

        tax_tool = next(t for t in tools if t["name"] == "calculate_tax")
        self.assertEqual(tax_tool["governance"]["cost_credits"], 5)
        self.assertFalse(tax_tool["governance"]["requires_human_approval"])

        wipe_tool = next(t for t in tools if t["name"] == "wipe_database")
        self.assertTrue(wipe_tool["governance"]["requires_human_approval"])
        self.assertEqual(wipe_tool["governance"]["cost_credits"], 20)

    def test_tools_call_authorized_execution(self) -> None:
        """Verify authorized tool call execution with credit deduction and receipt."""
        req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "calculate_tax",
                "arguments": {"income": 50000.0, "rate": 0.15},
            },
        }
        res = self.gateway.handle_json_rpc(req)
        self.assertIn("result", res)
        result = res["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["type"], "text")
        self.assertEqual(float(result["content"][0]["text"]), 7500.0)
        self.assertEqual(result["_dualtrust"]["status"], "AUTHORIZED")
        self.assertEqual(result["_dualtrust"]["cost_deducted"], 5)

        # Credits balance deducted: 100 - 5 = 95
        human = self.dt.get_human("supervisor_alice")
        self.assertEqual(human.credits_balance, 95)

    def test_tools_call_blocked_quarantined_agent(self) -> None:
        """Verify that quarantined agents receive informative isError=true for Reflexion."""
        self.dt.quarantine_agent("claude_assistant", "Hallucinated dangerous payload")

        req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "calculate_tax",
                "arguments": {"income": 1000.0},
            },
        }
        res = self.gateway.handle_json_rpc(req)
        result = res["result"]
        # Must return isError=true within result so LLM sees it
        self.assertTrue(result["isError"])
        content_text = result["content"][0]["text"]
        self.assertIn("[DUALTRUST_BLOCKED]", content_text)
        self.assertIn("quarantined", content_text.lower())
        self.assertEqual(result["_dualtrust"]["status"], "DENIED")
        self.assertEqual(result["_dualtrust"]["agent_status"], "quarantined")

    def test_tools_call_insufficient_credits(self) -> None:
        """Verify action blocked when spendable credit balance is depleted."""
        # Deplete credits
        self.dt.storage.deduct_credits("supervisor_alice", 100)

        req = {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "restart_node",
                "arguments": {"node_id": "worker-01"},
            },
        }
        res = self.gateway.handle_json_rpc(req)
        result = res["result"]
        self.assertTrue(result["isError"])
        self.assertIn("Insufficient spendable credits", result["content"][0]["text"])

    def test_tools_call_hitl_approval_lifecycle(self) -> None:
        """Verify stepped human approval challenge generation and resolution via MCP."""
        req_step1 = {
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "wipe_database",
                "arguments": {"db_name": "prod_users"},
            },
        }
        # 1. First invocation triggers challenge token
        res1 = self.gateway.handle_json_rpc(req_step1)
        result1 = res1["result"]
        self.assertTrue(result1["isError"])
        self.assertIn("[DUALTRUST_HUMAN_APPROVAL_REQUIRED]", result1["content"][0]["text"])
        self.assertEqual(result1["_dualtrust"]["status"], "CHALLENGE_REQUIRED")
        challenge_id = result1["_dualtrust"]["challenge_id"]
        self.assertIsNotNone(challenge_id)

        # 2. Human reviews and approves challenge
        ok, msg = self.dt.resolve_human_challenge(challenge_id, approved=True)
        self.assertTrue(ok)

        # 3. Second invocation with approved challenge_id executes
        req_step2 = {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "wipe_database",
                "arguments": {"db_name": "prod_users"},
                "_dualtrust": {"challenge_id": challenge_id},
            },
        }
        res2 = self.gateway.handle_json_rpc(req_step2)
        result2 = res2["result"]
        self.assertFalse(result2["isError"])
        self.assertIn("Database prod_users purged.", result2["content"][0]["text"])
        self.assertEqual(result2["_dualtrust"]["status"], "AUTHORIZED")

    def test_tools_call_hitl_tampering_blocked(self) -> None:
        """Verify that altering parameters between challenge issuance and execution fails."""
        req_initial = {
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "wipe_database",
                "arguments": {"db_name": "staging_test"},
            },
        }
        res1 = self.gateway.handle_json_rpc(req_initial)
        ch_id = res1["result"]["_dualtrust"]["challenge_id"]

        # Human approves deletion of 'staging_test'
        self.dt.resolve_human_challenge(ch_id, approved=True)

        # Attacker modifies db_name to 'production_financial_ledger'
        req_tampered = {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "wipe_database",
                "arguments": {"db_name": "production_financial_ledger"},
                "_dualtrust": {"challenge_id": ch_id},
            },
        }
        res2 = self.gateway.handle_json_rpc(req_tampered)
        result2 = res2["result"]
        self.assertTrue(result2["isError"])
        self.assertEqual(result2["_dualtrust"]["status"], "TAMPERING_DETECTED")
        self.assertIn("Payload tampering detected", result2["content"][0]["text"])

    def test_protocol_error_handling(self) -> None:
        """Verify proper JSON-RPC 2.0 protocol error codes."""
        # 1. Parse error
        err1 = self.gateway.handle_json_rpc("{ malformed json ...")
        self.assertEqual(err1["error"]["code"], -32700)

        # 2. Invalid Request
        err2 = self.gateway.handle_json_rpc({"jsonrpc": "1.0", "id": 1, "method": "ping"})
        self.assertEqual(err2["error"]["code"], -32600)

        # 3. Method not found
        err3 = self.gateway.handle_json_rpc({"jsonrpc": "2.0", "id": 1, "method": "unknown_action"})
        self.assertEqual(err3["error"]["code"], -32601)

        # 4. Unknown tool in tools/call
        err4 = self.gateway.handle_json_rpc({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ghost_tool", "arguments": {}},
        })
        self.assertEqual(err4["error"]["code"], -32601)

    def test_runtime_exception_handling(self) -> None:
        """Verify that handler exceptions are cleanly captured without crashing."""
        req = {
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": {"name": "failing_tool", "arguments": {}},
        }
        res = self.gateway.handle_json_rpc(req)
        result = res["result"]
        self.assertTrue(result["isError"])
        self.assertEqual(result["_dualtrust"]["status"], "RUNTIME_ERROR")
        self.assertIn("Corrupted data pipeline", result["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
