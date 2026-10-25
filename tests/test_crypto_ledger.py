"""Unit tests for the cryptographic hash-chained audit ledger."""

import hashlib
import os
import tempfile
import unittest
from dualtrust.crypto_ledger import CryptographicLedger, MerkleTree
from dualtrust.engine import DualTrust
from dualtrust.storage import SQLiteStorage


class TestCryptographicLedger(unittest.TestCase):
    """Verify SHA-256 hash chaining, Merkle-like sequential integrity, and tamper detection."""

    def test_ledger_append_and_sequential_chaining(self) -> None:
        """Ledger must sequentially link blocks via cryptographic hashes."""
        ledger = CryptographicLedger()

        block_0 = ledger.append("HUMAN_REGISTERED", "user_1", {"credit": 700})
        self.assertEqual(block_0.index, 0)
        self.assertEqual(block_0.prev_hash, CryptographicLedger.GENESIS_HASH)
        self.assertTrue(block_0.verify_hash())

        block_1 = ledger.append("AGENT_REWARDED", "agent_1", {"trust": 0.85})
        self.assertEqual(block_1.index, 1)
        self.assertEqual(block_1.prev_hash, block_0.block_hash)
        self.assertTrue(block_1.verify_hash())

        block_2 = ledger.append("VIOLATION_PENALTY", "agent_1", {"severity": 4.0})
        self.assertEqual(block_2.index, 2)
        self.assertEqual(block_2.prev_hash, block_1.block_hash)

        is_valid, err = ledger.verify_integrity()
        self.assertTrue(is_valid)
        self.assertIsNone(err)

    def test_tamper_detection_in_payload(self) -> None:
        """Altering a committed block payload must break cryptographic verification."""
        ledger = CryptographicLedger()
        ledger.append("EVENT_A", "user_1", {"amount": 100})
        ledger.append("EVENT_B", "user_2", {"amount": 200})
        ledger.append("EVENT_C", "user_3", {"amount": 300})

        # Tamper with block 1 payload directly
        tampered_block = ledger._chain[1]
        # Replace block with modified payload without re-hashing
        ledger._chain[1] = type(tampered_block)(
            index=tampered_block.index,
            timestamp=tampered_block.timestamp,
            event_type=tampered_block.event_type,
            entity_id=tampered_block.entity_id,
            payload={"amount": 999999},  # Tampered data!
            prev_hash=tampered_block.prev_hash,
            block_hash=tampered_block.block_hash,
        )

        is_valid, err = ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertIn("tampered", str(err).lower())

    def test_tamper_detection_in_hash_linkage(self) -> None:
        """Forging a block's prev_hash must trigger chain-break detection."""
        ledger = CryptographicLedger()
        ledger.append("EVENT_A", "user_1", {"step": 1})
        ledger.append("EVENT_B", "user_1", {"step": 2})

        # Forge prev_hash of block 1
        block_1 = ledger._chain[1]
        ledger._chain[1] = type(block_1)(
            index=block_1.index,
            timestamp=block_1.timestamp,
            event_type=block_1.event_type,
            entity_id=block_1.entity_id,
            payload=block_1.payload,
            prev_hash="f" * 64,  # Forged linkage!
            block_hash=block_1.block_hash,
        )

        is_valid, err = ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertIn("chain break", str(err).lower())

    def test_rfc6962_domain_separation_invariants(self) -> None:
        """Verify RFC 6962 domain separation prefixes: 0x00 for leaves, 0x01 for internal nodes."""
        data = b"sample_event_payload"
        expected_leaf = hashlib.sha256(b"\x00" + data).hexdigest()
        actual_leaf = MerkleTree.hash_leaf(data)
        self.assertEqual(actual_leaf, expected_leaf)

        left = "a" * 64
        right = "b" * 64
        expected_node = hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
        actual_node = MerkleTree._hash_pair(left, right)
        self.assertEqual(actual_node, expected_node)

        # Second preimage resistance: leaf hash of (left || right) must never equal node hash of (left, right)
        leaf_of_concat = hashlib.sha256(b"\x00" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
        self.assertNotEqual(leaf_of_concat, actual_node)

    def test_sqlite_ledger_persistence_and_chain_hydration(self) -> None:
        """Verify that audit blocks persist to SQLite and hydrate on startup with chain integrity."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "ledger_test.db")

        try:
            storage1 = SQLiteStorage(db_path=db_path)
            dt1 = DualTrust(storage=storage1, secret_key="ledger-key")
            dt1.register_human("user_alice", social_credit=700, credits_balance=50)
            dt1.register_agent("agent_bob", initial_trust=0.80)
            dt1.reward_agent("agent_bob", weight=1.0)

            blocks_count1 = dt1.ledger.length
            self.assertEqual(blocks_count1, 3)
            root1 = dt1.get_merkle_root()

            valid1, err1 = dt1.verify_ledger_integrity()
            self.assertTrue(valid1)
            self.assertIsNone(err1)
            storage1.close()

            # Second instance: Re-open with new connection
            storage2 = SQLiteStorage(db_path=db_path)
            dt2 = DualTrust(storage=storage2, secret_key="ledger-key")

            # Verify chain hydration
            self.assertEqual(dt2.ledger.length, 3)
            self.assertEqual(dt2.get_merkle_root(), root1)
            valid2, err2 = dt2.verify_ledger_integrity()
            self.assertTrue(valid2)
            self.assertIsNone(err2)

            # Append block 4 in second session
            dt2.add_credits("user_alice", 25)
            self.assertEqual(dt2.ledger.length, 4)
            valid3, _ = dt2.verify_ledger_integrity()
            self.assertTrue(valid3)

            # Check that block 3 linked directly to block 2
            self.assertEqual(dt2.ledger._chain[3].prev_hash, dt2.ledger._chain[2].block_hash)
            storage2.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)


if __name__ == "__main__":
    unittest.main()

