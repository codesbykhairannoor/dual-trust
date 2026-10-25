"""Unit tests for the cryptographic hash-chained audit ledger."""

import unittest
from dualtrust.crypto_ledger import CryptographicLedger


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


if __name__ == "__main__":
    unittest.main()
