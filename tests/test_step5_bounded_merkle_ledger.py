"""Step 5: Tests for Unbounded RAM Growth mitigation in Merkle Audit Ledger:
Rolling epoch checkpoints, bounded in-memory sliding windows, disk offloading,
and thread-safe concurrent append chaining.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import os
import shutil
import tempfile
import unittest

from dualtrust.crypto_ledger import CryptographicLedger, EpochCheckpoint, MerkleTree
from dualtrust.engine import DualTrust
from dualtrust.storage import MemoryStorage, SQLiteStorage


class TestStep5BoundedMerkleLedger(unittest.TestCase):
    """Test suite validating bounded RAM usage, rolling epochs, and thread-safe Merkle ledger."""

    def test_bounded_in_memory_sliding_window(self):
        """Ledger must evict older blocks from RAM once max_in_memory_blocks is exceeded."""
        max_ram_blocks = 40
        epoch_size = 15
        total_to_append = 100

        ledger = CryptographicLedger(
            max_in_memory_blocks=max_ram_blocks,
            epoch_size=epoch_size,
        )

        for i in range(total_to_append):
            ledger.append(
                event_type="TEST_EVENT",
                entity_id=f"agent_{i % 5}",
                payload={"iteration": i, "data": "x" * 100},
            )

        # Total blocks recorded is 100
        self.assertEqual(ledger.total_blocks, total_to_append)
        self.assertEqual(ledger.length, total_to_append)

        # In-memory blocks are strictly bounded to max_ram_blocks (40)
        self.assertEqual(ledger.in_memory_blocks_count, max_ram_blocks)
        self.assertEqual(len(ledger.blocks), max_ram_blocks)

        # Check that 100 // 15 = 6 epochs are sealed, 10 blocks remain in active epoch
        self.assertEqual(ledger.epoch_count, 6)
        self.assertEqual(len(ledger.epochs), 6)

        # Verify epochs metadata
        ep0 = ledger.epochs[0]
        self.assertEqual(ep0.epoch_index, 0)
        self.assertEqual(ep0.start_block_index, 0)
        self.assertEqual(ep0.end_block_index, 14)
        self.assertEqual(ep0.block_count, 15)
        self.assertEqual(ep0.prev_epoch_hash, CryptographicLedger.GENESIS_EPOCH_HASH)
        self.assertTrue(ep0.verify_hash())

        ep1 = ledger.epochs[1]
        self.assertEqual(ep1.prev_epoch_hash, ep0.epoch_hash)
        self.assertTrue(ep1.verify_hash())

    def test_hierarchical_merkle_inclusion_proof_across_pruned_epochs(self):
        """Inclusion proof must verify cleanly for any block, even when evicted from RAM."""
        epoch_size = 10
        max_ram = 25
        total = 65

        ledger = CryptographicLedger(
            max_in_memory_blocks=max_ram,
            epoch_size=epoch_size,
        )

        blocks = []
        for i in range(total):
            b = ledger.append(
                event_type="EVAL",
                entity_id="entity_1",
                payload={"seq": i},
            )
            blocks.append(b)

        root = ledger.get_merkle_root()
        self.assertIsNotNone(root)
        self.assertEqual(len(root), 64)

        # Test block 5 (in Epoch 0, evicted from RAM since base_index is 65-25=40)
        leaf_5, proof_5, root_5 = ledger.get_inclusion_proof(5)
        self.assertEqual(root_5, root)
        self.assertEqual(leaf_5, blocks[5].block_hash)
        self.assertTrue(MerkleTree.verify_proof(leaf_5, proof_5, root))

        # Test block 35 (in Epoch 3, evicted from RAM)
        leaf_35, proof_35, root_35 = ledger.get_inclusion_proof(35)
        self.assertEqual(root_35, root)
        self.assertEqual(leaf_35, blocks[35].block_hash)
        self.assertTrue(MerkleTree.verify_proof(leaf_35, proof_35, root))

        # Test block 62 (in active unsealed epoch, currently in RAM)
        leaf_62, proof_62, root_62 = ledger.get_inclusion_proof(62)
        self.assertEqual(root_62, root)
        self.assertEqual(leaf_62, blocks[62].block_hash)
        self.assertTrue(MerkleTree.verify_proof(leaf_62, proof_62, root))

        # Tampered leaf hash must fail verification
        tampered_leaf = leaf_5[:-1] + ("0" if leaf_5[-1] != "0" else "1")
        self.assertFalse(MerkleTree.verify_proof(tampered_leaf, proof_5, root))

    def test_sqlite_offloading_and_streaming_integrity_verification(self):
        """Verify that streaming verification across disk offloaded blocks catches tampering."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "test_bounded_ledger.db")

        try:
            storage = SQLiteStorage(db_path=db_path)
            # Memory bounded to 20 blocks, epoch size 15, append 75 blocks
            ledger = CryptographicLedger(
                storage=storage,
                max_in_memory_blocks=20,
                epoch_size=15,
            )

            for i in range(75):
                ledger.append(
                    event_type="DISPATCH",
                    entity_id=f"agent_{i}",
                    payload={"work": i},
                )

            # In-memory window holds only 20 blocks
            self.assertEqual(ledger.in_memory_blocks_count, 20)
            self.assertEqual(ledger.total_blocks, 75)

            # Integrity verification streams all 75 blocks from SQLite
            is_valid, err = ledger.verify_integrity()
            self.assertTrue(is_valid)
            self.assertIsNone(err)

            # Tamper with an evicted block in SQLite (e.g. block index 7)
            with storage._write_transaction() as conn:
                conn.execute(
                    "UPDATE ledger_blocks SET payload_json = ? WHERE block_index = 7",
                    (json.dumps({"tampered": True}),),
                )

            # Re-verifying must detect the tampering on disk!
            is_valid_tampered, err_tampered = ledger.verify_integrity()
            self.assertFalse(is_valid_tampered)
            self.assertIn("tampered", str(err_tampered).lower())

            storage.close()
        finally:
            if os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception:
                    pass

    def test_concurrent_threads_atomic_chaining_zero_forks(self):
        """High-concurrency append stress test: 20 threads simultaneously appending must never fork the chain."""
        ledger = CryptographicLedger(max_in_memory_blocks=1000, epoch_size=50)
        num_threads = 16
        appends_per_thread = 50
        total_expected = num_threads * appends_per_thread  # 800 blocks

        def worker(thread_id: int):
            for i in range(appends_per_thread):
                ledger.append(
                    event_type="CONCURRENT_ACTION",
                    entity_id=f"thread_{thread_id}",
                    payload={"iter": i},
                )

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, t) for t in range(num_threads)]
            for f in futures:
                f.result()

        self.assertEqual(ledger.total_blocks, total_expected)
        self.assertEqual(ledger.latest_block.index, total_expected - 1)

        # Verify no forks occurred
        is_valid, err = ledger.verify_integrity()
        self.assertTrue(is_valid, f"Chain integrity failed: {err}")
        self.assertIsNone(err)

    def test_epoch_checkpoint_tamper_detection(self):
        """Tampering with a sealed EpochCheckpoint hash or previous link must break verification."""
        ledger = CryptographicLedger(max_in_memory_blocks=100, epoch_size=10)
        for i in range(35):
            ledger.append("EVENT", "agent_x", {"i": i})

        self.assertEqual(ledger.epoch_count, 3)

        # Baseline verification passes
        is_valid, err = ledger.verify_integrity()
        self.assertTrue(is_valid)

        # Tamper with epoch 1 prev_epoch_hash
        original_ep1 = ledger._epochs[1]
        forged_ep1 = EpochCheckpoint(
            epoch_index=original_ep1.epoch_index,
            start_block_index=original_ep1.start_block_index,
            end_block_index=original_ep1.end_block_index,
            merkle_root=original_ep1.merkle_root,
            prev_epoch_hash="e" * 64,  # Forged!
            epoch_hash=original_ep1.epoch_hash,
            block_count=original_ep1.block_count,
            timestamp=original_ep1.timestamp,
        )
        ledger._epochs[1] = forged_ep1

        is_valid, err = ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertIn("prev_epoch_hash mismatch", str(err))

    def test_dualtrust_engine_integration_with_bounded_ledger(self):
        """Verify DualTrust engine correctly instantiates and interacts with bounded ledger."""
        dt = DualTrust(
            max_in_memory_blocks=30,
            epoch_size=10,
        )

        dt.register_human("user_test", social_credit=800, credits_balance=500)
        dt.register_agent("agent_test", initial_trust=0.90)

        for _ in range(35):
            dt.evaluate(user_id="user_test", agent_id="agent_test", cost_credits=1, deduct_cost=True)

        # Total events > 35
        self.assertGreater(dt.ledger.total_blocks, 35)
        # Memory bounded to 30
        self.assertLessEqual(dt.ledger.in_memory_blocks_count, 30)

        # Merkle root computation works
        root = dt.get_merkle_root()
        self.assertEqual(len(root), 64)

        # Integrity verification passes
        is_valid, err = dt.verify_ledger_integrity()
        self.assertTrue(is_valid, f"Verification failed: {err}")


if __name__ == "__main__":
    unittest.main()
