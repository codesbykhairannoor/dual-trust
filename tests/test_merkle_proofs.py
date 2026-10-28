"""Unit and cryptographic invariant tests for RFC 6962 Merkle tree inclusion proofs."""

import hashlib
import unittest
from dualtrust.crypto_ledger import MerkleTree
from dualtrust.engine import DualTrust
from dualtrust.models import ViolationType


class TestMerkleProofs(unittest.TestCase):
    """Rigorous verification of Merkle tree generation, inclusion proofs, and tamper detection."""

    def test_merkle_tree_empty(self) -> None:
        """An empty tree returns 64 zeroes as genesis root."""
        tree = MerkleTree([])
        self.assertEqual(tree.root, "0" * 64)

    def test_merkle_tree_single_leaf(self) -> None:
        """Single leaf tree root is the leaf itself with empty proof."""
        leaf = hashlib.sha256(b"event_0").hexdigest()
        tree = MerkleTree([leaf])
        self.assertEqual(tree.root, leaf)
        proof = tree.get_proof(0)
        self.assertEqual(proof, [])
        self.assertTrue(MerkleTree.verify_proof(leaf, proof, tree.root))

    def test_merkle_tree_various_sizes(self) -> None:
        """Verify inclusion proofs for power-of-two, odd, and prime leaf counts."""
        test_counts = [2, 3, 4, 5, 7, 8, 9, 15, 16, 23, 32]
        for count in test_counts:
            leaves = [hashlib.sha256(f"leaf_{i}".encode()).hexdigest() for i in range(count)]
            tree = MerkleTree(leaves)

            self.assertIsNotNone(tree.root)
            self.assertEqual(len(tree.root), 64)

            # Every leaf in the tree must produce a provably valid inclusion proof
            for idx, leaf in enumerate(leaves):
                proof = tree.get_proof(idx)
                is_valid = MerkleTree.verify_proof(leaf, proof, tree.root)
                self.assertTrue(
                    is_valid,
                    f"Merkle proof verification failed for leaf index {idx} in tree of size {count}.",
                )

    def test_tampered_leaf_rejected(self) -> None:
        """Tampering with the leaf hash must cause proof verification to fail."""
        leaves = [hashlib.sha256(f"audit_item_{i}".encode()).hexdigest() for i in range(6)]
        tree = MerkleTree(leaves)

        target_idx = 3
        valid_leaf = leaves[target_idx]
        proof = tree.get_proof(target_idx)

        # Flip last hex character
        tampered_leaf = valid_leaf[:-1] + ("0" if valid_leaf[-1] != "0" else "1")
        self.assertFalse(MerkleTree.verify_proof(tampered_leaf, proof, tree.root))

    def test_tampered_root_rejected(self) -> None:
        """Tampered root hash must fail proof verification."""
        leaves = [hashlib.sha256(f"audit_{i}".encode()).hexdigest() for i in range(4)]
        tree = MerkleTree(leaves)

        proof = tree.get_proof(1)
        tampered_root = "f" * 64
        self.assertFalse(MerkleTree.verify_proof(leaves[1], proof, tampered_root))

    def test_tampered_proof_sibling_rejected(self) -> None:
        """Tampering with an intermediate sibling hash in the proof path must fail."""
        leaves = [hashlib.sha256(f"txn_{i}".encode()).hexdigest() for i in range(8)]
        tree = MerkleTree(leaves)

        proof = tree.get_proof(2)
        self.assertTrue(MerkleTree.verify_proof(leaves[2], proof, tree.root))

        # Tamper with the first sibling
        sibling_hash, is_left = proof[0]
        corrupted_sibling = sibling_hash[:-1] + ("a" if sibling_hash[-1] != "a" else "b")
        tampered_proof = [(corrupted_sibling, is_left)] + proof[1:]
        self.assertFalse(MerkleTree.verify_proof(leaves[2], tampered_proof, tree.root))

    def test_out_of_bounds_leaf_index(self) -> None:
        """Negative index or index >= count must raise IndexError."""
        leaves = [hashlib.sha256(b"node").hexdigest() for _ in range(5)]
        tree = MerkleTree(leaves)
        with self.assertRaises(IndexError):
            tree.get_proof(-1)
        with self.assertRaises(IndexError):
            tree.get_proof(5)

    def test_engine_merkle_audit_workflow(self) -> None:
        """End-to-end integration: DualTrust engine generates and verifies Merkle audit proofs."""
        engine = DualTrust()

        engine.register_human(user_id="user_neo", social_credit=800, credits_balance=100)
        engine.register_agent(agent_id="agent_alpha", initial_trust=0.75)

        # Generate a sequence of audit trail events
        for i in range(10):
            engine.reward_agent(agent_id="agent_alpha", weight=1.0)
            engine.evaluate(user_id="user_neo", agent_id="agent_alpha", cost_credits=2, deduct_cost=True)

        engine.report_violation(
            agent_id="agent_alpha",
            violation_type=ViolationType.USER_RAGE,
            severity=1.5,
            details="Minor delay in smart-glass HUD projection",
        )

        merkle_root = engine.get_merkle_root()
        self.assertIsNotNone(merkle_root)
        self.assertEqual(len(merkle_root), 64)

        total_blocks = engine.ledger.length
        self.assertGreater(total_blocks, 10)

        # Cryptographically verify inclusion proof for every committed block
        for block_idx in range(total_blocks):
            leaf_hash, proof, root = engine.get_audit_proof(block_idx)
            self.assertEqual(root, merkle_root)

            # Verification against true root
            is_valid = engine.verify_audit_proof(leaf_hash, proof, root)
            self.assertTrue(is_valid, f"Proof verification failed for block {block_idx}")

            # Tampered verification must fail
            tampered_leaf = leaf_hash[:-1] + ("0" if leaf_hash[-1] != "0" else "1")
            self.assertFalse(engine.verify_audit_proof(tampered_leaf, proof, root))

    def test_cve_2012_2459_malleability_immunity(self) -> None:
        """Verify immunity against Bitcoin CVE-2012-2459 duplicate leaf malleability attacks."""
        a = hashlib.sha256(b"event_A").hexdigest()
        b = hashlib.sha256(b"event_B").hexdigest()
        c = hashlib.sha256(b"event_C").hexdigest()

        tree_odd = MerkleTree([a, b, c])
        tree_duplicated = MerkleTree([a, b, c, c])

        # Under direct promotion NodeHash(L)=L, tree_odd and tree_duplicated MUST produce distinct roots
        self.assertNotEqual(
            tree_odd.root,
            tree_duplicated.root,
            "Vulnerability detected: Odd node duplication caused root collision (CVE-2012-2459).",
        )

        # Inclusion proofs for all leaves in odd-sized tree must still verify rigorously
        for idx, leaf in enumerate([a, b, c]):
            proof = tree_odd.get_proof(idx)
            self.assertTrue(MerkleTree.verify_proof(leaf, proof, tree_odd.root))


if __name__ == "__main__":
    unittest.main()
