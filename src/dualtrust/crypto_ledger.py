"""Cryptographic hash-chained audit ledger and Merkle tree proofs for tamper-evident event logging."""

from dataclasses import asdict, dataclass, field
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass(frozen=True)
class AuditBlock:
    """An immutable, cryptographically chained audit record."""

    index: int
    timestamp: float
    event_type: str
    entity_id: str
    payload: Dict[str, Any]
    prev_hash: str
    block_hash: str

    @classmethod
    def create(
        cls,
        index: int,
        event_type: str,
        entity_id: str,
        payload: Dict[str, Any],
        prev_hash: str,
        timestamp: Optional[float] = None,
    ) -> "AuditBlock":
        """Compute the deterministic SHA-256 hash and construct a block."""
        block_time = timestamp if timestamp is not None else time.time()
        # Sort payload keys to ensure deterministic JSON serialization
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        raw_preimage = (
            f"{index}|{block_time:.6f}|{event_type}|{entity_id}|{prev_hash}|{canonical_payload}"
        )
        block_hash = hashlib.sha256(raw_preimage.encode("utf-8")).hexdigest()

        return cls(
            index=index,
            timestamp=block_time,
            event_type=event_type,
            entity_id=entity_id,
            payload=payload,
            prev_hash=prev_hash,
            block_hash=block_hash,
        )

    def verify_hash(self) -> bool:
        """Verify that the block's content recalculates to its declared hash."""
        canonical_payload = json.dumps(self.payload, sort_keys=True, separators=(",", ":"))
        raw_preimage = (
            f"{self.index}|{self.timestamp:.6f}|{self.event_type}|{self.entity_id}|{self.prev_hash}|{canonical_payload}"
        )
        expected = hashlib.sha256(raw_preimage.encode("utf-8")).hexdigest()
        return self.block_hash == expected


class MerkleTree:
    """Binary cryptographic Merkle tree for compact audit inclusion proofs (RFC 6962 compliant)."""

    def __init__(self, leaf_hashes: List[str]) -> None:
        """Build a Merkle tree from an ordered list of leaf hashes."""
        self.leaf_hashes = list(leaf_hashes)
        self.layers: List[List[str]] = []
        self._build_tree()

    @staticmethod
    def hash_leaf(data: Union[str, bytes]) -> str:
        """Compute RFC 6962 leaf hash with 0x00 domain separation prefix: SHA-256(0x00 || data)."""
        payload = data if isinstance(data, bytes) else data.encode("utf-8")
        return hashlib.sha256(b"\x00" + payload).hexdigest()

    @staticmethod
    def _hash_pair(left: str, right: str) -> str:
        """Hash child nodes using RFC 6962 0x01 internal node domain separation prefix: SHA-256(0x01 || left || right)."""
        try:
            left_bytes = bytes.fromhex(left) if len(left) == 64 else left.encode("utf-8")
            right_bytes = bytes.fromhex(right) if len(right) == 64 else right.encode("utf-8")
        except ValueError:
            left_bytes = left.encode("utf-8")
            right_bytes = right.encode("utf-8")
        return hashlib.sha256(b"\x01" + left_bytes + right_bytes).hexdigest()

    @classmethod
    def hash_children(cls, left: str, right: str) -> str:
        """Public alias for hashing two nodes under RFC 6962 domain separation."""
        return cls._hash_pair(left, right)

    def _build_tree(self) -> None:
        """Construct hierarchical layers from leaves to root."""
        if not self.leaf_hashes:
            self.layers = [["0" * 64]]
            return

        current_layer = list(self.leaf_hashes)
        self.layers.append(current_layer)

        while len(current_layer) > 1:
            next_layer: List[str] = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                # If odd number of nodes, duplicate the last node
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                next_layer.append(self._hash_pair(left, right))
            self.layers.append(next_layer)
            current_layer = next_layer

    @property
    def root(self) -> str:
        """Return the Merkle root hash."""
        return self.layers[-1][0] if self.layers else "0" * 64

    def get_proof(self, leaf_index: int) -> List[Tuple[str, bool]]:
        """Generate a Merkle inclusion proof for the leaf at leaf_index.

        Returns:
            List of (sibling_hash: str, is_left: bool) tuples leading to the root.
        """
        if leaf_index < 0 or leaf_index >= len(self.leaf_hashes):
            raise IndexError(f"Leaf index {leaf_index} out of bounds (0 to {len(self.leaf_hashes)-1}).")

        proof: List[Tuple[str, bool]] = []
        idx = leaf_index

        for layer_idx in range(len(self.layers) - 1):
            layer = self.layers[layer_idx]
            is_odd = (idx % 2 == 1)

            if is_odd:
                sibling_idx = idx - 1
                is_sibling_left = True
            else:
                sibling_idx = idx + 1 if idx + 1 < len(layer) else idx
                is_sibling_left = False

            proof.append((layer[sibling_idx], is_sibling_left))
            idx = idx // 2

        return proof

    @classmethod
    def verify_proof(cls, leaf_hash: str, proof: List[Tuple[str, bool]], root_hash: str) -> bool:
        """Verify that a leaf hash belongs to a Merkle tree with the given root."""
        current = leaf_hash
        for sibling, is_left in proof:
            if is_left:
                current = cls._hash_pair(sibling, current)
            else:
                current = cls._hash_pair(current, sibling)
        return current == root_hash


class CryptographicLedger:
    """Maintains an append-only, SHA-256 hash-chained sequence of governance events."""

    GENESIS_HASH = "0" * 64

    def __init__(self, storage: Optional[Any] = None) -> None:
        self._chain: List[AuditBlock] = []
        self._storage = storage
        if self._storage is not None and hasattr(self._storage, "get_ledger_blocks"):
            persisted = self._storage.get_ledger_blocks()
            if persisted:
                self._chain = list(persisted)

    def append(
        self,
        event_type: str,
        entity_id: str,
        payload: Dict[str, Any],
        timestamp: Optional[float] = None,
    ) -> AuditBlock:
        """Append a new verified block to the hash chain and persist to storage if configured."""
        index = len(self._chain)
        prev_hash = self._chain[-1].block_hash if self._chain else self.GENESIS_HASH
        block = AuditBlock.create(
            index=index,
            event_type=event_type,
            entity_id=entity_id,
            payload=payload,
            prev_hash=prev_hash,
            timestamp=timestamp,
        )
        self._chain.append(block)
        if self._storage is not None and hasattr(self._storage, "save_ledger_block"):
            self._storage.save_ledger_block(block)
        return block

    @property
    def latest_block(self) -> Optional[AuditBlock]:
        """Return the most recently committed block, or None if empty."""
        return self._chain[-1] if self._chain else None

    @property
    def length(self) -> int:
        """Return total blocks in the ledger."""
        return len(self._chain)

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """Cryptographically verify the entire chain from genesis to head.

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str]).
        """
        if not self._chain:
            return True, None

        # Verify Genesis Block
        genesis = self._chain[0]
        if genesis.index != 0:
            return False, "Genesis block index is not 0."
        if genesis.prev_hash != self.GENESIS_HASH:
            return False, f"Genesis prev_hash mismatch: expected {self.GENESIS_HASH}, got {genesis.prev_hash}"
        if not genesis.verify_hash():
            return False, "Genesis block internal hash computation failed."

        # Verify Sequential Linkages
        for i in range(1, len(self._chain)):
            current = self._chain[i]
            previous = self._chain[i - 1]

            if current.index != i:
                return False, f"Block {i} index mismatch: expected {i}, got {current.index}."
            if current.prev_hash != previous.block_hash:
                return (
                    False,
                    f"Chain break at block {i}: prev_hash ({current.prev_hash[:16]}...) does not match "
                    f"previous block hash ({previous.block_hash[:16]}...).",
                )
            if not current.verify_hash():
                return False, f"Block {i} payload was tampered with; hash verification failed."

        return True, None

    def get_merkle_tree(self) -> MerkleTree:
        """Generate a Merkle tree encompassing all committed audit blocks."""
        leaf_hashes = [b.block_hash for b in self._chain]
        return MerkleTree(leaf_hashes)

    def get_merkle_root(self) -> str:
        """Return the current Merkle root representing all audit blocks in the ledger."""
        return self.get_merkle_tree().root

    def get_inclusion_proof(self, block_index: int) -> Tuple[str, List[Tuple[str, bool]], str]:
        """Generate a Merkle inclusion proof for a block at block_index.

        Returns:
            Tuple of (leaf_hash: str, proof: List[Tuple[str, bool]], root_hash: str).
        """
        tree = self.get_merkle_tree()
        leaf_hash = self._chain[block_index].block_hash
        proof = tree.get_proof(block_index)
        return leaf_hash, proof, tree.root

    def get_events(self, entity_id: Optional[str] = None, limit: int = 50) -> List[AuditBlock]:
        """Retrieve recent blocks, optionally filtered by entity identifier."""
        if entity_id:
            filtered = [b for b in self._chain if b.entity_id == entity_id]
        else:
            filtered = list(self._chain)
        return filtered[-limit:]
