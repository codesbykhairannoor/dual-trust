"""Cryptographic hash-chained audit ledger and Merkle tree proofs for tamper-evident event logging."""

from dataclasses import asdict, dataclass, field
import hashlib
import json
import threading
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


@dataclass(frozen=True)
class EpochCheckpoint:
    """Cryptographically sealed checkpoint for a completed epoch of audit blocks."""

    epoch_index: int
    start_block_index: int
    end_block_index: int
    merkle_root: str
    prev_epoch_hash: str
    epoch_hash: str
    block_count: int
    timestamp: float

    @classmethod
    def create(
        cls,
        epoch_index: int,
        start_block_index: int,
        end_block_index: int,
        merkle_root: str,
        prev_epoch_hash: str,
        block_count: int,
        timestamp: Optional[float] = None,
    ) -> "EpochCheckpoint":
        t = timestamp if timestamp is not None else time.time()
        preimage = (
            f"{epoch_index}|{start_block_index}|{end_block_index}|{merkle_root}|"
            f"{prev_epoch_hash}|{block_count}|{t:.6f}"
        )
        epoch_hash = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        return cls(
            epoch_index=epoch_index,
            start_block_index=start_block_index,
            end_block_index=end_block_index,
            merkle_root=merkle_root,
            prev_epoch_hash=prev_epoch_hash,
            epoch_hash=epoch_hash,
            block_count=block_count,
            timestamp=t,
        )

    def verify_hash(self) -> bool:
        """Verify that the epoch's hash recalculates accurately from its preimage."""
        preimage = (
            f"{self.epoch_index}|{self.start_block_index}|{self.end_block_index}|"
            f"{self.merkle_root}|{self.prev_epoch_hash}|{self.block_count}|{self.timestamp:.6f}"
        )
        expected = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        return self.epoch_hash == expected


class CryptographicLedger:
    """Maintains an append-only, SHA-256 hash-chained sequence of governance events
    with thread safety, rolling epoch checkpointing, and bounded in-memory sliding windows."""

    GENESIS_HASH = "0" * 64
    GENESIS_EPOCH_HASH = "0" * 64

    def __init__(
        self,
        storage: Optional[Any] = None,
        max_in_memory_blocks: int = 5000,
        epoch_size: int = 1000,
    ) -> None:
        self._lock = threading.RLock()
        self._storage = storage
        self.max_in_memory_blocks = max(10, max_in_memory_blocks) if max_in_memory_blocks else None
        self.epoch_size = max(2, epoch_size)

        self._chain: List[AuditBlock] = []
        self._base_index: int = 0
        self._total_blocks: int = 0
        self._latest_block: Optional[AuditBlock] = None
        self._latest_block_hash: str = self.GENESIS_HASH

        self._epochs: List[EpochCheckpoint] = []
        self._epoch_trees: List[MerkleTree] = []
        self._current_epoch_hashes: List[str] = []

        if self._storage is not None and hasattr(self._storage, "get_ledger_blocks"):
            persisted = self._storage.get_ledger_blocks()
            if persisted:
                for b in persisted:
                    self._append_internal(b, persist=False)

    def _append_internal(self, block: AuditBlock, persist: bool = True) -> None:
        # Note: must be called with self._lock acquired
        self._chain.append(block)
        self._current_epoch_hashes.append(block.block_hash)
        self._latest_block = block
        self._latest_block_hash = block.block_hash
        self._total_blocks += 1

        if len(self._current_epoch_hashes) >= self.epoch_size:
            self._seal_epoch()

        if self.max_in_memory_blocks and len(self._chain) > self.max_in_memory_blocks:
            excess = len(self._chain) - self.max_in_memory_blocks
            self._chain = self._chain[excess:]
            self._base_index += excess

        if persist and self._storage is not None and hasattr(self._storage, "save_ledger_block"):
            self._storage.save_ledger_block(block)

    def _seal_epoch(self) -> Optional[EpochCheckpoint]:
        # Note: must be called with self._lock acquired
        if not self._current_epoch_hashes:
            return None
        epoch_idx = len(self._epochs)
        epoch_hashes = list(self._current_epoch_hashes)
        tree = MerkleTree(epoch_hashes)
        self._epoch_trees.append(tree)

        start_idx = self._total_blocks - len(epoch_hashes)
        end_idx = self._total_blocks - 1
        prev_hash = self._epochs[-1].epoch_hash if self._epochs else self.GENESIS_EPOCH_HASH

        checkpoint = EpochCheckpoint.create(
            epoch_index=epoch_idx,
            start_block_index=start_idx,
            end_block_index=end_idx,
            merkle_root=tree.root,
            prev_epoch_hash=prev_hash,
            block_count=len(epoch_hashes),
        )
        self._epochs.append(checkpoint)
        self._current_epoch_hashes = []
        return checkpoint

    def checkpoint_epoch(self) -> Optional[EpochCheckpoint]:
        """Manually seal the current active blocks into an EpochCheckpoint."""
        with self._lock:
            return self._seal_epoch()

    def append(
        self,
        event_type: str,
        entity_id: str,
        payload: Dict[str, Any],
        timestamp: Optional[float] = None,
    ) -> AuditBlock:
        """Append a new verified block to the hash chain and persist to storage if configured."""
        with self._lock:
            index = self._total_blocks
            prev_hash = self._latest_block_hash
            block = AuditBlock.create(
                index=index,
                event_type=event_type,
                entity_id=entity_id,
                payload=payload,
                prev_hash=prev_hash,
                timestamp=timestamp,
            )
            self._append_internal(block, persist=True)
            return block

    @property
    def latest_block(self) -> Optional[AuditBlock]:
        """Return the most recently committed block, or None if empty."""
        with self._lock:
            return self._latest_block

    @property
    def length(self) -> int:
        """Return total blocks in the ledger across all history."""
        with self._lock:
            return self._total_blocks

    @property
    def total_blocks(self) -> int:
        with self._lock:
            return self._total_blocks

    @property
    def in_memory_blocks_count(self) -> int:
        with self._lock:
            return len(self._chain)

    @property
    def epochs(self) -> List[EpochCheckpoint]:
        with self._lock:
            return list(self._epochs)

    @property
    def epoch_count(self) -> int:
        with self._lock:
            return len(self._epochs)

    @property
    def blocks(self) -> List[AuditBlock]:
        """Return a copy of recent audit blocks in the in-memory window (or all if unpruned)."""
        with self._lock:
            return list(self._chain)

    def get_blocks(self) -> List[AuditBlock]:
        """Return a copy of recent audit blocks in chronological order."""
        with self._lock:
            return list(self._chain)

    def get_all_blocks(self) -> List[AuditBlock]:
        """Return all audit blocks across entire history, loading from storage if pruned."""
        with self._lock:
            if self._base_index == 0 or self._storage is None:
                return list(self._chain)
            if hasattr(self._storage, "get_ledger_blocks"):
                return self._storage.get_ledger_blocks()
            return list(self._chain)

    def get_block(self, index: int) -> Optional[AuditBlock]:
        """Retrieve an audit block by global index."""
        with self._lock:
            if index < 0 or index >= self._total_blocks:
                return None
            local_idx = index - self._base_index
            if 0 <= local_idx < len(self._chain):
                return self._chain[local_idx]
            if self._storage is not None and hasattr(self._storage, "get_ledger_block"):
                return self._storage.get_ledger_block(index)
            elif self._storage is not None and hasattr(self._storage, "get_ledger_blocks_range"):
                blocks = self._storage.get_ledger_blocks_range(index, 1)
                return blocks[0] if blocks else None
            return None

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """Cryptographically verify the entire chain from genesis to head."""
        with self._lock:
            if self._total_blocks == 0:
                return True, None

            # 1. Verify Epoch Checkpoint Chain
            for i, epoch in enumerate(self._epochs):
                expected_prev = self.GENESIS_EPOCH_HASH if i == 0 else self._epochs[i - 1].epoch_hash
                if epoch.prev_epoch_hash != expected_prev:
                    return False, f"Epoch {i} prev_epoch_hash mismatch: expected {expected_prev}, got {epoch.prev_epoch_hash}"
                if not epoch.verify_hash():
                    return False, f"Epoch {i} hash verification failed; checkpoint was tampered with."

            # 2. Verify Block Sequential Chain
            if self._base_index == 0:
                genesis = self._chain[0]
                if genesis.index != 0:
                    return False, "Genesis block index is not 0."
                if genesis.prev_hash != self.GENESIS_HASH:
                    return False, f"Genesis prev_hash mismatch: expected {self.GENESIS_HASH}, got {genesis.prev_hash}"
                if not genesis.verify_hash():
                    return False, "Genesis block internal hash computation failed."

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
            else:
                if self._storage is not None and hasattr(self._storage, "get_ledger_blocks_range"):
                    batch_size = 500
                    current_idx = 0
                    prev_block_hash = self.GENESIS_HASH

                    while current_idx < self._total_blocks:
                        batch = self._storage.get_ledger_blocks_range(current_idx, batch_size)
                        if not batch:
                            return False, f"Missing blocks from storage at index {current_idx}."
                        for block in batch:
                            if block.index != current_idx:
                                return False, f"Block {current_idx} index mismatch: expected {current_idx}, got {block.index}."
                            if block.prev_hash != prev_block_hash:
                                return (
                                    False,
                                    f"Chain break at block {current_idx}: prev_hash ({block.prev_hash[:16]}...) does not match "
                                    f"previous block hash ({prev_block_hash[:16]}...).",
                                )
                            if not block.verify_hash():
                                return False, f"Block {current_idx} payload was tampered with; hash verification failed."
                            prev_block_hash = block.block_hash
                            current_idx += 1
                else:
                    if self._chain:
                        for i in range(1, len(self._chain)):
                            current = self._chain[i]
                            previous = self._chain[i - 1]
                            if current.index != previous.index + 1:
                                return False, f"Block {current.index} index mismatch."
                            if current.prev_hash != previous.block_hash:
                                return False, f"Chain break at block {current.index}."
                            if not current.verify_hash():
                                return False, f"Block {current.index} payload was tampered with."

            return True, None

    def get_merkle_root(self) -> str:
        """Return the current Merkle root representing all audit blocks in the ledger."""
        with self._lock:
            if not self._epochs:
                if not self._current_epoch_hashes:
                    return "0" * 64
                return MerkleTree(self._current_epoch_hashes).root

            epoch_roots = [ep.merkle_root for ep in self._epochs]
            if self._current_epoch_hashes:
                epoch_roots.append(MerkleTree(self._current_epoch_hashes).root)
            return MerkleTree(epoch_roots).root

    def get_merkle_tree(self) -> MerkleTree:
        """Generate a Merkle tree encompassing all committed audit blocks or epoch roots."""
        with self._lock:
            if not self._epochs:
                return MerkleTree(self._current_epoch_hashes)
            epoch_roots = [ep.merkle_root for ep in self._epochs]
            if self._current_epoch_hashes:
                epoch_roots.append(MerkleTree(self._current_epoch_hashes).root)
            return MerkleTree(epoch_roots)

    def get_inclusion_proof(self, block_index: int) -> Tuple[str, List[Tuple[str, bool]], str]:
        """Generate a Merkle inclusion proof for a block at block_index.

        Returns:
            Tuple of (leaf_hash: str, proof: List[Tuple[str, bool]], root_hash: str).
        """
        with self._lock:
            if block_index < 0 or block_index >= self._total_blocks:
                raise IndexError(f"Block index {block_index} out of bounds (0 to {self._total_blocks - 1}).")

            if not self._epochs:
                tree = MerkleTree(self._current_epoch_hashes)
                leaf_hash = self._current_epoch_hashes[block_index]
                proof = tree.get_proof(block_index)
                return leaf_hash, proof, tree.root

            num_sealed_blocks = len(self._epochs) * self.epoch_size
            if block_index < num_sealed_blocks:
                epoch_idx = block_index // self.epoch_size
                local_idx = block_index % self.epoch_size
                if epoch_idx < len(self._epoch_trees):
                    intra_tree = self._epoch_trees[epoch_idx]
                    intra_proof = intra_tree.get_proof(local_idx)
                    leaf_hash = intra_tree.leaf_hashes[local_idx]
                else:
                    start_i = epoch_idx * self.epoch_size
                    if self._storage is not None and hasattr(self._storage, "get_ledger_blocks_range"):
                        blocks = self._storage.get_ledger_blocks_range(start_i, self.epoch_size)
                        hashes = [b.block_hash for b in blocks]
                    else:
                        hashes = [b.block_hash for b in self._chain if start_i <= b.index < start_i + self.epoch_size]
                    intra_tree = MerkleTree(hashes)
                    intra_proof = intra_tree.get_proof(local_idx)
                    leaf_hash = intra_tree.leaf_hashes[local_idx]
            else:
                epoch_idx = len(self._epochs)
                local_idx = block_index - num_sealed_blocks
                intra_tree = MerkleTree(self._current_epoch_hashes)
                intra_proof = intra_tree.get_proof(local_idx)
                leaf_hash = self._current_epoch_hashes[local_idx]

            epoch_roots = [ep.merkle_root for ep in self._epochs]
            if self._current_epoch_hashes:
                epoch_roots.append(MerkleTree(self._current_epoch_hashes).root)
            super_tree = MerkleTree(epoch_roots)
            inter_proof = super_tree.get_proof(epoch_idx)

            composite_proof = intra_proof + inter_proof
            return leaf_hash, composite_proof, super_tree.root

    def get_events(self, entity_id: Optional[str] = None, limit: int = 50) -> List[AuditBlock]:
        """Retrieve recent blocks, optionally filtered by entity identifier."""
        with self._lock:
            if entity_id:
                filtered = [b for b in self._chain if b.entity_id == entity_id]
            else:
                filtered = list(self._chain)
            return filtered[-limit:]

