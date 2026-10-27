"""Storage backends for persisting profiles, reputation states, and audit trails."""

from abc import ABC, abstractmethod
import contextlib
import json
import math
import random
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional
from dualtrust.exceptions import EntityNotFoundError
from dualtrust.models import (
    AgentProfile,
    AgentStatus,
    ChallengeStatus,
    DelegationMandate,
    EpisodicReflection,
    HumanApprovalChallenge,
    HumanProfile,
    HumanTier,
    MandateStatus,
    ViolationEvent,
    ViolationType,
)
from dualtrust.crypto_ledger import AuditBlock


class StorageBackend(ABC):
    """Abstract interface defining required storage operations for DualTrust."""

    @abstractmethod
    def save_agent(self, profile: AgentProfile) -> None:
        """Persist or update an agent profile."""

    @abstractmethod
    def get_agent(self, agent_id: str) -> Optional[AgentProfile]:
        """Retrieve an agent profile by unique identifier."""

    @abstractmethod
    def save_human(self, profile: HumanProfile) -> None:
        """Persist or update a human social credit profile."""

    @abstractmethod
    def get_human(self, user_id: str) -> Optional[HumanProfile]:
        """Retrieve a human profile by unique identifier."""

    @abstractmethod
    def deduct_credits(self, user_id: str, amount: int) -> bool:
        """Atomically deduct spendable credits if balance >= amount.

        Returns:
            True if deduction succeeded, False if insufficient balance or user not found.
        """

    @abstractmethod
    def add_credits(self, user_id: str, amount: int) -> int:
        """Atomically add spendable credits to a human profile.

        Returns:
            The updated credit balance.
        """

    @abstractmethod
    def record_violation(self, event: ViolationEvent) -> None:
        """Append a violation record to the audit trail."""

    @abstractmethod
    def get_violations(
        self, agent_id: Optional[str] = None, limit: int = 50
    ) -> List[ViolationEvent]:
        """Retrieve recent violations, optionally filtered by agent."""

    @abstractmethod
    def save_reflection(self, reflection: EpisodicReflection) -> None:
        """Persist an episodic self-reflection lesson (Princeton Reflexion)."""

    @abstractmethod
    def get_reflections(
        self, agent_id: str, limit: int = 5
    ) -> List[EpisodicReflection]:
        """Retrieve recent episodic reflections for an agent, newest first."""

    @abstractmethod
    def save_challenge(self, challenge: HumanApprovalChallenge) -> None:
        """Persist a human approval challenge token (NIST SP 800-63B)."""

    @abstractmethod
    def get_challenge(self, challenge_id: str) -> Optional[HumanApprovalChallenge]:
        """Retrieve a human approval challenge by identifier."""

    @abstractmethod
    def update_challenge_status(
        self,
        challenge_id: str,
        status: ChallengeStatus,
        resolved_at: float,
        reason: str = "",
    ) -> bool:
        """Update the status of a challenge atomically (single-use enforcement)."""

    @abstractmethod
    def save_ledger_block(self, block: AuditBlock) -> None:
        """Persist a cryptographically chained audit block."""

    @abstractmethod
    def get_ledger_blocks(self) -> List[AuditBlock]:
        """Retrieve all audit blocks in chronological order from genesis."""

    def get_ledger_block(self, block_index: int) -> Optional[AuditBlock]:
        """Retrieve a single audit block by index."""
        blocks = self.get_ledger_blocks_range(block_index, 1)
        return blocks[0] if blocks else None

    def get_ledger_blocks_range(self, start_index: int, limit: int) -> List[AuditBlock]:
        """Retrieve a slice of audit blocks starting at start_index up to limit."""
        all_blocks = self.get_ledger_blocks()
        return all_blocks[start_index : start_index + limit]

    @abstractmethod
    def save_mandate(self, mandate: DelegationMandate) -> None:
        """Persist or update an agent-to-agent delegation mandate."""

    @abstractmethod
    def get_mandate(self, mandate_id: str) -> Optional[DelegationMandate]:
        """Retrieve a delegation mandate by unique identifier."""

    @abstractmethod
    def get_all_mandates(self) -> List[DelegationMandate]:
        """Retrieve all delegation mandates."""


class MemoryStorage(StorageBackend):
    """Thread-safe in-memory storage backend."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._agents: Dict[str, AgentProfile] = {}
        self._humans: Dict[str, HumanProfile] = {}
        self._violations: List[ViolationEvent] = []
        self._reflections: Dict[str, List[EpisodicReflection]] = {}
        self._challenges: Dict[str, HumanApprovalChallenge] = {}
        self._ledger_blocks: List[AuditBlock] = []
        self._mandates: Dict[str, DelegationMandate] = {}

    def save_agent(self, profile: AgentProfile) -> None:
        with self._lock:
            self._agents[profile.agent_id] = profile

    def get_agent(self, agent_id: str) -> Optional[AgentProfile]:
        with self._lock:
            return self._agents.get(agent_id)

    def save_human(self, profile: HumanProfile) -> None:
        with self._lock:
            self._humans[profile.user_id] = profile

    def get_human(self, user_id: str) -> Optional[HumanProfile]:
        with self._lock:
            return self._humans.get(user_id)

    def deduct_credits(self, user_id: str, amount: int) -> bool:
        """Atomically deduct spendable credits if balance >= amount."""
        if not isinstance(amount, (int, float)) or (isinstance(amount, float) and (math.isnan(amount) or math.isinf(amount))):
            raise ValueError("Deduct amount must be a finite number.")
        if amount < 0:
            raise ValueError("Deduct amount cannot be negative.")
        amount = int(amount)
        if amount == 0:
            return True
        with self._lock:
            human = self._humans.get(user_id)
            if not human:
                return False
            if human.credits_balance < amount:
                return False
            human.credits_balance -= amount
            human.last_updated = time.time()
            return True

    def add_credits(self, user_id: str, amount: int) -> int:
        """Atomically deposit spendable credits."""
        if not isinstance(amount, (int, float)) or (isinstance(amount, float) and (math.isnan(amount) or math.isinf(amount))):
            raise ValueError("Deposit amount must be a finite number.")
        if amount <= 0:
            raise ValueError(f"Deposit amount must be positive, got {amount}")
        amount = int(amount)
        with self._lock:
            human = self._humans.get(user_id)
            if not human:
                raise EntityNotFoundError(f"Human '{user_id}' not found.")
            human.credits_balance += amount
            human.last_updated = time.time()
            return human.credits_balance

    def record_violation(self, event: ViolationEvent) -> None:
        with self._lock:
            self._violations.append(event)

    def get_violations(
        self, agent_id: Optional[str] = None, limit: int = 50
    ) -> List[ViolationEvent]:
        with self._lock:
            if agent_id:
                filtered = [v for v in self._violations if v.agent_id == agent_id]
            else:
                filtered = list(self._violations)
            return filtered[-limit:]

    def save_reflection(self, reflection: EpisodicReflection) -> None:
        with self._lock:
            self._reflections.setdefault(reflection.agent_id, []).append(reflection)

    def get_reflections(
        self, agent_id: str, limit: int = 5
    ) -> List[EpisodicReflection]:
        with self._lock:
            agent_refs = self._reflections.get(agent_id, [])
            return list(reversed(agent_refs))[:limit]

    def save_challenge(self, challenge: HumanApprovalChallenge) -> None:
        with self._lock:
            self._challenges[challenge.challenge_id] = challenge

    def get_challenge(self, challenge_id: str) -> Optional[HumanApprovalChallenge]:
        with self._lock:
            return self._challenges.get(challenge_id)

    def update_challenge_status(
        self,
        challenge_id: str,
        status: ChallengeStatus,
        resolved_at: float,
        reason: str = "",
    ) -> bool:
        with self._lock:
            ch = self._challenges.get(challenge_id)
            if not ch:
                return False
            # Enforce valid state transitions
            if ch.status == ChallengeStatus.PENDING:
                if status not in (ChallengeStatus.APPROVED, ChallengeStatus.REJECTED, ChallengeStatus.EXPIRED):
                    return False
            elif ch.status == ChallengeStatus.APPROVED:
                if status not in (ChallengeStatus.CONSUMED, ChallengeStatus.EXPIRED):
                    return False
            else:
                return False
            updated = HumanApprovalChallenge(
                challenge_id=ch.challenge_id,
                user_id=ch.user_id,
                agent_id=ch.agent_id,
                action_name=ch.action_name,
                arguments_hash=ch.arguments_hash,
                cost_credits=ch.cost_credits,
                created_at=ch.created_at,
                expires_at=ch.expires_at,
                token=ch.token,
                status=status,
                resolved_at=resolved_at,
                resolution_reason=reason,
            )
            self._challenges[challenge_id] = updated
            return True

    def save_ledger_block(self, block: AuditBlock) -> None:
        with self._lock:
            self._ledger_blocks.append(block)

    def get_ledger_blocks(self) -> List[AuditBlock]:
        with self._lock:
            return list(self._ledger_blocks)

    def get_ledger_block(self, block_index: int) -> Optional[AuditBlock]:
        with self._lock:
            if 0 <= block_index < len(self._ledger_blocks):
                return self._ledger_blocks[block_index]
            return None

    def get_ledger_blocks_range(self, start_index: int, limit: int) -> List[AuditBlock]:
        with self._lock:
            return self._ledger_blocks[start_index : start_index + limit]

    def save_mandate(self, mandate: DelegationMandate) -> None:
        with self._lock:
            self._mandates[mandate.mandate_id] = mandate

    def get_mandate(self, mandate_id: str) -> Optional[DelegationMandate]:
        with self._lock:
            return self._mandates.get(mandate_id)

    def get_all_mandates(self) -> List[DelegationMandate]:
        with self._lock:
            return list(self._mandates.values())


class SQLiteStorage(StorageBackend):
    """Persistent, thread-safe SQLite storage backend with thread-local connection pooling,
    WAL mode, busy timeouts, immediate write transactions, and cross-process data_version cache synchronization."""

    def __init__(self, db_path: str = "dualtrust.db") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._local = threading.local()
        self._all_conns: List[sqlite3.Connection] = []
        self._cache_agents: Dict[str, AgentProfile] = {}
        self._cache_humans: Dict[str, HumanProfile] = {}
        self._last_data_version: int = -1
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 15000;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA cache_size = -64000;")
            self._local.conn = conn
            with self._lock:
                self._all_conns.append(conn)
        return conn

    @contextlib.contextmanager
    def _connection(self):
        conn = self._get_connection()
        yield conn

    @contextlib.contextmanager
    def _write_transaction(self, max_retries: int = 5, initial_backoff: float = 0.02):
        """Execute a write transaction using BEGIN IMMEDIATE to avoid lock escalation deadlocks."""
        with self._lock:
            conn = self._get_connection()
            depth = getattr(self._local, "tx_depth", 0)
            if depth > 0:
                self._local.tx_depth += 1
                try:
                    yield conn
                finally:
                    self._local.tx_depth -= 1
                return

            attempt = 0
            while True:
                try:
                    conn.execute("BEGIN IMMEDIATE;")
                    break
                except sqlite3.OperationalError as e:
                    err_msg = str(e).lower()
                    if "locked" in err_msg or "busy" in err_msg:
                        attempt += 1
                        if attempt > max_retries:
                            raise
                        backoff = (initial_backoff * (2 ** (attempt - 1))) + random.uniform(0.005, 0.02)
                        time.sleep(backoff)
                    else:
                        raise

            self._local.tx_depth = 1
            try:
                yield conn
                conn.execute("COMMIT;")
                try:
                    cur = conn.execute("PRAGMA data_version;")
                    row = cur.fetchone()
                    if row:
                        self._last_data_version = int(row[0])
                except Exception:
                    pass
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise
            finally:
                self._local.tx_depth = 0

    def _copy_agent(self, profile: AgentProfile) -> AgentProfile:
        return AgentProfile(
            agent_id=profile.agent_id,
            alpha=profile.alpha,
            beta=profile.beta,
            trust_score=profile.trust_score,
            status=profile.status,
            violations_count=profile.violations_count,
            consecutive_clean_actions=profile.consecutive_clean_actions,
            minor_infractions=profile.minor_infractions,
            lifetime_minor_infractions=profile.lifetime_minor_infractions,
            last_updated=profile.last_updated,
            metadata=dict(profile.metadata),
        )

    def _copy_human(self, profile: HumanProfile) -> HumanProfile:
        return HumanProfile(
            user_id=profile.user_id,
            social_credit=profile.social_credit,
            tier=profile.tier,
            credits_balance=profile.credits_balance,
            is_active=profile.is_active,
            last_updated=profile.last_updated,
            metadata=dict(profile.metadata),
        )

    def _sync_cache(self, conn: sqlite3.Connection) -> None:
        """Invalidate local memory cache if another process or connection committed changes via PRAGMA data_version."""
        try:
            cur = conn.execute("PRAGMA data_version;")
            row = cur.fetchone()
            if row:
                curr_ver = int(row[0])
                if self._last_data_version != -1 and curr_ver != self._last_data_version:
                    self._cache_agents.clear()
                    self._cache_humans.clear()
                self._last_data_version = curr_ver
        except Exception:
            self._cache_agents.clear()
            self._cache_humans.clear()

    def checkpoint(self) -> None:
        """Force a WAL checkpoint to flush transaction logs to disk."""
        with self._lock, self._connection() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")

    def close(self) -> None:
        """Close all connections opened across threads."""
        with self._lock:
            for conn in self._all_conns:
                try:
                    conn.close()
                except Exception:
                    pass
            self._all_conns.clear()
            self._local = threading.local()
            self._cache_agents.clear()
            self._cache_humans.clear()
            self._last_data_version = -1

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA busy_timeout = 15000;")
            with self._write_transaction():
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS agents (
                        agent_id TEXT PRIMARY KEY,
                        alpha REAL,
                        beta REAL,
                        trust_score REAL,
                        status TEXT,
                        violations_count INTEGER,
                        consecutive_clean_actions INTEGER DEFAULT 0,
                        minor_infractions INTEGER DEFAULT 0,
                        lifetime_minor_infractions INTEGER DEFAULT 0,
                        last_updated REAL,
                        metadata_json TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS humans (
                        user_id TEXT PRIMARY KEY,
                        social_credit INTEGER,
                        tier TEXT,
                        credits_balance INTEGER,
                        is_active INTEGER,
                        last_updated REAL,
                        metadata_json TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS violations (
                        event_id TEXT PRIMARY KEY,
                        agent_id TEXT,
                        violation_type TEXT,
                        severity REAL,
                        details TEXT,
                        penalty_applied REAL,
                        timestamp REAL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS reflections (
                        reflection_id TEXT PRIMARY KEY,
                        agent_id TEXT,
                        event_id TEXT,
                        mistake_analysis TEXT,
                        corrective_action TEXT,
                        timestamp REAL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS challenges (
                        challenge_id TEXT PRIMARY KEY,
                        user_id TEXT,
                        agent_id TEXT,
                        action_name TEXT,
                        arguments_hash TEXT,
                        cost_credits INTEGER,
                        created_at REAL,
                        expires_at REAL,
                        token TEXT,
                        status TEXT,
                        resolved_at REAL,
                        resolution_reason TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ledger_blocks (
                        block_index INTEGER PRIMARY KEY,
                        timestamp REAL,
                        event_type TEXT,
                        entity_id TEXT,
                        payload_json TEXT,
                        prev_hash TEXT,
                        block_hash TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS delegation_mandates (
                        mandate_id TEXT PRIMARY KEY,
                        parent_agent_id TEXT,
                        sub_agent_id TEXT,
                        user_id TEXT,
                        parent_mandate_id TEXT,
                        current_depth INTEGER,
                        max_depth INTEGER,
                        max_credits INTEGER,
                        credits_used INTEGER,
                        reserved_child_credits INTEGER,
                        allowed_actions_json TEXT,
                        expires_at REAL,
                        created_at REAL,
                        status TEXT,
                        metadata_json TEXT,
                        signature TEXT
                    )
                    """
                )
                try:
                    conn.execute("ALTER TABLE agents ADD COLUMN minor_infractions INTEGER DEFAULT 0")
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute("ALTER TABLE agents ADD COLUMN lifetime_minor_infractions INTEGER DEFAULT 0")
                except sqlite3.OperationalError:
                    pass
            try:
                cur = conn.execute("PRAGMA data_version;")
                row = cur.fetchone()
                if row:
                    self._last_data_version = int(row[0])
            except Exception:
                pass

    def save_agent(self, profile: AgentProfile) -> None:
        with self._write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO agents 
                (agent_id, alpha, beta, trust_score, status, violations_count, consecutive_clean_actions, minor_infractions, lifetime_minor_infractions, last_updated, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.agent_id,
                    profile.alpha,
                    profile.beta,
                    profile.trust_score,
                    profile.status.value,
                    profile.violations_count,
                    profile.consecutive_clean_actions,
                    profile.minor_infractions,
                    profile.lifetime_minor_infractions,
                    profile.last_updated,
                    json.dumps(profile.metadata),
                ),
            )
            self._cache_agents[profile.agent_id] = self._copy_agent(profile)

    def get_agent(self, agent_id: str) -> Optional[AgentProfile]:
        with self._lock, self._connection() as conn:
            self._sync_cache(conn)
            if agent_id in self._cache_agents:
                return self._copy_agent(self._cache_agents[agent_id])

            cursor = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
            row = cursor.fetchone()
            if not row:
                return None
            keys = row.keys()
            clean_actions = row["consecutive_clean_actions"] if "consecutive_clean_actions" in keys else 0
            minor_infractions = row["minor_infractions"] if "minor_infractions" in keys else 0
            lifetime_minor_infractions = row["lifetime_minor_infractions"] if "lifetime_minor_infractions" in keys else 0
            profile = AgentProfile(
                agent_id=row["agent_id"],
                alpha=row["alpha"],
                beta=row["beta"],
                trust_score=row["trust_score"],
                status=AgentStatus(row["status"]),
                violations_count=row["violations_count"],
                consecutive_clean_actions=clean_actions,
                minor_infractions=minor_infractions,
                lifetime_minor_infractions=lifetime_minor_infractions,
                last_updated=row["last_updated"],
                metadata=json.loads(row["metadata_json"] or "{}"),
            )
            self._cache_agents[agent_id] = self._copy_agent(profile)
            return profile

    def save_human(self, profile: HumanProfile) -> None:
        with self._write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO humans
                (user_id, social_credit, tier, credits_balance, is_active, last_updated, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.user_id,
                    profile.social_credit,
                    profile.tier.value,
                    profile.credits_balance,
                    1 if profile.is_active else 0,
                    profile.last_updated,
                    json.dumps(profile.metadata),
                ),
            )
            self._cache_humans[profile.user_id] = self._copy_human(profile)

    def get_human(self, user_id: str) -> Optional[HumanProfile]:
        with self._lock, self._connection() as conn:
            self._sync_cache(conn)
            if user_id in self._cache_humans:
                return self._copy_human(self._cache_humans[user_id])

            cursor = conn.execute("SELECT * FROM humans WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                return None
            profile = HumanProfile(
                user_id=row["user_id"],
                social_credit=row["social_credit"],
                tier=HumanTier(row["tier"]),
                credits_balance=row["credits_balance"],
                is_active=bool(row["is_active"]),
                last_updated=row["last_updated"],
                metadata=json.loads(row["metadata_json"] or "{}"),
            )
            self._cache_humans[user_id] = self._copy_human(profile)
            return profile

    def deduct_credits(self, user_id: str, amount: int) -> bool:
        """Atomically deduct spendable credits in SQLite if balance >= amount."""
        if not isinstance(amount, (int, float)) or (isinstance(amount, float) and (math.isnan(amount) or math.isinf(amount))):
            raise ValueError("Deduct amount must be a finite number.")
        if amount < 0:
            raise ValueError("Deduct amount cannot be negative.")
        amount = int(amount)
        if amount == 0:
            return True
        with self._write_transaction() as conn:
            now = time.time()
            cursor = conn.execute(
                """
                UPDATE humans
                SET credits_balance = credits_balance - ?, last_updated = ?
                WHERE user_id = ? AND credits_balance >= ?
                """,
                (amount, now, user_id, amount),
            )
            success = cursor.rowcount > 0
            if success:
                if user_id in self._cache_humans:
                    self._cache_humans[user_id].credits_balance -= amount
                    self._cache_humans[user_id].last_updated = now
            return success

    def add_credits(self, user_id: str, amount: int) -> int:
        """Atomically deposit credits into human account in SQLite."""
        if not isinstance(amount, (int, float)) or (isinstance(amount, float) and (math.isnan(amount) or math.isinf(amount))):
            raise ValueError("Deposit amount must be a finite number.")
        if amount <= 0:
            raise ValueError(f"Deposit amount must be positive, got {amount}")
        amount = int(amount)
        with self._write_transaction() as conn:
            now = time.time()
            cursor = conn.execute(
                """
                UPDATE humans
                SET credits_balance = credits_balance + ?, last_updated = ?
                WHERE user_id = ?
                """,
                (amount, now, user_id),
            )
            if cursor.rowcount == 0:
                raise EntityNotFoundError(f"Human '{user_id}' not found.")
            cursor = conn.execute("SELECT credits_balance FROM humans WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            new_balance = int(row["credits_balance"])
            if user_id in self._cache_humans:
                self._cache_humans[user_id].credits_balance = new_balance
                self._cache_humans[user_id].last_updated = now
            return new_balance

    def record_violation(self, event: ViolationEvent) -> None:
        with self._write_transaction() as conn:
            conn.execute(
                """
                INSERT INTO violations
                (event_id, agent_id, violation_type, severity, details, penalty_applied, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.agent_id,
                    event.violation_type.value,
                    event.severity,
                    event.details,
                    event.penalty_applied,
                    event.timestamp,
                ),
            )

    def get_violations(
        self, agent_id: Optional[str] = None, limit: int = 50
    ) -> List[ViolationEvent]:
        with self._lock, self._connection() as conn:
            if agent_id:
                cursor = conn.execute(
                    """
                    SELECT * FROM violations WHERE agent_id = ? 
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (agent_id, limit),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM violations ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                )
            rows = cursor.fetchall()
            events = [
                ViolationEvent(
                    event_id=row["event_id"],
                    agent_id=row["agent_id"],
                    violation_type=ViolationType(row["violation_type"]),
                    severity=row["severity"],
                    details=row["details"],
                    penalty_applied=row["penalty_applied"],
                    timestamp=row["timestamp"],
                )
                for row in reversed(rows)
            ]
            return events

    def save_reflection(self, reflection: EpisodicReflection) -> None:
        with self._write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO reflections
                (reflection_id, agent_id, event_id, mistake_analysis, corrective_action, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    reflection.reflection_id,
                    reflection.agent_id,
                    reflection.event_id,
                    reflection.mistake_analysis,
                    reflection.corrective_action,
                    reflection.timestamp,
                ),
            )

    def get_reflections(
        self, agent_id: str, limit: int = 5
    ) -> List[EpisodicReflection]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM reflections
                WHERE agent_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (agent_id, limit),
            )
            rows = cursor.fetchall()
            return [
                EpisodicReflection(
                     reflection_id=row["reflection_id"],
                     agent_id=row["agent_id"],
                     event_id=row["event_id"],
                     mistake_analysis=row["mistake_analysis"],
                     corrective_action=row["corrective_action"],
                     timestamp=row["timestamp"],
                )
                for row in rows
            ]

    def save_challenge(self, challenge: HumanApprovalChallenge) -> None:
        with self._write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO challenges
                (challenge_id, user_id, agent_id, action_name, arguments_hash, cost_credits, created_at, expires_at, token, status, resolved_at, resolution_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge.challenge_id,
                    challenge.user_id,
                    challenge.agent_id,
                    challenge.action_name,
                    challenge.arguments_hash,
                    challenge.cost_credits,
                    challenge.created_at,
                    challenge.expires_at,
                    challenge.token,
                    challenge.status.value,
                    challenge.resolved_at,
                    challenge.resolution_reason,
                ),
            )

    def get_challenge(self, challenge_id: str) -> Optional[HumanApprovalChallenge]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return HumanApprovalChallenge(
                challenge_id=row["challenge_id"],
                user_id=row["user_id"],
                agent_id=row["agent_id"],
                action_name=row["action_name"],
                arguments_hash=row["arguments_hash"],
                cost_credits=row["cost_credits"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                token=row["token"],
                status=ChallengeStatus(row["status"]),
                resolved_at=row["resolved_at"],
                resolution_reason=row["resolution_reason"] or "",
            )

    def update_challenge_status(
        self,
        challenge_id: str,
        status: ChallengeStatus,
        resolved_at: float,
        reason: str = "",
    ) -> bool:
        """Atomic status update: enforces valid state transitions (single-use anti-replay enforcement)."""
        with self._write_transaction() as conn:
            if status in (ChallengeStatus.APPROVED, ChallengeStatus.REJECTED):
                prev_statuses = (ChallengeStatus.PENDING.value,)
            elif status == ChallengeStatus.CONSUMED:
                prev_statuses = (ChallengeStatus.APPROVED.value,)
            elif status == ChallengeStatus.EXPIRED:
                prev_statuses = (ChallengeStatus.PENDING.value, ChallengeStatus.APPROVED.value)
            else:
                return False

            placeholders = ",".join("?" for _ in prev_statuses)
            cursor = conn.execute(
                f"""
                UPDATE challenges
                SET status = ?, resolved_at = ?, resolution_reason = ?
                WHERE challenge_id = ? AND status IN ({placeholders})
                """,
                (status.value, resolved_at, reason, challenge_id, *prev_statuses),
            )
            return cursor.rowcount > 0

    def save_ledger_block(self, block: AuditBlock) -> None:
        with self._write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO ledger_blocks
                (block_index, timestamp, event_type, entity_id, payload_json, prev_hash, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    block.index,
                    block.timestamp,
                    block.event_type,
                    block.entity_id,
                    json.dumps(block.payload, sort_keys=True),
                    block.prev_hash,
                    block.block_hash,
                ),
            )

    def get_ledger_blocks(self) -> List[AuditBlock]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM ledger_blocks ORDER BY block_index ASC")
            rows = cursor.fetchall()
            return [
                AuditBlock(
                    index=row["block_index"],
                    timestamp=row["timestamp"],
                    event_type=row["event_type"],
                    entity_id=row["entity_id"],
                    payload=json.loads(row["payload_json"]),
                    prev_hash=row["prev_hash"],
                    block_hash=row["block_hash"],
                )
                for row in rows
            ]

    def get_ledger_block(self, block_index: int) -> Optional[AuditBlock]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM ledger_blocks WHERE block_index = ?", (block_index,))
            row = cursor.fetchone()
            if not row:
                return None
            return AuditBlock(
                index=row["block_index"],
                timestamp=row["timestamp"],
                event_type=row["event_type"],
                entity_id=row["entity_id"],
                payload=json.loads(row["payload_json"]),
                prev_hash=row["prev_hash"],
                block_hash=row["block_hash"],
            )

    def get_ledger_blocks_range(self, start_index: int, limit: int) -> List[AuditBlock]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM ledger_blocks WHERE block_index >= ? ORDER BY block_index ASC LIMIT ?",
                (start_index, limit),
            )
            rows = cursor.fetchall()
            return [
                AuditBlock(
                    index=row["block_index"],
                    timestamp=row["timestamp"],
                    event_type=row["event_type"],
                    entity_id=row["entity_id"],
                    payload=json.loads(row["payload_json"]),
                    prev_hash=row["prev_hash"],
                    block_hash=row["block_hash"],
                )
                for row in rows
            ]

    def save_mandate(self, mandate: DelegationMandate) -> None:
        with self._write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO delegation_mandates
                (mandate_id, parent_agent_id, sub_agent_id, user_id, parent_mandate_id, current_depth, max_depth, max_credits,
                 credits_used, reserved_child_credits, allowed_actions_json, expires_at, created_at, status, metadata_json, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mandate.mandate_id,
                    mandate.parent_agent_id,
                    mandate.sub_agent_id,
                    mandate.user_id,
                    mandate.parent_mandate_id,
                    mandate.current_depth,
                    mandate.max_depth,
                    mandate.max_credits,
                    mandate.credits_used,
                    mandate.reserved_child_credits,
                    json.dumps(list(mandate.allowed_actions)),
                    mandate.expires_at,
                    mandate.created_at,
                    mandate.status.value,
                    json.dumps(mandate.metadata),
                    mandate.signature,
                ),
            )

    def get_mandate(self, mandate_id: str) -> Optional[DelegationMandate]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM delegation_mandates WHERE mandate_id = ?", (mandate_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return DelegationMandate(
                mandate_id=row["mandate_id"],
                parent_agent_id=row["parent_agent_id"],
                sub_agent_id=row["sub_agent_id"],
                user_id=row["user_id"],
                parent_mandate_id=row["parent_mandate_id"],
                current_depth=row["current_depth"],
                max_depth=row["max_depth"],
                max_credits=row["max_credits"],
                credits_used=row["credits_used"],
                reserved_child_credits=row["reserved_child_credits"],
                allowed_actions=json.loads(row["allowed_actions_json"]),
                expires_at=row["expires_at"],
                created_at=row["created_at"],
                status=MandateStatus(row["status"]),
                metadata=json.loads(row["metadata_json"] or "{}"),
                signature=row["signature"],
            )

    def get_all_mandates(self) -> List[DelegationMandate]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM delegation_mandates")
            rows = cursor.fetchall()
            return [
                DelegationMandate(
                    mandate_id=row["mandate_id"],
                    parent_agent_id=row["parent_agent_id"],
                    sub_agent_id=row["sub_agent_id"],
                    user_id=row["user_id"],
                    parent_mandate_id=row["parent_mandate_id"],
                    current_depth=row["current_depth"],
                    max_depth=row["max_depth"],
                    max_credits=row["max_credits"],
                    credits_used=row["credits_used"],
                    reserved_child_credits=row["reserved_child_credits"],
                    allowed_actions=json.loads(row["allowed_actions_json"]),
                    expires_at=row["expires_at"],
                    created_at=row["created_at"],
                    status=MandateStatus(row["status"]),
                    metadata=json.loads(row["metadata_json"] or "{}"),
                    signature=row["signature"],
                )
                for row in rows
            ]


