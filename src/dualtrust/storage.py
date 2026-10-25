"""Storage backends for persisting profiles, reputation states, and audit trails."""

from abc import ABC, abstractmethod
import contextlib
import json
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional
from dualtrust.exceptions import EntityNotFoundError
from dualtrust.models import (
    AgentProfile,
    AgentStatus,
    ChallengeStatus,
    EpisodicReflection,
    HumanApprovalChallenge,
    HumanProfile,
    HumanTier,
    ViolationEvent,
    ViolationType,
)


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


class MemoryStorage(StorageBackend):
    """Thread-safe in-memory storage backend."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._agents: Dict[str, AgentProfile] = {}
        self._humans: Dict[str, HumanProfile] = {}
        self._violations: List[ViolationEvent] = []
        self._reflections: Dict[str, List[EpisodicReflection]] = {}
        self._challenges: Dict[str, HumanApprovalChallenge] = {}

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
        if amount <= 0:
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
            if ch.status != ChallengeStatus.PENDING:
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


class SQLiteStorage(StorageBackend):
    """Persistent, thread-safe SQLite storage backend with thread-local connection pooling."""

    def __init__(self, db_path: str = "dualtrust.db") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._local = threading.local()
        self._all_conns: List[sqlite3.Connection] = []
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 10000;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            self._local.conn = conn
            with self._lock:
                self._all_conns.append(conn)
        return conn

    @contextlib.contextmanager
    def _connection(self):
        conn = self._get_connection()
        yield conn

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

    def _init_db(self) -> None:
        with self._lock, self._connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA busy_timeout = 10000;")
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
            conn.commit()

    def save_agent(self, profile: AgentProfile) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO agents 
                (agent_id, alpha, beta, trust_score, status, violations_count, consecutive_clean_actions, last_updated, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.agent_id,
                    profile.alpha,
                    profile.beta,
                    profile.trust_score,
                    profile.status.value,
                    profile.violations_count,
                    profile.consecutive_clean_actions,
                    profile.last_updated,
                    json.dumps(profile.metadata),
                ),
            )
            conn.commit()

    def get_agent(self, agent_id: str) -> Optional[AgentProfile]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
            row = cursor.fetchone()
            if not row:
                return None
            keys = row.keys()
            clean_actions = row["consecutive_clean_actions"] if "consecutive_clean_actions" in keys else 0
            return AgentProfile(
                agent_id=row["agent_id"],
                alpha=row["alpha"],
                beta=row["beta"],
                trust_score=row["trust_score"],
                status=AgentStatus(row["status"]),
                violations_count=row["violations_count"],
                consecutive_clean_actions=clean_actions,
                last_updated=row["last_updated"],
                metadata=json.loads(row["metadata_json"] or "{}"),
            )

    def save_human(self, profile: HumanProfile) -> None:
        with self._lock, self._connection() as conn:
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
            conn.commit()

    def get_human(self, user_id: str) -> Optional[HumanProfile]:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM humans WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return HumanProfile(
                user_id=row["user_id"],
                social_credit=row["social_credit"],
                tier=HumanTier(row["tier"]),
                credits_balance=row["credits_balance"],
                is_active=bool(row["is_active"]),
                last_updated=row["last_updated"],
                metadata=json.loads(row["metadata_json"] or "{}"),
            )

    def deduct_credits(self, user_id: str, amount: int) -> bool:
        """Atomically deduct spendable credits in SQLite if balance >= amount."""
        if amount <= 0:
            return True
        with self._lock, self._connection() as conn:
            now = time.time()
            cursor = conn.execute(
                """
                UPDATE humans
                SET credits_balance = credits_balance - ?, last_updated = ?
                WHERE user_id = ? AND credits_balance >= ?
                """,
                (amount, now, user_id, amount),
            )
            conn.commit()
            return cursor.rowcount > 0

    def add_credits(self, user_id: str, amount: int) -> int:
        """Atomically deposit credits into human account in SQLite."""
        with self._lock, self._connection() as conn:
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
            conn.commit()
            return int(row["credits_balance"])

    def record_violation(self, event: ViolationEvent) -> None:
        with self._lock, self._connection() as conn:
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
            conn.commit()

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
        with self._lock, self._connection() as conn:
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
            conn.commit()

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
        with self._lock, self._connection() as conn:
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
            conn.commit()

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
        """Atomic status update: only updates if current status is PENDING (single-use enforcement)."""
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE challenges
                SET status = ?, resolved_at = ?, resolution_reason = ?
                WHERE challenge_id = ? AND status = ?
                """,
                (status.value, resolved_at, reason, challenge_id, ChallengeStatus.PENDING.value),
            )
            conn.commit()
            return cursor.rowcount > 0
