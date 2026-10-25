"""Agent-to-Agent (A2A) Governance, Delegation Mandates, and Attestation Engine.

Implements zero-dependency cryptographic delegation mandates for multi-agent swarms,
conforming to the Principle of Least Privilege (PoLP) and Macaroons capability-based
access control models.
"""

from dataclasses import replace
import hashlib
import hmac
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .exceptions import (
    DelegationError,
    MandateBudgetExceededError,
    MandateDepthExceededError,
    MandateExpiredError,
    MandateRevokedError,
    MandateScopeViolationError,
)
from .models import DelegationMandate, MandateStatus


class MandateManager:
    """Manages creation, cryptographic signing, tamper verification, and lifecycle of A2A delegation mandates."""

    def __init__(self, secret_key: Optional[str] = None) -> None:
        """Initialize the MandateManager with an HMAC signing secret."""
        self._secret_key: bytes = (secret_key or secrets.token_hex(32)).encode("utf-8")
        self._mandates: Dict[str, DelegationMandate] = {}
        self._lock = threading.RLock()

    def _canonical_representation(
        self,
        mandate_id: str,
        parent_agent_id: str,
        sub_agent_id: str,
        user_id: str,
        allowed_actions: List[str],
        max_credits: int,
        max_depth: int,
        current_depth: int,
        created_at: float,
        expires_at: float,
    ) -> str:
        """Construct the deterministic canonical string for cryptographic attestation."""
        sorted_actions = ",".join(sorted(allowed_actions))
        return (
            f"{mandate_id}:{parent_agent_id}:{sub_agent_id}:{user_id}:"
            f"{sorted_actions}:{max_credits}:{max_depth}:{current_depth}:"
            f"{created_at:.4f}:{expires_at:.4f}"
        )

    def _sign_payload(self, canonical_str: str) -> str:
        """Generate a deterministic HMAC-SHA256 signature for the canonical representation."""
        return hmac.new(self._secret_key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue_mandate(
        self,
        parent_agent_id: str,
        sub_agent_id: str,
        user_id: str,
        allowed_actions: List[str],
        max_credits: int,
        ttl_seconds: float = 300.0,
        max_depth: int = 1,
        current_depth: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DelegationMandate:
        """Issue a cryptographically sealed delegation mandate authorizing a sub-agent to act on behalf of a parent."""
        if not parent_agent_id or not sub_agent_id:
            raise DelegationError("Both parent_agent_id and sub_agent_id must be non-empty strings.")
        if parent_agent_id == sub_agent_id:
            raise DelegationError("An agent cannot delegate an A2A mandate to itself.")
        if not user_id:
            raise DelegationError("Mandate user_id must be non-empty.")
        if max_credits <= 0:
            raise DelegationError(f"max_credits must be strictly positive, got {max_credits}.")
        if ttl_seconds <= 0:
            raise DelegationError(f"ttl_seconds must be strictly positive, got {ttl_seconds}.")
        if max_depth < 1:
            raise DelegationError(f"max_depth must be at least 1, got {max_depth}.")
        if current_depth > max_depth:
            raise MandateDepthExceededError(
                f"Cannot issue mandate: current_depth ({current_depth}) exceeds max_depth ({max_depth})."
            )

        now = time.time()
        expires_at = now + ttl_seconds
        mandate_id = secrets.token_hex(16)
        cleaned_actions = sorted(list(set(allowed_actions or ["*"])))

        canonical = self._canonical_representation(
            mandate_id=mandate_id,
            parent_agent_id=parent_agent_id,
            sub_agent_id=sub_agent_id,
            user_id=user_id,
            allowed_actions=cleaned_actions,
            max_credits=max_credits,
            max_depth=max_depth,
            current_depth=current_depth,
            created_at=now,
            expires_at=expires_at,
        )
        signature = self._sign_payload(canonical)

        mandate = DelegationMandate(
            mandate_id=mandate_id,
            parent_agent_id=parent_agent_id,
            sub_agent_id=sub_agent_id,
            user_id=user_id,
            allowed_actions=cleaned_actions,
            max_credits=max_credits,
            credits_used=0,
            max_depth=max_depth,
            current_depth=current_depth,
            created_at=now,
            expires_at=expires_at,
            status=MandateStatus.ACTIVE,
            metadata=dict(metadata or {}),
            signature=signature,
        )

        with self._lock:
            self._mandates[mandate_id] = mandate

        return mandate

    def verify_mandate(
        self,
        mandate: DelegationMandate,
        action: Optional[str] = None,
        cost_credits: int = 0,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """Perform comprehensive cryptographic and policy verification on a delegation mandate."""
        now = current_time if current_time is not None else time.time()

        # 1. Cryptographic HMAC tamper check
        canonical = self._canonical_representation(
            mandate_id=mandate.mandate_id,
            parent_agent_id=mandate.parent_agent_id,
            sub_agent_id=mandate.sub_agent_id,
            user_id=mandate.user_id,
            allowed_actions=mandate.allowed_actions,
            max_credits=mandate.max_credits,
            max_depth=mandate.max_depth,
            current_depth=mandate.current_depth,
            created_at=mandate.created_at,
            expires_at=mandate.expires_at,
        )
        expected_sig = self._sign_payload(canonical)
        if not hmac.compare_digest(mandate.signature, expected_sig):
            return False, "Cryptographic signature mismatch: mandate has been forged or altered."

        # 2. Status verification
        with self._lock:
            stored_mandate = self._mandates.get(mandate.mandate_id)
            current_status = stored_mandate.status if stored_mandate else mandate.status

        if current_status == MandateStatus.REVOKED:
            return False, "Mandate has been revoked by the parent agent or human."
        if current_status == MandateStatus.EXHAUSTED:
            return False, "Mandate credit budget is exhausted."

        # 3. Expiration check
        if mandate.is_expired(now):
            return False, f"Mandate token expired at {mandate.expires_at:.2f} (current: {now:.2f})."

        # 4. Delegation depth check
        if mandate.current_depth > mandate.max_depth:
            return False, f"Mandate delegation depth ({mandate.current_depth}) exceeds maximum ({mandate.max_depth})."

        # 5. Action scope check
        if action is not None and not mandate.can_perform(action):
            allowed_str = ", ".join(mandate.allowed_actions)
            return False, f"Action '{action}' is not permitted by mandate scope [{allowed_str}]."

        # 6. Credit budget check
        if cost_credits > 0:
            with self._lock:
                used = stored_mandate.credits_used if stored_mandate else mandate.credits_used
            if (used + cost_credits) > mandate.max_credits:
                remaining = max(0, mandate.max_credits - used)
                return False, f"Insufficient mandate credit budget: requested {cost_credits}, remaining {remaining}."

        return True, "Mandate verified and authorized."

    def validate_and_consume(
        self,
        mandate_id: str,
        action: str,
        cost_credits: int = 0,
        current_time: Optional[float] = None,
    ) -> DelegationMandate:
        """Validate mandate policies and atomically deduct the action cost from the mandate budget."""
        with self._lock:
            mandate = self._mandates.get(mandate_id)
            if not mandate:
                raise DelegationError(f"Mandate '{mandate_id}' not found in registry.")

            now = current_time if current_time is not None else time.time()

            # Check validity
            is_valid, reason = self.verify_mandate(
                mandate, action=action, cost_credits=cost_credits, current_time=now
            )
            if not is_valid:
                if "signature mismatch" in reason:
                    raise DelegationError(reason)
                if "revoked" in reason:
                    raise MandateRevokedError(reason)
                if "expired" in reason:
                    raise MandateExpiredError(reason)
                if "depth" in reason:
                    raise MandateDepthExceededError(reason)
                if "not permitted by mandate scope" in reason:
                    raise MandateScopeViolationError(reason)
                if "Insufficient mandate credit budget" in reason or "exhausted" in reason:
                    raise MandateBudgetExceededError(reason)
                raise DelegationError(reason)

            # Consume budget
            if cost_credits > 0:
                mandate.credits_used += cost_credits
                if mandate.credits_used >= mandate.max_credits:
                    mandate.status = MandateStatus.EXHAUSTED

            return mandate

    def derive_sub_mandate(
        self,
        parent_mandate_id: str,
        new_sub_agent_id: str,
        allowed_actions: Optional[List[str]] = None,
        max_credits: Optional[int] = None,
        ttl_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DelegationMandate:
        """Derive an attenuated sub-mandate for a tertiary agent, enforcing monotonic attenuation."""
        with self._lock:
            parent = self._mandates.get(parent_mandate_id)
            if not parent:
                raise DelegationError(f"Parent mandate '{parent_mandate_id}' not found.")

            # Check status and expiration of parent
            now = time.time()
            if parent.is_expired(now):
                raise MandateExpiredError("Cannot derive sub-mandate: parent mandate is expired.")
            if parent.status != MandateStatus.ACTIVE:
                raise DelegationError(f"Cannot derive sub-mandate: parent mandate status is {parent.status.value}.")

            # Depth recursion check
            new_depth = parent.current_depth + 1
            if new_depth > parent.max_depth:
                raise MandateDepthExceededError(
                    f"Sub-delegation denied: delegation depth {new_depth} exceeds max allowed depth ({parent.max_depth})."
                )

            # Scope attenuation (Principle of Least Privilege)
            if allowed_actions is None:
                derived_actions = list(parent.allowed_actions)
            else:
                if "*" not in parent.allowed_actions:
                    for act in allowed_actions:
                        if act not in parent.allowed_actions:
                            raise MandateScopeViolationError(
                                f"Cannot escalate scope: action '{act}' is not in parent mandate scope."
                            )
                derived_actions = allowed_actions

            # Budget attenuation
            remaining = parent.remaining_credits
            if max_credits is None:
                derived_credits = remaining
            else:
                if max_credits <= 0:
                    raise DelegationError(f"Sub-mandate max_credits must be strictly positive, got {max_credits}.")
                if max_credits > remaining:
                    raise MandateBudgetExceededError(
                        f"Cannot allot {max_credits} credits: parent mandate only has {remaining} credits remaining."
                    )
                derived_credits = max_credits

            # TTL attenuation
            max_ttl = max(1.0, parent.expires_at - now)
            derived_ttl = min(ttl_seconds, max_ttl) if ttl_seconds is not None else max_ttl

        # Issue the derived mandate
        return self.issue_mandate(
            parent_agent_id=parent.sub_agent_id,
            sub_agent_id=new_sub_agent_id,
            user_id=parent.user_id,
            allowed_actions=derived_actions,
            max_credits=derived_credits,
            ttl_seconds=derived_ttl,
            max_depth=parent.max_depth,
            current_depth=new_depth,
            metadata=metadata,
        )

    def revoke_mandate(self, mandate_id: str, reason: str = "") -> bool:
        """Revoke an active delegation mandate immediately."""
        with self._lock:
            mandate = self._mandates.get(mandate_id)
            if not mandate:
                return False
            mandate.status = MandateStatus.REVOKED
            if reason:
                mandate.metadata["revocation_reason"] = reason
            return True

    def get_mandate(self, mandate_id: str) -> Optional[DelegationMandate]:
        """Retrieve a mandate by ID."""
        with self._lock:
            return self._mandates.get(mandate_id)
