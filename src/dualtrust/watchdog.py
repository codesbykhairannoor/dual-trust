"""Automated Security Watchdog for AI Agent anomaly detection and sliding-window velocity governance."""

from collections import deque
import threading
import time
from typing import Deque, Dict, Optional, Tuple

from dualtrust.models import AgentTelemetry, AnomalyType, WatchdogVerdict


class AgentWatchdog:
    """Sliding-window behavioral watchdog for AI agent anomaly detection and automated circuit breaking.

    Monitors execution velocity (calls/sec), credit depletion velocity (burn/sec), and infraction clustering
    in real time (MITRE ATLAS AML.T0029, AML.T0040). Enforces escalating asymmetric slashing and auto-quarantine.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_calls_per_window: int = 30,
        max_credit_burn_per_window: int = 200,
        max_violations_per_window: int = 3,
        auto_quarantine_on_burst: bool = True,
        velocity_slashing_multiplier: float = 1.5,
    ) -> None:
        """Initialize the Automated Watchdog.

        Args:
            window_seconds: Time horizon for sliding-window telemetry (seconds).
            max_calls_per_window: Maximum tool calls permitted within window before throttling/slashing.
            max_credit_burn_per_window: Maximum spendable credits an agent may deplete per window.
            max_violations_per_window: Maximum infractions within window before auto-quarantine triggers.
            auto_quarantine_on_burst: Whether exceeding call burst rate immediately triggers quarantine.
            velocity_slashing_multiplier: Exponential scaling base for clustered infractions ($m^k$).
        """
        self.window_seconds = max(1.0, float(window_seconds))
        self.max_calls_per_window = max(1, int(max_calls_per_window))
        self.max_credit_burn_per_window = max(0, int(max_credit_burn_per_window))
        self.max_violations_per_window = max(1, int(max_violations_per_window))
        self.auto_quarantine_on_burst = auto_quarantine_on_burst
        self.velocity_slashing_multiplier = max(1.0, float(velocity_slashing_multiplier))

        self._lock = threading.RLock()
        self._call_history: Dict[str, Deque[float]] = {}
        self._burn_history: Dict[str, Deque[Tuple[float, int]]] = {}
        self._violation_history: Dict[str, Deque[Tuple[float, float]]] = {}
        self._anomaly_counts: Dict[str, int] = {}

    def _prune(self, agent_id: str, now: float) -> None:
        """Discard timestamped telemetry items outside the active sliding window."""
        cutoff = now - self.window_seconds

        # Prune calls
        calls = self._call_history.get(agent_id)
        if calls:
            while calls and calls[0] < cutoff:
                calls.popleft()

        # Prune credit burns
        burns = self._burn_history.get(agent_id)
        if burns:
            while burns and burns[0][0] < cutoff:
                burns.popleft()

        # Prune violations
        viols = self._violation_history.get(agent_id)
        if viols:
            while viols and viols[0][0] < cutoff:
                viols.popleft()

    def inspect_pre_call(
        self,
        agent_id: str,
        cost_credits: int = 0,
        current_time: Optional[float] = None,
    ) -> WatchdogVerdict:
        """Evaluate whether a proposed tool call breaches sliding window rate or velocity constraints."""
        now = current_time if current_time is not None else time.time()

        with self._lock:
            self._prune(agent_id, now)

            calls = self._call_history.setdefault(agent_id, deque())
            burns = self._burn_history.setdefault(agent_id, deque())

            # Check 1: Action Velocity Burst
            if len(calls) >= self.max_calls_per_window:
                self._anomaly_counts[agent_id] = self._anomaly_counts.get(agent_id, 0) + 1
                reason = (
                    f"Call velocity burst limit exceeded ({len(calls)} calls in {self.window_seconds}s; "
                    f"limit: {self.max_calls_per_window})."
                )
                return WatchdogVerdict(
                    is_anomalous=True,
                    anomaly_type=AnomalyType.BURST_RATE_EXCEEDED,
                    action_permitted=False,
                    action_throttled=True,
                    auto_quarantined=self.auto_quarantine_on_burst,
                    reason=reason,
                )

            # Check 2: Credit Burn Velocity Drain
            current_burn = sum(amount for _, amount in burns)
            if self.max_credit_burn_per_window > 0 and (current_burn + cost_credits) > self.max_credit_burn_per_window:
                self._anomaly_counts[agent_id] = self._anomaly_counts.get(agent_id, 0) + 1
                reason = (
                    f"Credit drain velocity exceeded ({current_burn + cost_credits} credits in {self.window_seconds}s; "
                    f"limit: {self.max_credit_burn_per_window})."
                )
                return WatchdogVerdict(
                    is_anomalous=True,
                    anomaly_type=AnomalyType.CREDIT_DRAIN_VELOCITY,
                    action_permitted=False,
                    action_throttled=True,
                    auto_quarantined=False,
                    reason=reason,
                )

            return WatchdogVerdict(
                is_anomalous=False,
                action_permitted=True,
                action_throttled=False,
                auto_quarantined=False,
            )

    def record_call_success(
        self,
        agent_id: str,
        cost_credits: int = 0,
        current_time: Optional[float] = None,
    ) -> None:
        """Commit an executed tool invocation and its credit cost into the agent's sliding window."""
        now = current_time if current_time is not None else time.time()
        with self._lock:
            self._prune(agent_id, now)
            self._call_history.setdefault(agent_id, deque()).append(now)
            if cost_credits > 0:
                self._burn_history.setdefault(agent_id, deque()).append((now, cost_credits))

    def record_violation_velocity(
        self,
        agent_id: str,
        severity: float,
        current_time: Optional[float] = None,
    ) -> Tuple[float, bool]:
        """Record an infraction, compute exponential velocity multiplier, and test for auto-quarantine.

        Returns:
            Tuple of (velocity_multiplier: float, should_auto_quarantine: bool).
        """
        now = current_time if current_time is not None else time.time()
        with self._lock:
            self._prune(agent_id, now)
            viols = self._violation_history.setdefault(agent_id, deque())
            recent_count = len(viols)

            # Calculate escalating multiplier: m^k where k is number of recent infractions
            multiplier = self.velocity_slashing_multiplier ** recent_count

            viols.append((now, severity))
            total_recent = len(viols)

            should_quarantine = total_recent >= self.max_violations_per_window
            if should_quarantine or total_recent > 1:
                self._anomaly_counts[agent_id] = self._anomaly_counts.get(agent_id, 0) + 1

            return multiplier, should_quarantine

    def record_semantic_drift(
        self,
        agent_id: str,
        drift_distance: float,
        threshold: float = 0.75,
    ) -> WatchdogVerdict:
        """Evaluate semantic divergence from initial system directives."""
        with self._lock:
            if drift_distance >= threshold:
                self._anomaly_counts[agent_id] = self._anomaly_counts.get(agent_id, 0) + 1
                reason = f"Semantic drift anomaly detected: distance {drift_distance:.2f} >= threshold {threshold:.2f}."
                return WatchdogVerdict(
                    is_anomalous=True,
                    anomaly_type=AnomalyType.SEMANTIC_DRIFT,
                    action_permitted=False,
                    action_throttled=True,
                    auto_quarantined=False,
                    reason=reason,
                )
            return WatchdogVerdict(is_anomalous=False, action_permitted=True)

    def get_telemetry(
        self,
        agent_id: str,
        current_time: Optional[float] = None,
    ) -> AgentTelemetry:
        """Fetch real-time activity velocity and rate metrics for an agent."""
        now = current_time if current_time is not None else time.time()
        with self._lock:
            self._prune(agent_id, now)
            calls = self._call_history.get(agent_id, deque())
            burns = self._burn_history.get(agent_id, deque())
            viols = self._violation_history.get(agent_id, deque())

            calls_count = len(calls)
            call_rate = calls_count / self.window_seconds
            burn_count = sum(amount for _, amount in burns)
            viol_count = len(viols)
            anomalies = self._anomaly_counts.get(agent_id, 0)
            is_throttled = calls_count >= self.max_calls_per_window

            return AgentTelemetry(
                agent_id=agent_id,
                window_seconds=self.window_seconds,
                calls_in_window=calls_count,
                call_rate_per_sec=call_rate,
                credits_burned_in_window=burn_count,
                violations_in_window=viol_count,
                anomalies_detected=anomalies,
                is_throttled=is_throttled,
            )

    def reset(self, agent_id: Optional[str] = None) -> None:
        """Reset telemetry history for a specific agent or all agents."""
        with self._lock:
            if agent_id:
                self._call_history.pop(agent_id, None)
                self._burn_history.pop(agent_id, None)
                self._violation_history.pop(agent_id, None)
                self._anomaly_counts.pop(agent_id, None)
            else:
                self._call_history.clear()
                self._burn_history.clear()
                self._violation_history.clear()
                self._anomaly_counts.clear()
