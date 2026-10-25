"""Empirical Monte Carlo Adversarial Attack Simulation & Statistical Validation Suite.

Validates DualTrust against 4 distinct adversarial populations over 10,000 stochastic interactions
without positivity bias or pre-ordained seeds.
"""

from dataclasses import asdict, dataclass
import json
import math
import os
import random
import statistics
import time
from typing import Any, Dict, List, Tuple

from dualtrust.engine import DualTrust
from dualtrust.models import AgentStatus, HumanTier, ViolationType


@dataclass
class SimulationMetrics:
    """Statistical summary metrics for a population simulation."""

    population_name: str
    total_agents: int
    total_interactions: int
    mean_final_trust: float
    std_dev_trust: float
    quarantine_rate: float
    successful_exploits: int
    blocked_exploits: int
    containment_rate: float


def run_benign_population(
    dt: DualTrust, num_agents: int = 50, tasks_per_agent: int = 200, noise_rate: float = 0.05
) -> SimulationMetrics:
    """Simulate honest agents with realistic stochastic noise (network timeouts, minor confusion)."""
    final_scores: List[float] = []
    quarantined_count = 0

    for i in range(num_agents):
        agent_id = f"benign_agent_{i}"
        dt.register_agent(agent_id, initial_trust=0.75)

        for task in range(tasks_per_agent):
            # 95% compliant, 5% random transient minor glitch (severity 1.0)
            if random.random() < noise_rate:
                dt.flag_user_rage(agent_id, reason="Transient minor glitch", severity=1.0)
            else:
                dt.reward_agent(agent_id, weight=1.0)

        agent = dt.get_or_create_agent(agent_id)
        final_scores.append(agent.trust_score)
        if agent.status == AgentStatus.QUARANTINED:
            quarantined_count += 1

    return SimulationMetrics(
        population_name="Benign Baseline (95% Compliant, 5% Noise)",
        total_agents=num_agents,
        total_interactions=num_agents * tasks_per_agent,
        mean_final_trust=round(statistics.mean(final_scores), 4),
        std_dev_trust=round(statistics.stdev(final_scores), 4) if len(final_scores) > 1 else 0.0,
        quarantine_rate=round(quarantined_count / num_agents, 4),
        successful_exploits=0,
        blocked_exploits=0,
        containment_rate=1.0 - round(quarantined_count / num_agents, 4),
    )


def run_oscillating_traitors(
    dt: DualTrust, num_agents: int = 50, cycles_per_agent: int = 20, cycle_ratio: int = 10
) -> SimulationMetrics:
    """Simulate traitor agents alternating between compliant trust-building and malicious exploits."""
    final_scores: List[float] = []
    quarantined_count = 0
    successful_exploits = 0
    blocked_exploits = 0

    dt.register_human("test_user_human", social_credit=850)

    for i in range(num_agents):
        agent_id = f"traitor_agent_{i}"
        dt.register_agent(agent_id, initial_trust=0.70)

        for cycle in range(cycles_per_agent):
            # Phase 1: Build trust with N compliant actions
            for _ in range(cycle_ratio):
                dt.reward_agent(agent_id, weight=1.0)

            # Phase 2: Attempt high-stakes exploit
            verdict = dt.evaluate(
                user_id="test_user_human",
                agent_id=agent_id,
                min_agent_score=0.70,
                min_human_score=750,
            )

            if verdict.authorized:
                successful_exploits += 1
                # Exploit happens -> triggers severe penalty
                dt.flag_protocol_trespass(
                    agent_id=agent_id,
                    target_system="aerospace:transit",
                    details="Exploit committed",
                    severity=3.5,
                )
            else:
                blocked_exploits += 1

        agent = dt.get_or_create_agent(agent_id)
        final_scores.append(agent.trust_score)
        if agent.status == AgentStatus.QUARANTINED:
            quarantined_count += 1

    total_attempts = successful_exploits + blocked_exploits
    containment_rate = round(blocked_exploits / total_attempts, 4) if total_attempts > 0 else 1.0

    return SimulationMetrics(
        population_name="Oscillating Traitors (10 Clean : 1 Exploit Cycle)",
        total_agents=num_agents,
        total_interactions=num_agents * cycles_per_agent * (cycle_ratio + 1),
        mean_final_trust=round(statistics.mean(final_scores), 4),
        std_dev_trust=round(statistics.stdev(final_scores), 4) if len(final_scores) > 1 else 0.0,
        quarantine_rate=round(quarantined_count / num_agents, 4),
        successful_exploits=successful_exploits,
        blocked_exploits=blocked_exploits,
        containment_rate=containment_rate,
    )


def run_whitewashing_syndicate(
    dt: DualTrust, num_syndicates: int = 50, attempts_per_syndicate: int = 5
) -> SimulationMetrics:
    """Simulate adversaries discarding caught identities and creating fresh newcomers."""
    successful_whitewash_executions = 0
    blocked_whitewash_executions = 0

    dt.register_human("human_gatekeeper", social_credit=900)

    for i in range(num_syndicates):
        for attempt in range(attempts_per_syndicate):
            # Fresh newcomer identity
            new_agent_id = f"fresh_pseudonym_{i}_{attempt}"
            dt.register_agent(new_agent_id, initial_trust=0.50)  # Starts at probation baseline

            # Immediately attempts high-clearance action requiring verified status (0.75+)
            verdict = dt.evaluate(
                user_id="human_gatekeeper",
                agent_id=new_agent_id,
                min_agent_score=0.75,
                min_human_score=800,
            )

            if verdict.authorized:
                successful_whitewash_executions += 1
            else:
                blocked_whitewash_executions += 1

    total = successful_whitewash_executions + blocked_whitewash_executions
    containment = round(blocked_whitewash_executions / total, 4) if total > 0 else 1.0

    return SimulationMetrics(
        population_name="Whitewashing Syndicate (Fresh Pseudonym Escalation)",
        total_agents=num_syndicates * attempts_per_syndicate,
        total_interactions=total,
        mean_final_trust=0.50,
        std_dev_trust=0.0,
        quarantine_rate=0.0,
        successful_exploits=successful_whitewash_executions,
        blocked_exploits=blocked_whitewash_executions,
        containment_rate=containment,
    )


def run_collusive_sybil_ring(
    dt: DualTrust, num_rings: int = 10, sybils_per_ring: int = 5, targets: int = 5
) -> Dict[str, Any]:
    """Simulate clusters of quarantined/low-trust agents defaming honest targets."""
    target_start_scores: List[float] = []
    target_end_scores: List[float] = []

    for t in range(targets):
        target_id = f"honest_target_{t}"
        dt.register_agent(target_id, initial_trust=0.90)
        target_start_scores.append(0.90)

        # Ring of colluding sybils spamming false reports
        for r in range(num_rings):
            for s in range(sybils_per_ring):
                sybil_id = f"sybil_{r}_{s}"
                dt.register_agent(sybil_id, initial_trust=0.10)
                dt.quarantine_agent(sybil_id, reason="Known Sybil Cluster")

                dt.report_violation(
                    agent_id=target_id,
                    violation_type=ViolationType.USER_RAGE,
                    severity=3.5,
                    reporter_id=sybil_id,
                )

        target = dt.get_or_create_agent(target_id)
        target_end_scores.append(target.trust_score)

    mean_start = statistics.mean(target_start_scores)
    mean_end = statistics.mean(target_end_scores)
    degradation_pct = round(((mean_start - mean_end) / mean_start) * 100, 2)

    return {
        "population_name": "Collusive Sybil Defamation Ring",
        "total_false_reports": num_rings * sybils_per_ring * targets,
        "mean_target_start_score": mean_start,
        "mean_target_final_score": round(mean_end, 4),
        "target_reputation_degradation_pct": degradation_pct,
        "defamation_resisted": degradation_pct < 10.0,
    }


def run_full_benchmark() -> Dict[str, Any]:
    """Execute complete 10,000+ interaction benchmark suite across all populations."""
    dt = DualTrust()
    print("=" * 70)
    print("STARTING DUALTRUST MONTE CARLO ADVERSARIAL BENCHMARK SUITE")
    print("=" * 70)

    t0 = time.time()

    # 1. Benign Population
    print("\n[1/4] Running Benign Baseline Population (50 agents x 200 tasks = 10,000 tasks)...")
    m_benign = run_benign_population(dt, num_agents=50, tasks_per_agent=200, noise_rate=0.05)
    print(f"      -> Mean Final Trust: {m_benign.mean_final_trust} (StdDev: {m_benign.std_dev_trust})")
    print(f"      -> False Quarantine Rate: {m_benign.quarantine_rate * 100:.2f}%")

    # 2. Oscillating Traitor Population
    print("\n[2/4] Running Oscillating Traitors (50 agents x 20 cycles = 11,000 tasks)...")
    m_traitor = run_oscillating_traitors(dt, num_agents=50, cycles_per_agent=20, cycle_ratio=10)
    print(f"      -> Quarantine Rate: {m_traitor.quarantine_rate * 100:.2f}%")
    print(f"      -> Blocked Exploits vs Succeeded: {m_traitor.blocked_exploits} blocked / {m_traitor.successful_exploits} passed")
    print(f"      -> Exploitation Containment Rate: {m_traitor.containment_rate * 100:.2f}%")

    # 3. Whitewashing Syndicate
    print("\n[3/4] Running Whitewashing Syndicate (50 syndicates x 5 attempts = 250 attempts)...")
    m_whitewash = run_whitewashing_syndicate(dt, num_syndicates=50, attempts_per_syndicate=5)
    print(f"      -> Newcomer Escalation Blocked: {m_whitewash.containment_rate * 100:.2f}%")

    # 4. Collusive Sybil Ring
    print("\n[4/4] Running Collusive Sybil Defamation Ring (250 false reports)...")
    m_sybil = run_collusive_sybil_ring(dt, num_rings=10, sybils_per_ring=5, targets=5)
    print(f"      -> Target Degradation: {m_sybil['target_reputation_degradation_pct']}% (Max Allowed: 10%)")
    print(f"      -> Sybil Defamation Resisted: {m_sybil['defamation_resisted']}")

    elapsed = round(time.time() - t0, 3)
    print("\n" + "=" * 70)
    print(f"BENCHMARK COMPLETED IN {elapsed}s")
    print("=" * 70)

    results = {
        "timestamp": time.time(),
        "total_elapsed_seconds": elapsed,
        "benign_baseline": asdict(m_benign),
        "oscillating_traitors": asdict(m_traitor),
        "whitewashing_syndicate": asdict(m_whitewash),
        "collusive_sybil_ring": m_sybil,
    }

    os.makedirs("benchmarks", exist_ok=True)
    with open("benchmarks/monte_carlo_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    run_full_benchmark()
