"""Microsecond latency benchmark for DualTrust policy evaluation and cryptographic operations.

Complies with the zero-hallucination-proofs protocol:
- Measures empirical wall-clock time using time.perf_counter_ns().
- Computes sample size N, mean, SEM, 95% CI, p50, p90, p95, p99, min, max.
- Dumps machine-readable artifacts to JSON and CSV.
"""

import asyncio
import csv
import json
import math
import os
import statistics
import time
from typing import Any, Callable, Dict, List

from dualtrust.crypto_ledger import CryptographicLedger, MerkleTree
from dualtrust.engine import DualTrust
from dualtrust.storage import MemoryStorage


def compute_statistics(latencies_ns: List[int]) -> Dict[str, Any]:
    """Compute comprehensive statistical metrics from raw nanosecond measurements."""
    n = len(latencies_ns)
    if n == 0:
        return {}

    latencies_us = [ns / 1_000.0 for ns in latencies_ns]
    latencies_ms = [ns / 1_000_000.0 for ns in latencies_ns]

    mean_us = statistics.mean(latencies_us)
    std_us = statistics.stdev(latencies_us) if n > 1 else 0.0
    sem_us = std_us / math.sqrt(n) if n > 0 else 0.0
    ci95_lower_us = max(0.0, mean_us - 1.96 * sem_us)
    ci95_upper_us = mean_us + 1.96 * sem_us

    sorted_us = sorted(latencies_us)
    p50_us = sorted_us[int(0.50 * n)]
    p90_us = sorted_us[int(0.90 * n)]
    p95_us = sorted_us[int(0.95 * n)]
    p99_us = sorted_us[min(int(0.99 * n), n - 1)]

    mean_ms = statistics.mean(latencies_ms)
    p50_ms = p50_us / 1000.0
    p99_ms = p99_us / 1000.0

    return {
        "sample_size": n,
        "mean_us": round(mean_us, 2),
        "mean_ms": round(mean_ms, 4),
        "std_us": round(std_us, 2),
        "sem_us": round(sem_us, 3),
        "ci95_lower_us": round(ci95_lower_us, 2),
        "ci95_upper_us": round(ci95_upper_us, 2),
        "p50_us": round(p50_us, 2),
        "p50_ms": round(p50_ms, 4),
        "p90_us": round(p90_us, 2),
        "p95_us": round(p95_us, 2),
        "p99_us": round(p99_us, 2),
        "p99_ms": round(p99_ms, 4),
        "min_us": round(sorted_us[0], 2),
        "max_us": round(sorted_us[-1], 2),
    }


def run_benchmark(iterations: int = 10000) -> Dict[str, Any]:
    """Execute rigorous microsecond latency benchmarking across all critical paths."""
    print(f"[*] Starting DualTrust microsecond benchmark (N = {iterations} iterations)...")

    storage = MemoryStorage()
    dt = DualTrust(storage=storage)

    # Pre-register test identities
    user_id = "bench_human_01"
    agent_id = "bench_agent_01"
    dt.register_human(user_id=user_id, social_credit=850, credits_balance=100000)
    dt.register_agent(agent_id=agent_id, initial_trust=0.80)

    # 1. Warm-up
    for _ in range(500):
        dt.evaluate(user_id=user_id, agent_id=agent_id, cost_credits=1, deduct_cost=False)

    # -------------------------------------------------------------------------
    # Benchmark 1: Core Policy Evaluation (dt.evaluate - In-Memory Fast Tier)
    # -------------------------------------------------------------------------
    latencies_eval: List[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        _ = dt.evaluate(user_id=user_id, agent_id=agent_id, min_human_score=600, min_agent_score=0.50)
        t1 = time.perf_counter_ns()
        latencies_eval.append(t1 - t0)

    # -------------------------------------------------------------------------
    # Benchmark 2: Sync @gate Decorator Overhead
    # -------------------------------------------------------------------------
    @dt.gate(min_human_score=600, min_agent_score=0.50)
    def guarded_target(user_id: str, agent_id: str) -> str:
        return "success"

    latencies_gate_sync: List[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        _ = guarded_target(user_id=user_id, agent_id=agent_id)
        t1 = time.perf_counter_ns()
        latencies_gate_sync.append(t1 - t0)

    # -------------------------------------------------------------------------
    # Benchmark 3: Async @gate Decorator Overhead
    # -------------------------------------------------------------------------
    @dt.gate(min_human_score=600, min_agent_score=0.50)
    async def async_guarded_target(user_id: str, agent_id: str) -> str:
        return "async_success"

    async def run_async_bench() -> List[int]:
        l_async = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            _ = await async_guarded_target(user_id=user_id, agent_id=agent_id)
            t1 = time.perf_counter_ns()
            l_async.append(t1 - t0)
        return l_async

    latencies_gate_async = asyncio.run(run_async_bench())

    # -------------------------------------------------------------------------
    # Benchmark 4: SQLite WAL Persistent Policy Evaluation Tier
    # -------------------------------------------------------------------------
    from dualtrust.storage import SQLiteStorage
    import tempfile

    sqlite_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_db_path = sqlite_db_file.name
    sqlite_db_file.close()

    sqlite_storage = SQLiteStorage(db_path=sqlite_db_path)
    dt_sqlite = DualTrust(storage=sqlite_storage)
    dt_sqlite.register_human(user_id="bench_sqlite_user", social_credit=850, credits_balance=100000)
    dt_sqlite.register_agent(agent_id="bench_sqlite_agent", initial_trust=0.80)

    # 1,000 physical disk transactions on SQLite WAL
    sqlite_iterations = min(1000, iterations)
    latencies_sqlite_wal: List[int] = []
    for _ in range(sqlite_iterations):
        t0 = time.perf_counter_ns()
        _ = dt_sqlite.evaluate(user_id="bench_sqlite_user", agent_id="bench_sqlite_agent", cost_credits=1, deduct_cost=True)
        t1 = time.perf_counter_ns()
        latencies_sqlite_wal.append(t1 - t0)

    sqlite_storage.close()
    try:
        os.remove(sqlite_db_path)
    except OSError:
        pass

    # -------------------------------------------------------------------------
    # Benchmark 5: Cryptographic HMAC Verdict Receipt Verification
    # -------------------------------------------------------------------------
    verdict = dt.evaluate(user_id=user_id, agent_id=agent_id)
    latencies_hmac: List[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        _ = dt.verify_verdict(verdict, user_id=user_id, agent_id=agent_id)
        t1 = time.perf_counter_ns()
        latencies_hmac.append(t1 - t0)

    # -------------------------------------------------------------------------
    # Benchmark 6: RFC 6962 Merkle Tree Inclusion Proof Verification
    # -------------------------------------------------------------------------
    # Build tree with 128 audit leaves
    leaves = [f"{i:064x}" for i in range(128)]
    tree = MerkleTree(leaves)
    leaf_idx = 42
    leaf_hash = leaves[leaf_idx]
    proof = tree.get_proof(leaf_idx)
    root = tree.root

    latencies_merkle: List[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        _ = MerkleTree.verify_proof(leaf_hash=leaf_hash, proof=proof, root_hash=root)
        t1 = time.perf_counter_ns()
        latencies_merkle.append(t1 - t0)

    # -------------------------------------------------------------------------
    # Benchmark 7: Anthropic MCP Gateway Tool Interception & Dispatch
    # -------------------------------------------------------------------------
    from dualtrust.adapters.mcp import DualTrustMCPGateway

    gateway = DualTrustMCPGateway(dualtrust=dt, default_user_id=user_id, default_agent_id=agent_id)
    gateway.register_tool("bench_tool", lambda x: x * 2)
    mcp_req = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {"name": "bench_tool", "arguments": {"x": 42}},
    }
    latencies_mcp: List[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        _ = gateway.handle_json_rpc(mcp_req)
        t1 = time.perf_counter_ns()
        latencies_mcp.append(t1 - t0)

    results = {
        "evaluate_policy_in_memory": compute_statistics(latencies_eval),
        "gate_decorator_sync": compute_statistics(latencies_gate_sync),
        "gate_decorator_async": compute_statistics(latencies_gate_async),
        "evaluate_policy_sqlite_wal": compute_statistics(latencies_sqlite_wal),
        "hmac_receipt_verification": compute_statistics(latencies_hmac),
        "merkle_inclusion_proof_verification": compute_statistics(latencies_merkle),
        "mcp_gateway_tool_dispatch": compute_statistics(latencies_mcp),
    }

    # Ensure output directory exists
    os.makedirs("benchmarks", exist_ok=True)

    # Save JSON artifact
    json_path = os.path.join("benchmarks", "latency_benchmark_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Save CSV artifact
    csv_path = os.path.join("benchmarks", "latency_benchmark_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Operation",
            "Sample Size (N)",
            "Mean (us)",
            "Mean (ms)",
            "StdDev (us)",
            "SEM (us)",
            "95% CI (us)",
            "p50 / Median (us)",
            "p90 (us)",
            "p95 (us)",
            "p99 (us)",
            "Min (us)",
            "Max (us)",
        ])
        for op, data in results.items():
            writer.writerow([
                op,
                data["sample_size"],
                data["mean_us"],
                data["mean_ms"],
                data["std_us"],
                data["sem_us"],
                f"[{data['ci95_lower_us']}, {data['ci95_upper_us']}]",
                data["p50_us"],
                data["p90_us"],
                data["p95_us"],
                data["p99_us"],
                data["min_us"],
                data["max_us"],
            ])

    print("\n" + "=" * 92)
    print(f"{'DUALTRUST MICROSECOND LATENCY BENCHMARK RESULTS (N = ' + str(iterations) + ')':^92}")
    print("=" * 92)
    print(f"{'Operation':<35} | {'Mean (us)':<10} | {'p50 (us)':<10} | {'p99 (us)':<10} | {'Mean (ms)':<10}")
    print("-" * 92)
    for op, data in results.items():
        print(
            f"{op:<35} | {data['mean_us']:<10.2f} | {data['p50_us']:<10.2f} | {data['p99_us']:<10.2f} | {data['mean_ms']:<10.4f}"
        )
    print("=" * 92)
    print(f"[+] Artifacts successfully written to:")
    print(f"    - {json_path}")
    print(f"    - {csv_path}\n")

    return results


if __name__ == "__main__":
    run_benchmark(iterations=10000)
