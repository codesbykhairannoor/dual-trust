# DualTrust Security Architecture & Threat Model

> **Standard Compliance**: Mapped to **MITRE ATLAS™** (Adversarial Threat Landscape for AI Systems) and **OWASP Top 10 for Large Language Models**.

---

## 1. Executive Summary

Autonomous AI agents acting on behalf of humans in ambient computing environments (smart glasses, spatial wearables, physical actuators) present a fundamentally different threat surface than traditional web services. 

Because agents can dynamically formulate execution paths and call real-world tools, an adversary does not need to compromise the underlying binary code—they can compromise the **context, intent, or multi-agent permissions**.

`DualTrust` serves as an immutable **Dual-Trust Gating and Reputation Firewall** sitting between the Agent's reasoning loop and physical/digital execution tools.

---

## 2. Adversarial Threat Matrix (MITRE ATLAS & OWASP Mapped)

| Threat ID | Threat Name | MITRE ATLAS / OWASP Technique | Attack Mechanism | DualTrust Defense Layer |
| :--- | :--- | :--- | :--- | :--- |
| **DT-T01** | **The Sleeping Trojan Agent** (Whitewashing & Sudden Breach) | `AML.T0043` ML Attack Staging / Goal Hijacking | Agent maintains high compliance over 500 routine calls to build a $0.95$ trust score, then executes a catastrophic unauthorized tool call. | **Asymmetric Slashing & Quarantine Floor**: A single severe violation (`severity >= 3.0`) triggers an immediate penalty doubling and quarantine isolation, instantly overriding historical $\alpha$ accumulation. |
| **DT-T02** | **The Sybil Defamation Ring** (Collusion Attack) | `AML.T0040` Impact on System Integrity | A cluster of low-reputation or newly spun-up agents flood the system with false violation reports to de-platform benign agents. | **Reporter Credibility Discounting (EigenTrust)**: Applied penalties are multiplied by $C_{\text{reporter}} \in [0.05, 1.0]$. Reports from quarantined or unverified agents are discounted by up to $95\%$. |
| **DT-T03** | **Excessive Agency & Protocol Trespass** | `OWASP LLM06` Excessive Agency / `AML.T0054` Plugin Compromise | Agent attempts to invoke tools outside its authorized tier or bypass multi-agent negotiation handshakes (e.g. jumping transit queues). | **Dual-Key Policy Gate (`@gate`)**: Strict verification of clearance tier, minimum human social credit, and agent state prior to execution. |
| **DT-T04** | **Unbounded Consumption / Wallet Drain** | `OWASP LLM10` Unbounded Consumption | Prompt injection causes the agent to enter a recursive loop, repeatedly calling paid or physical APIs, draining the user's funds. | **Credit Quota Ceiling & Atomic Balance Deductions**: Execution is rejected when `credits_balance < cost_credits`. Atomic balance deductions prevent overdrafts. |
| **DT-T05** | **Audit Trail Tampering** | `AML.T0017` Defense Evasion | An attacker with database read/write access attempts to modify historical infraction logs to exonerate a rogue agent. | **SHA-256 Hash-Chained Audit Ledger**: Every event is cryptographically sealed into a sequential block $H_n = \text{SHA256}(H_{n-1} \,\|\, \text{Payload})$. Modification of past records invalidates the entire chain. |
| **DT-T06** | **Replay & Stale Verdict Harvesting** | `AML.T0051` Execution Exploitation | An adversary intercepts a valid `TrustVerdict` approval and attempts to replay it to re-execute physical actions without re-authorization. | **Signed Verdict Receipts & Monotonic Nonces**: Verdicts carry cryptographic hashes, millisecond timestamps, and short validity windows. |

---

## 3. Mathematical Defense Guarantees

### 3.1. Exponential Penalty Scaling
Infraction escalation follows:
$$\Delta \beta = k_p \cdot (\text{Severity} \cdot C_{\text{reporter}}) \cdot v^{\gamma}$$

Where:
* $k_p = 3.5$ (Asymmetric penalty constant)
* $v$ (Monotonically increasing infraction count)
* $\gamma = 1.8$ (Super-linear power escalation)

**Guarantee**: Because $\gamma > 1.0$, alternating between good and bad actions produces a net downward drift in expected reputation $E(p) = \frac{\alpha}{\alpha + \beta}$, making opportunistic oscillating behavior mathematically unviable.

### 3.2. Continuous Time-Decay toward Uninformative Prior
Given elapsed seconds $\Delta t$ and wall-clock half-life $\tau$:
$$\text{decay\_ratio} = 2^{-\frac{\Delta t}{\tau}}$$
$$\alpha(t) = 1.0 + (\alpha_0 - 1.0) \cdot \text{decay\_ratio}, \quad \beta(t) = 1.0 + (\beta_0 - 1.0) \cdot \text{decay\_ratio}$$

**Guarantee**: Historical evidence decays toward $1.0$. An agent that has been dormant for multiple half-lives loses accrued trust and must re-verify reliability before accessing sensitive tools.
