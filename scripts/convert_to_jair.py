import re

with open('paper/main.tex', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Preamble replacement
# Replace from \documentclass up to \maketitle
preamble_acm = r"""\documentclass[acmsmall,screen,review,nonacm]{acmart}

% Ensure compatibility with ACM / JAIR guidelines
\settopmatter{printfolios=true,printacmref=false}
\setcopyright{none}
\renewcommand\footnotetextcopyrightpermission[1]{}
\pagestyle{plain}

% Math and utility packages
\usepackage{amsmath,amssymb,amsfonts}
\usepackage{algorithmic}
\usepackage{algorithm}
\usepackage{graphicx}
\usepackage{textcomp}
\usepackage{xcolor}
\usepackage{booktabs}
\usepackage{microtype}
\usepackage{enumitem}
\usepackage{balance}

\begin{document}

\title[DualTrust: Asymmetric Bayesian Governance for Autonomous Agents]{DualTrust: An Ultra-Low-Latency Asymmetric Bayesian Governance Framework for Resilient Autonomous Agent Containment in Cyber-Physical Systems}

\author{Khairan Noor Fadhlillah}
\email{dev@khairan.tech}
\affiliation{%
  \institution{Department of Computer Science, Universitas Ary Ginanjar}
  \city{Jakarta}
  \country{Indonesia}
}

\begin{abstract}
The proliferation of Ambient Wearable Intelligence (AWI) ecosystems---spanning augmented reality glasses, smartwatches, and pervasive edge IoT actuators---is fundamentally transitioning human-AI interaction from explicit tactile commands to continuous, implicit background tool delegation. In these ambient environments, autonomous Large Language Model (LLM) agents are granted operational authority to invoke external APIs, reserve financial micro-quotas, and control physical actuators. However, existing safety guardrails depend on secondary LLM-as-a-judge classifiers that introduce prohibitive runtime latencies (400--850\,ms) and recurring token expenses, while static role-based access control fails against continuous behavioral drift, memory backdoors, and interleaved salami-slicing exploits. We present \textbf{DualTrust}, an ultra-low-latency asymmetric Bayesian governance framework engineered specifically for autonomous multi-agent cyber-physical containment. DualTrust enforces a decoupled principal-agent architecture that strictly isolates Human Principal Accountable Credit from Bayesian Agent Operational Standing. Agent behavior is continuously modulated via an asymmetric power-law slashing engine ($\Delta\beta \propto (\text{sev} \cdot c^2) \cdot v_a^{1.8}$) with instantaneous clean-streak reset, deterministic SHA-256 64-bucket striped concurrency locks, atomically locked rollback refunds, and an $\mathcal{O}(1)$ RAM sliding-window RFC~6962 Merkle audit ledger with rolling epoch seals that bounds active memory consumption by committing historical roots to persistent storage. Evaluated across 176 automated invariant tests and 10,000-cycle Monte Carlo attack simulations, DualTrust makes deterministic authorization verdicts in a median latency of \textbf{47.10\,$\mu$s} in-memory (mean 63.16\,$\mu$s, tail p99 287.10\,$\mu$s) and \textbf{155.80\,$\mu$s} under persistent SQLite WAL disk transactions, with end-to-end Python decorator wrappers executing in median 60.70\,$\mu$s (async) and 88.30\,$\mu$s (sync) without external API calls. Compared against state-of-the-art LLM guardrails, DualTrust achieves over \textbf{6,600$\times$} lower latency (and over \textbf{32$\times$} to \textbf{50$\times$} lower latency than localized AST validators), by policy construction blocks Sybil defamation against collusive probation swarms, and provides tamper-evident, append-only audit durability with RFC~6962 inclusion verification, establishing a practical, foundational governance runtime for trustworthy ambient intelligence.
\end{abstract}

\keywords{Autonomous Agents, Multi-Agent Governance, Bayesian Trust Systems, Cyber-Physical Systems, Salami-Slicing Resistance, Merkle Audit Trails, Zero-Trust Architecture}

\maketitle
"""

# Extract the body starting from \section{Introduction}
body_start_idx = text.find(r'\section{Introduction}')
assert body_start_idx != -1, "Could not find \\section{Introduction}"
body = text[body_start_idx:]

# Remove \IEEEPARstart{D}{istributed} -> Distributed
body = body.replace(r'\IEEEPARstart{D}{istributed}', 'Distributed')

# Remove \IEEEproof -> proof
body = body.replace(r'\begin{IEEEproof}', r'\begin{proof}')
body = body.replace(r'\end{IEEEproof}', r'\end{proof}')

# Remove \IEEEpeerreviewmaketitle if present
body = body.replace(r'\IEEEpeerreviewmaketitle', '')

# Replace \bibliographystyle{IEEEtran} with \bibliographystyle{ACM-Reference-Format}
body = body.replace(r'\bibliographystyle{IEEEtran}', r'\bibliographystyle{ACM-Reference-Format}')

# Remove \vfill\newpage if it was added for IEEEtran column break
body = body.replace(r'\vfill\newpage', '')

# Replace width=\columnwidth with width=\linewidth or width=0.85\linewidth for single column
body = body.replace(r'width=\columnwidth', r'width=0.88\linewidth')

jair_text = preamble_acm + "\n" + body

with open('paper/jair_main.tex', 'w', encoding='utf-8') as f:
    f.write(jair_text)

print(f"SUCCESS: Created paper/jair_main.tex ({len(jair_text)} bytes)!")
