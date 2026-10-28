import urllib.request
import json
import time
import os
import sys

def call_model(model_name, prompt, api_key):
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/codesbykhairannoor/dual-trust",
        "X-Title": "DualTrust Rigorous Peer Review"
    }
    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2,
        "max_tokens": 4096
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers)
    
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            elapsed = time.time() - start
            usage = res.get("usage", {})
            content = res["choices"][0]["message"]["content"]
            return content, elapsed, usage
    except Exception as e:
        return f"ERROR calling {model_name}: {e}", 0, {}

def main():
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    
    # 1. Load full main.tex
    with open("paper/main.tex", "r", encoding="utf-8") as f:
        main_tex = f.read()
    
    # 2. Load Python source files
    py_files = {}
    for p in ["src/dualtrust/math_engine.py", "src/dualtrust/engine.py", "src/dualtrust/storage.py", "src/dualtrust/models.py"]:
        with open(p, "r", encoding="utf-8") as f:
            py_files[p] = f.read()
            
    code_bundle = ""
    for p, content in py_files.items():
        code_bundle += f"\n\n{'='*50}\nFILE: {p}\n{'='*50}\n{content}\n"
        
    audit_prompt = f"""You are a distinguished Senior Security Auditor and Area Chair for IEEE Transactions on Dependable and Secure Computing (TDSC).

Below is the COMPLETE, UNTRUNCATED manuscript `paper/main.tex` and the COMPLETE Python implementation of the DualTrust governance framework.

Your task is to conduct an uncompromising, mathematically rigorous, line-by-line verification of the paper against the code.

Pay rigorous attention to:
1. Theorem 1 (Finite-Horizon Salami-Slicing Non-Viability) vs Section IV.F/IV.G (Active Strike Recovery W_recovery = 20):
   - What happens if an adaptive adversary complies for k >= W_recovery clean actions between infractions? Does v_a decay? Does the power-law penalty escalate?
   - What exact mathematical precondition (e.g. k < W_recovery) must be added to Theorem 1, and what must be stated in Limitations?
2. Consistency between Threat Model (Section III-B: trusted host OS kernel & Python runtime) and claims in the paper (e.g., does any claim contradict the trusted runtime assumption)?
3. False-Positive Mitigation & Framing Defense (Section IV.G):
   - Provide concrete numerical verification using the engine formulas: e.g. for an agent at (alpha=20, beta=1, T=0.952), what is the exact trust trajectory with and without endpoint attribution under transient timeouts?
   - Does active redemption reduce beta or only v_a?
4. Literature baseline comparison clarity in Table I and Section VII.B:
   - Ensure latency speedup claims (47.10 us RAM median, 88.30 us @gate median, 155.80 us SQLite WAL) clearly distinguish between measured workstation latencies and literature baseline references.
5. Provide exact line numbers and concrete LaTeX snippet replacements for any required fixes.

=== BEGIN PAPER: paper/main.tex ===
{main_tex}
=== END PAPER: paper/main.tex ===

=== BEGIN CODEBASE IMPLEMENTATION ===
{code_bundle}
=== END CODEBASE IMPLEMENTATION ===
"""

    models = [
        ("deepseek/deepseek-chat", "DeepSeek-V3"),
        ("google/gemini-2.5-flash", "Gemini-2.5-Flash")
    ]
    
    results = {}
    for model_id, model_name in models:
        print(f"[*] Dispatching FULL manuscript + codebase audit to {model_name} ({model_id})...")
        content, elapsed, usage = call_model(model_id, audit_prompt, api_key)
        print(f"[+] {model_name} completed in {elapsed:.2f}s. Tokens: prompt={usage.get('prompt_tokens')}, completion={usage.get('completion_tokens')}")
        results[model_name] = content
        
    # Write report
    report_path = "TWO_FRONTIER_MODELS_AUDIT.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# FULL-CONTEXT AUDIT: DEEPSEEK-V3 & GEMINI-2.5-FLASH\n")
        f.write(f"Target: Full `paper/main.tex` ({len(main_tex)} chars) & Complete `src/dualtrust/` codebase\n\n")
        for model_name, content in results.items():
            f.write(f"\n{'='*70}\n")
            f.write(f"## AUDIT REPORT FROM {model_name}\n")
            f.write(f"{'='*70}\n\n")
            f.write(content)
            f.write("\n\n")
            
    print(f"[SUCCESS] Audit report written to {report_path}")

if __name__ == "__main__":
    main()

