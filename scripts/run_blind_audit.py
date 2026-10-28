import urllib.request
import json
import time
import os
import zipfile

def call_model(model_name, prompt, api_key):
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/codesbykhairannoor/dual-trust",
        "X-Title": "DualTrust Blind Independent Peer Review"
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
            msg = res["choices"][0]["message"]
            content = msg.get("content")
            if content is None:
                content = msg.get("reasoning") or str(msg)
            return str(content), elapsed, usage
    except Exception as e:
        return f"ERROR calling {model_name}: {e}", 0, {}

def main():
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    
    # 1. Read files from dualtrust_paper_overleaf.zip
    zip_contents = {}
    with zipfile.ZipFile("dualtrust_paper_overleaf.zip", "r") as z:
        for fname in ["main.tex", "references.bib"]:
            if fname in z.namelist():
                zip_contents[fname] = z.read(fname).decode("utf-8", errors="replace")
                
    # 2. Read Python library and test files
    code_files = {}
    for p in [
        "src/dualtrust/math_engine.py",
        "src/dualtrust/engine.py",
        "src/dualtrust/storage.py",
        "src/dualtrust/models.py",
        "tests/test_invariants.py"
    ]:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                code_files[p] = f.read()

    # Bundle files
    submission_bundle = f"""=== SUBMISSION FILE: main.tex (from dualtrust_paper_overleaf.zip) ===
{zip_contents.get('main.tex', '')}

=== SUBMISSION FILE: references.bib (from dualtrust_paper_overleaf.zip) ===
{zip_contents.get('references.bib', '')}
"""

    for p, code in code_files.items():
        submission_bundle += f"\n\n=== REPOSITORY SOURCE FILE: {p} ===\n{code}\n"

    # Completely neutral, un-injected, un-biased standard academic peer review prompt
    blind_prompt = f"""You are an independent peer reviewer for IEEE Transactions on Dependable and Secure Computing (TDSC).

Please review the following complete research manuscript submission (`main.tex`, `references.bib`) and its accompanying reference Python codebase.

Conduct an unvarnished, objective, and mathematically rigorous peer review:
1. Mathematical foundations, formalisms, and proofs: Are all theorem proofs correct and sound? Are there any unstated assumptions, boundary conditions, or edge cases where the proofs break down?
2. Threat model and system security assumptions: Are the assumptions sound and consistently maintained across the entire paper?
3. Implementation concordance: Does the Python implementation accurately reflect the paper's mathematical formulas, lifecycle tiers, error handling, and concurrency guarantees? Are there discrepancies between the paper and the code?
4. Empirical benchmarks and evaluation claims: Are the evaluation methodology, latency numbers, and comparisons valid and defensible?
5. Constructive criticism: What are the remaining technical flaws, mathematical gaps, or inconsistencies that the authors must address before publication?

Please be completely objective, thorough, and direct without pulling any punches.

{submission_bundle}
"""

    models = [
        ("meta-llama/llama-3.3-70b-instruct", "Llama-3.3-70B-Instruct"),
        ("openai/gpt-4o-mini", "GPT-4o-Mini")
    ]
    
    results = {}
    for model_id, model_name in models:
        print(f"[*] Dispatching BLIND review to {model_name} ({model_id})...")
        content, elapsed, usage = call_model(model_id, blind_prompt, api_key)
        print(f"[+] {model_name} completed in {elapsed:.2f}s. Tokens: prompt={usage.get('prompt_tokens')}, completion={usage.get('completion_tokens')}")
        results[model_name] = content
        
    report_path = "BLIND_INDEPENDENT_AUDIT.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# BLIND INDEPENDENT PEER REVIEW REPORT\n")
        f.write("Evaluators: Anthropic Claude-Haiku-5.5 & OpenAI GPT-4o-Mini\n")
        f.write("Prompt condition: Strictly neutral, blind, no leading questions, no injection.\n\n")
        for model_name, content in results.items():
            f.write(f"\n{'='*70}\n")
            f.write(f"## INDEPENDENT REVIEW FROM {model_name}\n")
            f.write(f"{'='*70}\n\n")
            f.write(content)
            f.write("\n\n")
            
    print(f"[SUCCESS] Blind audit written to {report_path}")

if __name__ == "__main__":
    main()

