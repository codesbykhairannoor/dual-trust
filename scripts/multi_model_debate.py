import urllib.request
import json
import time
import os

inference_key = os.environ.get('OPENROUTER_API_KEY', '')

with open('paper/main.tex', 'r', encoding='utf-8') as f:
    paper_text = f.read()

with open('src/dualtrust/math_engine.py', 'r', encoding='utf-8') as f:
    math_engine_code = f.read()

def call_model(model_name: str, messages: list, max_tokens: int = 3500) -> str:
    print(f"\n>>> Calling {model_name}...")
    payload = {
        'model': model_name,
        'messages': messages,
        'temperature': 0.2,
        'max_tokens': max_tokens
    }
    req = urllib.request.Request(
        'https://openrouter.ai/api/v1/chat/completions',
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {inference_key}',
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://github.com/codesbykhairannoor/dual-trust',
            'X-Title': 'DualTrust Multi-AI Arena'
        }
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                res = json.loads(resp.read().decode('utf-8'))
                msg = res['choices'][0]['message']
                content = msg.get('content') or msg.get('reasoning') or ''
                return content.strip()
        except Exception as e:
            print(f"Retry {attempt+1} on {model_name} due to: {e}")
            time.sleep(3)
    return f"[ERROR: Failed to call {model_name}]"

def main():
    transcript = []
    transcript.append("# MULTI-MODEL ADVERSARIAL DEBATE & CONSENSUS ARENA\n")
    transcript.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
    transcript.append("**Auditors:** OpenAI GPT-4o, DeepSeek-Chat, Google Gemini 2.5 Pro, Anthropic Claude Sonnet 5.5\n")
    transcript.append("**Target:** DualTrust IEEE TDSC Manuscript (`paper/main.tex`) & Implementation (`src/dualtrust/math_engine.py`)\n\n---\n")

    # -------------------------------------------------------------
    # ROUND 1: GPT-4o Attack
    # -------------------------------------------------------------
    print("\n=== ROUND 1: GPT-4o ATTACK ===")
    prompt_gpt = f"""You are Reviewer 1 (GPT-4o) on the IEEE TDSC panel.
Perform a ruthless, adversarial audit of this revised manuscript.
Check specifically:
- Equation (10) penalty scaling and Equation (13) flat reward (0.20)
- Section IV-C Salami non-viability and Section IV-D Sybil Shield
- Section IV-E Whitewashing & Section IV-F False-Positive Mitigation / Strike Recovery
- Section VII.B Trojan sleeper numbers (T drops 0.8980 -> 0.1964) and Salami slicer numbers (0.9153 -> 0.5745 -> 0.2638 -> 0.1300)
- Systems: 64-striped locks, BaseException rollback, SQLite WAL

State every single vulnerability, flaw, or inconsistency you can find. Be completely ruthless.

MANUSCRIPT EXCERPTS / TEXT:
{paper_text}
"""
    r1_gpt = call_model('openai/gpt-4o', [{'role': 'user', 'content': prompt_gpt}])
    transcript.append("## ROUND 1: INITIAL ADVERSARIAL ATTACK (OpenAI GPT-4o)\n\n" + r1_gpt + "\n\n---\n")

    # -------------------------------------------------------------
    # ROUND 2: DeepSeek-Chat Cross-Examination
    # -------------------------------------------------------------
    print("\n=== ROUND 2: DEEPSEEK CROSS-EXAMINATION ===")
    prompt_deepseek = f"""You are Reviewer 2 (DeepSeek-Chat) on the IEEE TDSC panel.
You have read the manuscript and GPT-4o's attack above.
Here is GPT-4o's attack:
{r1_gpt}

Here is the actual Python implementation of the math engine:
```python
{math_engine_code}
```

Cross-examine GPT-4o's attack:
1. Did GPT-4o make any mathematical errors or hallucinations?
2. Does the Python implementation actually match the paper's claims and formulas?
3. What additional structural, algorithmic, or cryptographic holes (if any) do you spot?
"""
    r2_deepseek = call_model('deepseek/deepseek-chat', [{'role': 'user', 'content': prompt_deepseek}])
    transcript.append("## ROUND 2: CROSS-EXAMINATION & CODE VERIFICATION (DeepSeek-Chat)\n\n" + r2_deepseek + "\n\n---\n")

    # -------------------------------------------------------------
    # ROUND 3: Claude Sonnet 5.5 Final Audit & Resolution
    # -------------------------------------------------------------
    print("\n=== ROUND 3: CLAUDE SONNET 5.5 AUDIT & RESOLUTION ===")
    prompt_claude = f"""You are Senior Lead Reviewer (Claude Sonnet 5.5) for IEEE TDSC.
You previously laid down the stopping criteria for this paper:
1. Flat Delta_alpha = 0.20 in Eq. (13) matching simulation.
2. Honest framing that Trojan is caught by dual-containment (PROTOCOL_TRESPASS fail-safe killswitch + Bayesian collapse).
3. Section IV-F on false positive mitigation, strike forgiveness/decay window (W_recovery=20), and bilateral endpoint attribution.
4. Small inconsistencies (sev=5.0 in VII.D, status enum alignment, 32x-60x speedup, algorithm line references, Fig 1 title).

Review the revised manuscript text in light of GPT-4o's critique and DeepSeek's cross-examination:

GPT-4o:
{r1_gpt}

DeepSeek:
{r2_deepseek}

Give your authoritative assessment:
1. Have all stopping criteria been met?
2. Are GPT-4o or DeepSeek's remaining points valid or already solved in the revised text/code?
3. What is your final publication recommendation for IEEE TDSC (Accept / Major Revision / Reject)?
"""
    r3_claude = call_model('anthropic/claude-sonnet-5.5', [{'role': 'user', 'content': prompt_claude}], max_tokens=4000)
    transcript.append("## ROUND 3: SENIOR AUDITOR RULING & VERDICT (Anthropic Claude Sonnet 5.5)\n\n" + r3_claude + "\n\n---\n")

    # -------------------------------------------------------------
    # ROUND 4: Gemini 2.5 Pro Consensus Sign-off
    # -------------------------------------------------------------
    print("\n=== ROUND 4: GEMINI 2.5 PRO CONSENSUS SIGN-OFF ===")
    prompt_gemini = f"""You are the Area Chair (Google Gemini 2.5 Pro) presiding over the IEEE TDSC panel.
You have observed the entire debate between GPT-4o, DeepSeek-Chat, and Claude Sonnet 5.5.

Claude's Ruling:
{r3_claude}

Provide the final Area Chair decision:
1. Summarize where the panel has reached 100% consensus.
2. Confirm whether the paper has achieved the necessary mathematical rigor, engineering validity, and defensibility for IEEE TDSC.
3. Final Verdict and action items for the author.
"""
    r4_gemini = call_model('google/gemini-2.5-pro', [{'role': 'user', 'content': prompt_gemini}])
    transcript.append("## ROUND 4: AREA CHAIR FINAL CONSENSUS & SIGN-OFF (Google Gemini 2.5 Pro)\n\n" + r4_gemini + "\n\n")

    with open('ADVERSARIAL_DEBATE_TRANSCRIPT.md', 'w', encoding='utf-8') as f:
        f.write(''.join(transcript))

    print("\nAdversarial Multi-Model Debate Complete! Saved to ADVERSARIAL_DEBATE_TRANSCRIPT.md")

if __name__ == '__main__':
    main()

