import urllib.request
import json
import time
import os

def call_model(model_name, prompt, api_key):
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/codesbykhairannoor/dual-trust",
        "X-Title": "DualTrust Simple Raw Audit"
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
    
    with open("paper/main.tex", "r", encoding="utf-8") as f:
        main_tex = f.read()
        
    code_bundle = ""
    for p in ["src/dualtrust/math_engine.py", "src/dualtrust/engine.py", "src/dualtrust/storage.py", "src/dualtrust/models.py"]:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                code_bundle += f"\n\n{'='*40}\nFILE: {p}\n{'='*40}\n{f.read()}\n"

    simple_prompt = f"""Berikut adalah naskah lengkap paper IEEE TDSC (`main.tex`) dan seluruh source code referensi Python (`src/dualtrust/`).

Jawab jujur dan blak-blakan tanpa basa-basi:
Nih bener ga jurnal gue?
1. Apakah paper ini ada halusinasi klaim atau angka yang fiktif? Cek angka latency (47.10 us RAM, 88.30 us gate, 155.80 us WAL) dan hasil simulasi Trojan/Salami terhadap kodenya.
2. Apakah konsisten antara naskah paper dengan implementasi kode Python aslinya?
3. Apakah rumusan matematika (Bayesian, Power-law slashing, Teorema 1, Sybil shield) valid dan pembuktiannya masuk akal?
4. Apakah naskah ini layak submit ke IEEE TDSC atau masih ada cacat yang bikin auto-reject? Jika ada bagian di main.tex yang masih cacat, tunjukkan barisnya dan berikan kode LaTeX perbaikannya.

=== FILE: paper/main.tex ===
{main_tex}

=== IMPLEMENTASI KODE PYTHON ===
{code_bundle}
"""

    models = [
        ("deepseek/deepseek-chat", "DeepSeek-V3"),
        ("google/gemini-2.5-flash", "Gemini-2.5-Flash")
    ]
    
    results = {}
    for model_id, model_name in models:
        print(f"[*] Menanyakan ke {model_name}...")
        content, elapsed, usage = call_model(model_id, simple_prompt, api_key)
        print(f"[+] {model_name} selesai ({elapsed:.2f}s). Prompt tokens={usage.get('prompt_tokens')}, output={usage.get('completion_tokens')}")
        results[model_name] = content
        
    out_file = "RAW_AI_VERDICT.md"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("# RAW VERDICT DARI AI LAIN DENGAN PROMPT SEDERHANA\n")
        f.write("Prompt: 'Nih bener ga jurnal gue? Halu kah? Konsisten kah?'\n\n")
        for m_name, text in results.items():
            f.write(f"\n{'='*70}\n## JAWABAN DARI {m_name}\n{'='*70}\n\n")
            f.write(text)
            f.write("\n\n")
            
    print(f"[SELESAI] Hasil disimpan ke {out_file}")

if __name__ == "__main__":
    main()

