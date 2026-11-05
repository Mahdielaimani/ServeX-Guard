# Security Policy — ServeX Guard

ServeX Guard is a security tool. We hold ourselves to a higher standard.  
This document covers our security model, known protections, hardening guidance, and how to report vulnerabilities.

---

## Table of contents

- [Security model](#security-model)
- [What ServeX Guard protects against](#what-servex-guard-protects-against)
- [Data privacy — what leaves your machine](#data-privacy)
- [Input validation & hardening](#input-validation--hardening)
- [Dependency security](#dependency-security)
- [CI/CD security](#cicd-security)
- [Known limitations](#known-limitations)
- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Security changelog](#security-changelog)

---

## Security model

ServeX Guard follows a **local-first, zero-trust** security model:

```
Your machine / CI runner
│
├── Dataset (.jsonl)     → read locally, never uploaded
├── PII scan             → regex, or Presidio with an installed spaCy model.
│                          Never downloads a model at runtime
├── Injection rules      → pure regex, no network calls
├── Drift detection      → hashed n-grams, fully local
│
├── RAGAS quality eval   → calls only the LLM endpoint you name
└── Injection judge      → optional, calls only the LLM endpoint you name
                           Nothing is sent until you name a model, even if
                           OPENAI_API_KEY is set. The key is read from the
                           environment and never written to a report.
```

**ServeX Guard never:**
- Sends your dataset to any external server
- Stores your data anywhere except the report file you ask for
- Logs PII content
- Requires an account or authentication to run
- Phones home or sends telemetry (RAGAS's own telemetry is switched off)

**A local report file quotes what it found**, including the leaked value, so treat
it as sensitive. `--upload` strips anything quoted from your dataset before sending.

---

## What ServeX Guard protects against

### In your RAG system (what it scans)

| Threat | How ServeX Guard detects it |
|---|---|
| LLM hallucination | RAGAS faithfulness score < threshold → blocks deployment |
| PII leak in outputs | Presidio NER + regex patterns → flags before deployment |
| Prompt injection | Known phrasings in questions, answers and contexts, plus an optional LLM judge. See [measured limits](README.md#measured-limits) |
| Query drift | N-gram similarity vs a saved baseline → detects a shift in wording |
| Silent quality regression | Quality gate fails CI/CD before users are impacted |

### In ServeX Guard itself (its own hardening)

| Attack vector | Mitigation |
|---|---|
| Path traversal via --dataset | Path resolved + validated within working directory |
| Path traversal via --baseline | Same validation applied to all file writes |
| ReDoS via malicious input | All inputs truncated to 10K chars before regex scan |
| Oversized dataset (RAM exhaustion) | 50MB file size limit, 10K row limit, 50K char/field limit |
| Dependency compromise (supply chain) | All dependencies pinned to exact versions |
| Secret leakage in logs | Logs count only, never content — no PII in log output |
| Arbitrary file write (baseline) | Extension enforced (.npy only), path within cwd only |

---

## Data privacy

### What stays on your machine — always

```
golden_dataset.jsonl    → only read locally
PII scan results        → held in memory, discarded after run
Injection scan results  → held in memory, discarded after run
Drift baseline.npy      → written to your local path only
JSON/Markdown reports   → written to your local path only
```

### What goes to your LLM endpoint

Only when you name a model. RAGAS sends the questions, answers, contexts and ground
truths of the metrics you enabled. The injection judge sends the questions and
contexts, not the answers.

This goes to **the endpoint you configure**, which can be a local server. It does
not go to ServeX AI servers.

**To run with zero network calls** (air-gapped environments):

```bash
servexguard check \
  --dataset golden.jsonl \
  --min-faithfulness 0.0 \
  --min-relevancy 0.0 \
  --min-context-recall 0.0 \
  --check-pii \
  --check-injection
```

This skips quality evaluation entirely and runs only offline checks. It is also
the behaviour with no model named, except that the gate then exits `3` unless
those thresholds are `0`.

---

## Input validation & hardening

### Dataset validation

ServeX Guard enforces strict limits on input files:

```python
MAX_FILE_SIZE = 50MB      # Files larger than this are rejected
MAX_ROWS     = 10,000     # Only first 10K rows processed
MAX_FIELD    = 50,000     # chars per question/answer field
ALLOWED_EXT  = .jsonl     # Only JSONL files accepted
PATH_SCOPE   = cwd only   # Dataset must be within working directory
```

### Path traversal protection

All file paths (dataset, baseline, output report) are:
1. Resolved to absolute path (`Path.resolve()`)
2. Checked to be within the current working directory
3. Validated for allowed file extensions

Paths like `../../etc/passwd` or `C:\Windows\System32\config` are rejected.

### ReDoS protection

Each regex run sees at most 10,000 characters, which bounds backtracking on
adversarially crafted inputs. Injection scans walk long fields in overlapping
windows up to 200,000 characters, so padding cannot hide a payload below that. PII
scans read the first 10,000 characters of an answer.

### Baseline file protection

The drift baseline file (`.npy`) is:
- Only written within the working directory
- Extension enforced (`.npy` only)
- Read with `allow_pickle=False` to prevent deserialization attacks

---

## Dependency security

### Pinned versions

All dependencies in `pyproject.toml` are pinned to exact versions (`==`)
to prevent supply chain attacks via unexpected dependency updates.

### Minimal footprint

ServeX Guard avoids unnecessary dependencies. Each dependency
is justified:

| Dependency | Why it's included | Can you skip it? |
|---|---|---|
| `ragas` | Quality evaluation metrics | Yes — `--min-faithfulness 0.0` |
| `presidio-analyzer` | NER-based PII detection | Yes — regex fallback activates |
| `langchain-*`, `datasets` | Required by RAGAS, versions capped | With `ragas` |
| `numpy` | Drift detection math | No — core dependency |
| `pydantic` | Config validation | No — core dependency |
| `typer` | CLI framework | No — core dependency |
| `rich` | Terminal output | No — core dependency |

### Checking for known vulnerabilities

```bash
# Check your ServeX Guard installation for CVEs
pip install pip-audit
pip-audit

# Or with Safety
pip install safety
safety check
```

### Verifying the package (PyPI)

```bash
# Verify the package hash after installing
pip download servex-guard --no-deps -d /tmp/sg
sha256sum /tmp/sg/servex_guard-*.whl
# Compare with the hash published in the GitHub release notes
```

---

## CI/CD security

### GitHub Actions hardening

When using ServeX Guard in GitHub Actions, follow these practices:

```yaml
jobs:
  servex-guard:
    runs-on: ubuntu-latest
    
    # Pin to a specific commit hash, not a floating tag
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-python@0b93645e9fea7318ecaed2dc359ef8b7caa543ad # v5.3.0

    # Minimal permissions
    permissions:
      contents: read

    # Never pass secrets directly — use GitHub Secrets
    env:
      AZURE_OPENAI_ENDPOINT: ${{ secrets.AZURE_OPENAI_ENDPOINT }}
      AZURE_OPENAI_KEY: ${{ secrets.AZURE_OPENAI_KEY }}
```

### Secret scanning

ServeX Guard's own CI runs Gitleaks on every push to detect
accidentally committed secrets:

```yaml
- name: Scan for secrets
  uses: gitleaks/gitleaks-action@v2
```

### What to NEVER put in your golden dataset

```
❌ Real customer names
❌ Real IBANs or account numbers  
❌ Real national ID numbers
❌ Real API keys or passwords
❌ Real email addresses of actual people
✅ Use synthetic / anonymized data only
```

---

## Known limitations

These are security limitations we are aware of and plan to address:

### v0.3.0 known limitations

| Limitation | Risk level | Planned fix |
|---|---|---|
| Injection rules miss reworded attacks (0 of 40 in testing) | High if used alone | Use `--llm-injection` |
| The LLM judge can be fooled by the text it reads | Medium | Better defences, to be measured |
| Judge weak on Darija in Latin script (3 of 8 in testing) | Medium | Larger Darija test set |
| RAGAS 0.4.3 pins LangChain below 1.0 and uses APIs it has deprecated | Low | Follow RAGAS's migration |
| Drift sees wording, not meaning | Low | Real embeddings |
| No SBOM (Software Bill of Materials) generated | Low | CycloneDX SBOM |
| No code signing on PyPI releases | Medium | Sigstore signing |

### What ServeX Guard does NOT protect against

ServeX Guard is a **pre-deployment** quality gate. It does NOT:

- Monitor your RAG system in real-time production (→ ServeX Guard Cloud)
- Protect against attacks that happen at inference time
- Guarantee your RAG system is secure — it checks quality and known patterns
- Replace a full security audit of your RAG architecture

---

## Reporting a vulnerability

**Do NOT open a public GitHub Issue for security vulnerabilities.**

### Contact

**Email:** mahdielaimani@gmail.com  
**Subject line:** `[SECURITY] ServeX Guard — <short description>`  
**Response SLA:** 48 hours acknowledgment, 7 days for a fix plan

### What to include

```
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Your suggested fix (optional but appreciated)
5. Your name/handle for the credits section (optional)
```

### What happens next

```
Day 1   → Acknowledgment email
Day 1-7 → We reproduce and assess severity
Day 7   → Fix developed and tested
Day 14  → Patch released (earlier for critical issues)
Day 14  → CVE requested if applicable
Day 21  → Public disclosure (coordinated with reporter)
```

### Severity classification

| Severity | Example | Response time |
|---|---|---|
| Critical | RCE, arbitrary file write, data exfiltration | 24 hours |
| High | Path traversal, ReDoS, auth bypass | 72 hours |
| Medium | Information disclosure, logic flaw | 7 days |
| Low | Minor issue, hardening improvement | 30 days |

### Security hall of fame

We publicly credit researchers who responsibly disclose vulnerabilities.
Your name and a description of your finding will appear here.

*No entries yet — be the first.*

---

## Security changelog

### v0.1.0 (current)

- Path traversal protection on all file inputs
- ReDoS mitigation via input truncation (10K chars)
- Dataset size limits (50MB / 10K rows / 50K chars per field)
- Baseline file extension enforcement (.npy only)
- Baseline deserialization hardened (allow_pickle=False)
- All dependencies pinned to exact versions
- No telemetry, no external calls for offline checks
- PII content never logged — counts only

---

*This document is updated with each release.*  
*Last updated: June 2026 — ServeX Guard v0.1.0*  
*Maintained by El Mahdi El Aimani · ServeX AI*
