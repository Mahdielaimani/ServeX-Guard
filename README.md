<p align="center">
  <img src="https://raw.githubusercontent.com/Mahdielaimani/ServeX-Guard/main/assets/logo.jpeg" width="160" alt="ServeX Guard" />
</p>

<h1 align="center">ServeX Guard</h1>

<p align="center">
  <strong>Production quality gate for RAG & LLM systems.</strong><br>
  Evaluate quality · Detect PII leaks · Block prompt injections · Stop drift.<br>
  <em>One command. In your CI/CD. Before it reaches production.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/servex-guard">
    <img src="https://img.shields.io/pypi/v/servex-guard?color=2563EB&label=pypi&logo=python&logoColor=white" alt="PyPI"/>
  </a>
  <a href="https://github.com/Mahdielaimani/ServeX-Guard/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Mahdielaimani/ServeX-Guard/ci.yml?label=CI&logo=github&logoColor=white" alt="CI"/>
  </a>
  <a href="https://opensource.org/licenses/Apache-2.0">
    <img src="https://img.shields.io/badge/License-Apache%202.0-F97316?logo=apache&logoColor=white" alt="License"/>
  </a>
  <a href="https://github.com/Mahdielaimani/ServeX-Guard/stargazers">
    <img src="https://img.shields.io/github/stars/Mahdielaimani/ServeX-Guard?style=social" alt="Stars"/>
  </a>
  <a href="https://pypi.org/project/servex-guard">
    <img src="https://img.shields.io/pypi/dm/servex-guard?label=downloads&color=2563EB" alt="Downloads"/>
  </a>
</p>

<p align="center">
  <a href="https://elaimani.io">Website</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#%EF%B8%8F-cicd-integration">CI/CD</a> ·
  <a href="#%EF%B8%8F-configuration">Config</a> ·
  <a href="#%EF%B8%8F-roadmap">Roadmap</a>
</p>

---

## The Problem

You deployed a RAG system. It worked great in dev.

Then in production:
- The LLM **hallucinated** on a financial document → wrong advice to a customer
- A prompt injection **leaked internal data** through the response
- A regulatory update wasn't indexed → the system **drifted silently** for 2 weeks
- PII (national IDs, IBANs, emails) **passed through** to the LLM and got logged

**Nobody noticed until the client complained.**

## The Solution

ServeX Guard is a single CLI command that checks your RAG system **before** deployment:

```bash
pip install servex-guard

servexguard check \
  --dataset golden_dataset.jsonl \
  --min-faithfulness 0.80 \
  --check-pii \
  --check-injection
```

```
🛡️ ServeX Guard Quality Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Quality Metrics
   Faithfulness      0.87  ✅  (min: 0.80)
   Answer Relevancy  0.82  ✅  (min: 0.75)
   Context Recall    0.79  ✅  (min: 0.70)

🔒 Security Scan
   PII detected      0 leaks  ✅
   Injection risks   0 found  ✅

📈 Drift Detection
   Query drift score 0.12  ✅  (max: 0.25)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ QUALITY GATE PASSED — Safe to deploy
```

If any check fails → **exit code 1** → CI/CD stops → bad code never reaches production.

---

## Quick Start

### Install

```bash
pip install servex-guard
```

### Prepare your golden dataset

A JSONL file with reference Q&A pairs your RAG system should answer correctly:

```jsonl
{"question": "What is the deductible?", "ground_truth": "500€", "answer": "The deductible is 500€ as stated in Article 4.", "contexts": ["Article 4: The deductible is fixed at 500€..."]}
{"question": "How do I file a claim?", "ground_truth": "Call 0800-123-456", "answer": "Call 0800-123-456 within 5 business days.", "contexts": ["Claims can be filed via phone at 0800-123-456..."]}
```

### Run

```bash
# Basic quality check
servexguard check --dataset golden_dataset.jsonl

# Full check — quality + security + output report
servexguard check \
  --dataset golden_dataset.jsonl \
  --min-faithfulness 0.80 \
  --min-relevancy 0.75 \
  --check-pii \
  --check-injection \
  --output report.json
```

### Send results to ServeX Guard Cloud (optional)

`--upload` posts the computed report to your Cloud dashboard. Everything is still
computed locally — the Cloud only receives the finished JSON.

```bash
export SERVEXGUARD_API_KEY=sxg_...          # from dashboard.servexguard.com → Settings
servexguard check --dataset golden_dataset.jsonl --upload --project my-rag-app
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--upload` | off | Post the report to the Cloud |
| `--project` | `default` | Cloud project name (created on first upload) |
| `--cloud-url` | `https://api.servexguard.com/v1/runs` | Override the ingest endpoint (or `SERVEXGUARD_CLOUD_URL`) |

An upload failure never fails the run: it prints a warning and keeps the exit code
from your quality gate.

### Use in Python

```python
from servexguard import ServeXGuard

guard = ServeXGuard(
    min_faithfulness=0.80,
    min_relevancy=0.75,
    check_pii=True,
    check_injection=True,
)

result = guard.check("golden_dataset.jsonl")

if result.passed:
    print("✅ Safe to deploy")
else:
    print(f"❌ Blocked: {result.failures}")
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: RAG Quality Gate

on: [push, pull_request]

jobs:
  servex-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - run: pip install servex-guard

      - name: ServeX Guard Quality Gate
        run: |
          servexguard check \
            --dataset data/golden_dataset.jsonl \
            --min-faithfulness 0.80 \
            --check-pii \
            --check-injection
        env:
          AZURE_OPENAI_ENDPOINT: ${{ secrets.AZURE_OPENAI_ENDPOINT }}
```

### Azure DevOps

```yaml
- task: Bash@3
  displayName: 'ServeX Guard Quality Gate'
  inputs:
    targetType: inline
    script: |
      pip install servex-guard
      servexguard check \
        --dataset $(Build.SourcesDirectory)/data/golden_dataset.jsonl \
        --min-faithfulness 0.80 \
        --check-pii
```

---

## What ServeX Guard Checks

### Quality metrics (via RAGAS)

| Metric | What it measures | Default |
|---|---|---|
| **Faithfulness** | Answer grounded in retrieved context? | ≥ 0.80 |
| **Answer Relevancy** | Answer addresses the question? | ≥ 0.75 |
| **Context Recall** | Retrieval found the right documents? | ≥ 0.70 |
| **Context Precision** | Retrieved docs actually relevant? | ≥ 0.70 |

### Security scanning

| Check | What it catches |
|---|---|
| **PII Detection** | IBANs, national IDs, emails, phone numbers in LLM output |
| **Prompt Injection** | Jailbreaks, system prompt leaks, instruction overrides |
| **Data Leakage** | Internal references, file paths, API keys in responses |

### Drift detection

| Check | What it catches |
|---|---|
| **Query Drift** | Users asking outside the calibration zone |
| **Quality Drift** | Faithfulness degrading over time |
| **Document Drift** | Source documents changed but index not updated |

---

## Configuration

Create a `servexguard.yaml` in your project root:

```yaml
quality:
  min_faithfulness: 0.80
  min_relevancy: 0.75
  min_context_recall: 0.70

security:
  check_pii: true
  pii_entities:
    - IBAN
    - NATIONAL_ID
    - EMAIL
    - PHONE_NUMBER
  check_injection: true

drift:
  enabled: true
  max_query_drift: 0.25
  baseline_file: "data/baseline_embeddings.npy"

dataset:
  path: "data/golden_dataset.jsonl"

output:
  format: json
  path: "reports/report.json"
```

Then run:

```bash
servexguard check  # reads servexguard.yaml automatically
```

---

## Architecture

```
Your RAG system
      ↓ golden_dataset.jsonl
┌──────────────────────────────┐
│      ServeX Guard CLI        │
│                              │
│  Evaluator   → RAGAS         │  Quality scores
│  Security    → Presidio      │  PII + injection
│  Drift       → cosine sim    │  Distribution shift
│  Reporter    → JSON/MD/CLI   │  Report + exit code
└──────────────────────────────┘
        ↓
  exit(0) ✅  or  exit(1) ❌
        ↓
  CI/CD continues or stops
```

---

## Who is this for?

- **AI Engineers** deploying RAG to production and needing a safety net
- **MLOps teams** who want automated quality checks in their pipelines
- **Enterprises** in banking, insurance, and healthcare with compliance requirements
- **Consultants** delivering RAG projects to clients who need audit trails

---

## Roadmap

- [x] Quality evaluation (RAGAS)
- [x] PII detection (Presidio + regex fallback)
- [x] Prompt injection scanning (12 patterns)
- [x] CLI with exit codes for CI/CD
- [x] YAML configuration
- [ ] Drift detection (query + quality + document)
- [ ] GitHub Action (marketplace)
- [ ] Dashboard (ServeX Guard Cloud)
- [ ] Slack / Teams alerts
- [ ] Arabic, French & Darija PII support
- [ ] Compliance PDF reports (ACAPS / BAM / RGPD)

---

## Contributing

ServeX Guard welcomes contributions! We follow an **Issue-first**
process — please open an Issue before submitting a PR.
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

```bash
git clone https://github.com/Mahdielaimani/ServeX-Guard.git
cd ServeX-Guard
pip install -e ".[dev]"
pytest
```

---

## License

Apache 2.0 — free for commercial use.

---

## Author

**El Mahdi El Aimani** — Senior AI Engineer · LLMOps Architect · ServeX AI

Built from production experience deploying RAG systems at Crédit Agricole du Maroc and OCP NutriCrops.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-El%20Mahdi%20El%20Aimani-2563EB?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/el-mahdi-el-aimani-bb5555227)
[![GitHub](https://img.shields.io/badge/GitHub-Mahdielaimani-333?logo=github&logoColor=white)](https://github.com/Mahdielaimani)
[![Instagram](https://img.shields.io/badge/Instagram-@elmahdi.ai-F97316?logo=instagram&logoColor=white)](https://instagram.com/elmahdi.ai)

---

<p align="center">
  Made with care in Morocco 🇲🇦 · by <a href="https://elaimani.io">ServeX AI</a>
</p>