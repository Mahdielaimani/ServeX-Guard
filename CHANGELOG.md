# Changelog

## 0.3.0

0.2.1 could not measure quality from a fresh install and still printed "Safe to
deploy". This release makes the measurements real and states their limits.

### Breaking

- Quality metrics now need a model you name (`llm.model` or `--llm-model`). Without
  one, nothing is sent anywhere and the gate exits `3`.
- New exit code `3`: a requested check could not be measured. It used to pass.
- A threshold of `0` now switches a metric off.
- Drift baselines must be rebuilt, with `--save-baseline`. A missing baseline blocks
  the gate and is no longer created implicitly.
- The default drift threshold moves from 0.25 to 0.20, and scores are not comparable
  with earlier versions.
- `context_precision` is gone. It was computed but never gated.
- `evaluate_quality` has a new signature and raises `QualityNotMeasuredError`.
- The `[eval]` and `[pii]` extras changed. `[pii]` no longer includes tiktoken, and
  spaCy models are now installed separately.

### Fixed

- `[eval]` crashed on import, and `[pii]` needed a Rust compiler.
- Drift could not tell one added word from a different topic.
- Presidio downloaded 400 MB at runtime and read French with an English model.
- A RIB was reported as a credit card.
- RAGAS telemetry is now off.
- `.json` array datasets load. A row that is not an object is a clear error.

### Security

- `--upload` no longer sends text quoted from the dataset. Earlier versions sent PII
  snippets in `raw_report`. If you uploaded with 0.2.x, your stored reports may
  contain them.
- Injection scans now cover retrieved contexts, and padding past 10,000 characters no
  longer hides a payload.

### Added

- Any OpenAI-compatible endpoint, local included.
- `--llm-injection`, an optional LLM judge for prompt injection.
- Injection rules for French, Arabic and Darija.
- `--pii-preset ma`: RIB with check key, CIN, phones, ICE, CNSS.
- CI that installs the built wheel with every extra and runs the real stacks.
