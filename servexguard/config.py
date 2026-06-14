"""
YAML configuration loader for ServeXGuard.

Loads ``servexguard.yaml`` (auto-discovered or explicit path), validates it
with Pydantic, and exposes sensible defaults so the tool works with no config.

CLI flags override YAML values — see :func:`merge_cli_overrides`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

CONFIG_FILENAME = "servexguard.yaml"

DEFAULT_PII_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IBAN_CODE",
    "CREDIT_CARD",
    "PERSON",
]


class QualityConfig(BaseModel):
    """Quality (RAGAS) thresholds."""

    min_faithfulness: float = 0.80
    min_relevancy: float = 0.75
    min_context_recall: float = 0.70


class CustomEntity(BaseModel):
    """A user-defined PII entity (regex pattern + label).

    Lets users add locale-specific detection (e.g. Moroccan CIN, French CNSS)
    without hardcoding it in the core, keeping ServeXGuard global-first.
    """

    pattern: str
    label: str = "CUSTOM_ENTITY"


class SecurityConfig(BaseModel):
    """PII + prompt injection scan settings."""

    check_pii: bool = False
    pii_entities: list[str] = Field(default_factory=lambda: list(DEFAULT_PII_ENTITIES))
    language: str = "en"
    check_injection: bool = False
    custom_entities: list[CustomEntity] = Field(default_factory=list)


class DriftConfig(BaseModel):
    """Query distribution drift settings."""

    enabled: bool = False
    max_query_drift: float = 0.25
    baseline_file: str | None = None


class DatasetConfig(BaseModel):
    """Dataset location."""

    path: str | None = None


class OutputConfig(BaseModel):
    """Report output settings."""

    format: str = "terminal"  # terminal | json | markdown
    path: str | None = None


class ServeXGuardConfig(BaseModel):
    """Top-level ServeXGuard configuration."""

    quality: QualityConfig = Field(default_factory=QualityConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    drift: DriftConfig = Field(default_factory=DriftConfig)
    dataset: DatasetConfig = Field(default_factory=DatasetConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


def find_config(start: str | Path | None = None) -> Path | None:
    """Auto-discover ``servexguard.yaml`` from ``start`` upward to filesystem root.

    Args:
        start: Directory to begin searching from. Defaults to current dir.

    Returns:
        Path to the config file, or ``None`` if not found.
    """
    current = Path(start or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            logger.debug("Found config: %s", candidate)
            return candidate
    return None


def load_config(path: str | Path | None = None) -> ServeXGuardConfig:
    """Load and validate configuration.

    Args:
        path: Explicit config path. If ``None``, auto-discovers
            ``servexguard.yaml``; if none found, returns defaults.

    Returns:
        Validated :class:`ServeXGuardConfig`.

    Raises:
        FileNotFoundError: If an explicit ``path`` is given but missing.
        ValueError: If the YAML is malformed or fails validation.
    """
    if path is not None:
        config_path = Path(path)
        if not config_path.is_file():
            raise FileNotFoundError(f"Config not found: {path}")
    else:
        config_path = find_config()
        if config_path is None:
            logger.debug("No %s found, using defaults", CONFIG_FILENAME)
            return ServeXGuardConfig()

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(f"Config root must be a mapping: {config_path}")

    try:
        return ServeXGuardConfig(**raw)
    except Exception as exc:  # pydantic ValidationError
        raise ValueError(f"Invalid config in {config_path}: {exc}") from exc


def merge_cli_overrides(
    config: ServeXGuardConfig, overrides: dict[str, Any]
) -> ServeXGuardConfig:
    """Apply CLI overrides onto a loaded config (CLI wins over YAML).

    Only non-``None`` override values are applied. Keys map to flat CLI
    flag names, e.g. ``min_faithfulness``, ``check_pii``, ``baseline``.

    Args:
        config: Base config loaded from YAML/defaults.
        overrides: CLI flag values; ``None`` means "not set, keep YAML".

    Returns:
        New :class:`ServeXGuardConfig` with overrides applied.
    """
    data = config.model_dump()

    mapping = {
        "min_faithfulness": ("quality", "min_faithfulness"),
        "min_relevancy": ("quality", "min_relevancy"),
        "min_context_recall": ("quality", "min_context_recall"),
        "check_pii": ("security", "check_pii"),
        "language": ("security", "language"),
        "check_injection": ("security", "check_injection"),
        "check_drift": ("drift", "enabled"),
        "drift_threshold": ("drift", "max_query_drift"),
        "baseline": ("drift", "baseline_file"),
        "dataset": ("dataset", "path"),
        "output": ("output", "path"),
    }

    for flag, value in overrides.items():
        if value is None or flag not in mapping:
            continue
        section, key = mapping[flag]
        data[section][key] = value

    return ServeXGuardConfig(**data)


def write_default_config(path: str | Path = CONFIG_FILENAME) -> Path:
    """Write an annotated default ``servexguard.yaml``.

    Args:
        path: Destination file path.

    Returns:
        Path written.

    Raises:
        FileExistsError: If the target already exists.
    """
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"Config already exists: {target}")

    target.write_text(_DEFAULT_YAML, encoding="utf-8")
    logger.info("Wrote default config: %s", target)
    return target


_DEFAULT_YAML = """\
# servexguard.yaml — ServeXGuard configuration
# Place this file in your project root.

quality:
  # CONSERVATIVE preset (healthcare, legal, banking, insurance)
  # min_faithfulness: 0.90
  # min_relevancy: 0.85
  # min_context_recall: 0.80
  #
  # BALANCED preset — recommended default
  min_faithfulness: 0.80
  min_relevancy: 0.75
  min_context_recall: 0.70
  #
  # PERMISSIVE preset (public chatbot, simple FAQ, internal tools)
  # min_faithfulness: 0.65
  # min_relevancy: 0.60
  # min_context_recall: 0.55

security:
  check_pii: true
  language: en  # any Presidio language: en | fr | ar | de | es ...
  pii_entities:
    - EMAIL_ADDRESS
    - PHONE_NUMBER
    - IBAN_CODE
    - CREDIT_CARD
    - PERSON
  check_injection: true
  # Optional locale-specific PII via your own regex (global-first core).
  # custom_entities:
  #   - pattern: "\\\\b[A-Z]{1,2}\\\\d{6}\\\\b"
  #     label: "MOROCCAN_CIN"
  #   - pattern: "\\\\b\\\\d{13}\\\\b"
  #     label: "CNSS_NUMBER"

drift:
  enabled: false
  max_query_drift: 0.25
  baseline_file: "data/baseline_embeddings.npy"

dataset:
  path: "data/golden_dataset.jsonl"

output:
  format: terminal  # terminal | json | markdown
  path: "reports/servexguard_report.json"
"""
