"""Tests for the YAML configuration loader."""

from __future__ import annotations

import pytest

from servexguard.config import (
    ServeXGuardConfig,
    load_config,
    merge_cli_overrides,
    write_default_config,
)


def test_defaults_when_no_yaml(tmp_path, monkeypatch):
    """load_config(None) with no discoverable yaml returns defaults."""
    monkeypatch.chdir(tmp_path)
    cfg = load_config(None)
    assert isinstance(cfg, ServeXGuardConfig)
    assert cfg.quality.min_faithfulness == 0.80
    assert cfg.security.check_pii is False


def test_yaml_loading(tmp_path):
    """A written YAML file is loaded with its values."""
    yaml_file = tmp_path / "servexguard.yaml"
    yaml_file.write_text(
        "quality:\n  min_faithfulness: 0.95\nsecurity:\n  check_pii: true\n",
        encoding="utf-8",
    )
    cfg = load_config(yaml_file)
    assert cfg.quality.min_faithfulness == 0.95
    assert cfg.security.check_pii is True


def test_cli_override():
    """merge_cli_overrides replaces only non-None values."""
    base = ServeXGuardConfig()
    merged = merge_cli_overrides(
        base, {"min_faithfulness": 0.99, "check_pii": None, "language": "fr"}
    )
    assert merged.quality.min_faithfulness == 0.99
    assert merged.security.language == "fr"
    # None override leaves the default untouched.
    assert merged.security.check_pii is False


def test_invalid_yaml_raises(tmp_path):
    """Malformed YAML raises ValueError."""
    bad = tmp_path / "servexguard.yaml"
    bad.write_text("quality: [unclosed\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(bad)


def test_write_default_config(tmp_path):
    """write_default_config generates a loadable YAML file."""
    target = tmp_path / "servexguard.yaml"
    written = write_default_config(target)
    assert written.exists()
    cfg = load_config(target)
    assert cfg.quality.min_faithfulness == 0.80
    assert cfg.security.check_injection is True


def test_custom_entities_parsed(tmp_path):
    """custom_entities in YAML parse into CustomEntity models."""
    yaml_file = tmp_path / "servexguard.yaml"
    yaml_file.write_text(
        "security:\n"
        "  custom_entities:\n"
        '    - pattern: "\\\\b[A-Z]{1,2}\\\\d{6}\\\\b"\n'
        '      label: "MOROCCAN_CIN"\n',
        encoding="utf-8",
    )
    cfg = load_config(yaml_file)
    assert len(cfg.security.custom_entities) == 1
    assert cfg.security.custom_entities[0].label == "MOROCCAN_CIN"
