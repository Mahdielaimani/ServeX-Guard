"""Runs the real RAGAS stack. The mocked tests cannot catch a broken install.

Skipped unless the eval extra is installed, so CI must run this file in a job
that does install it. The scoring path is exercised against a local endpoint
when SERVEXGUARD_TEST_LLM_MODEL is set.
"""

from __future__ import annotations

import os
import socket

import pytest

from servexguard import evaluator
from servexguard.evaluator import LLMSettings, evaluate_quality

pytest.importorskip("ragas")

ROWS = [
    {
        "question": "Quelle est la capitale du Maroc ?",
        "answer": "La capitale du Maroc est Rabat.",
        "contexts": ["Rabat est la capitale du Royaume du Maroc."],
        "ground_truth": "Rabat",
    },
    {
        "question": "Quelle est la capitale du Maroc ?",
        "answer": "La capitale du Maroc est Tombouctou, fondée par des extraterrestres.",
        "contexts": ["Rabat est la capitale du Royaume du Maroc."],
        "ground_truth": "Rabat",
    },
]


def test_the_stack_imports():
    """The exact failure of 0.2.1: pip succeeded, then the import raised."""
    stack = evaluator._load_stack()
    assert set(stack["metrics"]) == {"faithfulness", "answer_relevancy", "context_recall"}


def test_ragas_telemetry_is_off():
    evaluator._load_stack()
    assert os.environ["RAGAS_DO_NOT_TRACK"] == "true"


@pytest.mark.skipif(
    "SERVEXGUARD_TEST_LLM_MODEL" not in os.environ, reason="no local LLM configured"
)
def test_scores_tell_a_faithful_answer_from_an_invented_one(monkeypatch):
    """Real model, real scores, and no connection beyond the local endpoint."""
    # Name resolution, not connect(): the Windows event loop opens sockets through
    # ConnectEx, which a patched socket.connect never sees. Anything reaching a
    # remote host has to resolve its name first.
    real_getaddrinfo = socket.getaddrinfo
    remote = []

    def recording_getaddrinfo(host, *args, **kwargs):
        if host not in ("127.0.0.1", "::1", "localhost", None):
            remote.append(host)
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", recording_getaddrinfo)

    llm = LLMSettings(
        model=os.environ["SERVEXGUARD_TEST_LLM_MODEL"],
        base_url=os.environ.get("SERVEXGUARD_TEST_LLM_BASE_URL", "http://127.0.0.1:11434/v1"),
        timeout=300,
        max_workers=1,
    )
    good = evaluate_quality(ROWS[:1], ["faithfulness"], llm)
    bad = evaluate_quality(ROWS[1:], ["faithfulness"], llm)

    assert good.scores["faithfulness"] > bad.scores["faithfulness"]
    assert remote == []
