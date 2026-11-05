"""Runs the real RAGAS stack. The mocked tests cannot catch a broken install.

Skipped unless the eval extra is installed, so CI must run this file in a job
that does install it. The scoring path is exercised against a local endpoint
when SERVEXGUARD_TEST_LLM_MODEL is set.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


class FakeOpenAI:
    """Answers RAGAS's real prompts with fixed JSON, so CI needs no model.

    The real RAGAS code runs from dataset to score: only the model's words are
    canned. Any answer containing "Tombouctou" is judged unsupported.
    """

    def __init__(self, broken: bool = False):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, payload: dict) -> None:
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path.endswith("/embeddings"):
                    inputs = body["input"] if isinstance(body["input"], list) else [body["input"]]
                    self._send(
                        {
                            "object": "list",
                            "model": body["model"],
                            "data": [
                                {"object": "embedding", "index": i, "embedding": [1.0, 0.0, 0.0]}
                                for i in range(len(inputs))
                            ],
                            "usage": {"prompt_tokens": 1, "total_tokens": 1},
                        }
                    )
                    return
                prompt = " ".join(str(m.get("content")) for m in body["messages"])
                content = "this is not json" if fake.broken else fake.reply(prompt)
                self._send(
                    {
                        "id": "x",
                        "object": "chat.completion",
                        "created": 0,
                        "model": body["model"],
                        "choices": [
                            {
                                "index": i,
                                "finish_reason": "stop",
                                "message": {"role": "assistant", "content": content},
                            }
                            for i in range(body.get("n") or 1)
                        ],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    }
                )

        self.broken = broken
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    @staticmethod
    def reply(prompt: str) -> str:
        invented = "Tombouctou" in prompt
        if '"verdict"' in prompt or "verdict" in prompt:
            verdict = 0 if invented else 1
            return json.dumps(
                {"statements": [{"statement": "s", "reason": "r", "verdict": verdict}]}
            )
        if "attributed" in prompt:
            return json.dumps(
                {"classifications": [{"statement": "s", "reason": "r", "attributed": 1}]}
            )
        if "noncommittal" in prompt:
            return json.dumps({"question": "Quelle est la capitale ?", "noncommittal": 0})
        statement = "La capitale est Tombouctou." if invented else "La capitale est Rabat."
        return json.dumps({"statements": [statement]})


@pytest.fixture
def fake_openai():
    created = FakeOpenAI()
    yield created
    created.server.shutdown()


def _settings(url: str) -> LLMSettings:
    return LLMSettings(model="fake", base_url=url, embedding_model="fake", timeout=30)


def test_real_ragas_scores_all_three_metrics_end_to_end(fake_openai):
    """From dataset to score through the real RAGAS code, deterministically."""
    outcome = evaluate_quality(
        ROWS,
        ["faithfulness", "answer_relevancy", "context_recall"],
        _settings(fake_openai.url),
    )
    assert outcome.unmeasured == {}
    assert outcome.scores["faithfulness"] == pytest.approx(0.5)
    assert outcome.scores["context_recall"] == pytest.approx(1.0)
    assert 0.0 <= outcome.scores["answer_relevancy"] <= 1.0
    assert outcome.coverage["faithfulness"] == 1.0


def test_a_model_returning_garbage_is_not_measured(fake_openai):
    """The judge failing must never look like a low score, or a pass."""
    fake_openai.broken = True
    outcome = evaluate_quality(ROWS, ["faithfulness"], _settings(fake_openai.url))
    assert outcome.scores == {}
    assert "faithfulness" in outcome.unmeasured


def test_the_cli_gate_blocks_on_a_real_low_score(fake_openai, tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from servexguard.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / "d.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in ROWS), encoding="utf-8"
    )
    args = [
        "check", "--dataset", "d.jsonl",
        "--llm-model", "fake", "--llm-base-url", fake_openai.url,
        "--llm-embedding-model", "fake",
    ]
    blocked = CliRunner().invoke(app, [*args, "--min-faithfulness", "0.8"])
    assert blocked.exit_code == 1, blocked.output
    passed = CliRunner().invoke(
        app,
        [*args, "--min-faithfulness", "0.4", "--min-relevancy", "0", "--min-context-recall", "0"],
    )
    assert passed.exit_code == 0, passed.output


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
