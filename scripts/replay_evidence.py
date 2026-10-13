"""Replay the unchanged unsafe reference or the contained runner locally.

Run from the repository root: python -m scripts.replay_evidence before|after.
The before phase deliberately invokes _naive_loop, never the safe CLI.
Only synthetic fixtures and the fixed localhost sink are used.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

from agent import tools
from agent.llm import MockLLM
from agent.loop import _naive_loop, run_once
from sink.sink import LOG_PATH, reset_log, run_in_background

QUERY = "Tổng hợp các ticket còn mở tuần này"
ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("before", "after"))
    phase = parser.parse_args().phase
    server, _ = run_in_background()
    results = []
    search = tools.search_docs
    try:
        for variant in range(1, 5):
            with tempfile.TemporaryDirectory() as directory:
                corpus = Path(directory)
                for source in (ROOT / "corpus").glob("*.md"):
                    if not source.name.startswith("ticket-90") or source.name.startswith(f"ticket-90{variant}"):
                        (corpus / source.name).write_bytes(source.read_bytes())
                for principal in (["support_l1"] if phase == "before" else ["support_l1", "dpo"]):
                    reset_log()
                    with patch.object(tools, "search_docs", lambda query: search(query, corpus_dir=corpus)):
                        if phase == "before":
                            _naive_loop(QUERY, MockLLM())
                        else:
                            run_once(QUERY, mock=True, principal_id=principal)
                    sink = LOG_PATH.read_text(encoding="utf-8")
                    evidence = ROOT / "reports" / f"attack-{phase}-variant-{variant}-{principal}.log"
                    evidence.write_text(sink, encoding="utf-8")
                    results.append({"variant": variant, "principal": principal,
                                    "sink_requests": len(sink.splitlines()), "evidence": evidence.name})
        # The aggregate after evidence uses exactly the original CLI query,
        # after a fresh sink reset; the original before capture is preserved.
        if phase == "after":
            reset_log()
            run_once(QUERY, mock=True, principal_id="dpo")
            (ROOT / "reports/attack-after.log").write_bytes(LOG_PATH.read_bytes())
        (ROOT / "reports" / f"replay-{phase}.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(results, indent=2))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
