"""Evaluation checks for atomic write guarantees."""

from __future__ import annotations

import tempfile
from pathlib import Path

from titanium_repo_operator.config import REPO_ROOT
from titanium_repo_operator.utils import atomic_write


def run_check() -> tuple[bool, dict[str, str]]:
    details: dict[str, str] = {}
    with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp_dir:
        target = Path(tmp_dir) / "atomic_write.txt"
        atomic_write(target, "first")
        atomic_write(target, "second")

        content_ok = target.read_text(encoding="utf-8") == "second"
        tmp_path = target.with_suffix(target.suffix + ".tmp")
        tmp_clean = not tmp_path.exists()

        details["content_matches_latest"] = "pass" if content_ok else "fail"
        details["no_tmp_leftover"] = "pass" if tmp_clean else "fail"

    passed = content_ok and tmp_clean
    return passed, details


if __name__ == "__main__":
    ok, details = run_check()
    print("EVAL RESULTS")
    for name, status in details.items():
        print(f"{name}: {status}")
    raise SystemExit(0 if ok else 1)
