"""Run evaluation checks and report a concise summary."""

from __future__ import annotations

import time

from evals.atomic_write_eval import run_check as run_atomic_write
from evals.smoke_eval import run_check as run_smoke
from evals.tool_contract_eval import run_check as run_tool_contract


def _timed(fn) -> tuple[bool, float, dict[str, str]]:
    start = time.perf_counter()
    passed, details = fn()
    duration_ms = (time.perf_counter() - start) * 1000
    details["latency_ms"] = f"{duration_ms:.2f}"
    details["result"] = "pass" if passed else "fail"
    return passed, duration_ms, details


def main() -> int:
    checks = {
        "smoke": run_smoke,
        "tool_contract": run_tool_contract,
        "atomic_write": run_atomic_write,
    }

    results: dict[str, dict[str, str]] = {}
    passed = 0

    for name, fn in checks.items():
        ok, _, details = _timed(name, fn)
        results[name] = details
        if ok:
            passed += 1

    print("EVAL RESULTS")
    for name, details in results.items():
        print(f"{name}: {details['result']} ({details['latency_ms']}ms)")
    print(f"checks_passed: {passed}/{len(checks)}")
    print(f"safe_commands: {results.get('smoke', {}).get('safe_commands', '0')}")

    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
