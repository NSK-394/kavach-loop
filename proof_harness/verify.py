#!/usr/bin/env python3
"""
verify_patch() -- combines a PoV re-run of CVE-2026-33017 with a legitimate
functionality smoke test, into one verdict on whether a candidate patch is
good.

A patch is only useful if it satisfies BOTH of these, so this module never
scores them independently -- it fuses them into a single confidence_score:

  1. pov_blocked   -- exploit_repro.exploit.run_exploit() must now FAIL
                       (no nonce-matched evidence file). If the exploit
                       still succeeds, the patch didn't work, full stop.
  2. functionality -- Langflow's own REST API (health, version, whoami,
                       flow CRUD, ...) must still behave normally. A patch
                       that blocks the exploit by gutting build_public_tmp
                       entirely, or breaking auth some other way, "fixes"
                       the CVE at the cost of the app -- that's not a patch
                       we'd want to ship either.

LOCALHOST-ONLY, same as exploit_repro/exploit.py -- see _assert_localhost().
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from pathlib import Path

# ---------------------------------------------------------------------------
# Import-path setup
#
# proof_harness/ and exploit_repro/ are sibling directories at the repo
# root with no __init__.py anywhere (implicit namespace packages, matching
# the rest of the repo). That's fine for `pytest` run from the repo root,
# but `python proof_harness/verify.py` on its own only puts this file's own
# directory on sys.path -- not the repo root -- so `import exploit_repro`
# would fail. Fixing that here (rather than only in __main__, like
# exploit.py does with `sys`) means verify_patch() also works if imported
# directly, e.g. later from main.py, regardless of the caller's cwd.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from exploit_repro.exploit import run_exploit  # noqa: E402
from proof_harness.test_functionality import run_functionality_tests  # noqa: E402

# ---------------------------------------------------------------------------
# Safety guard (duplicated from exploit_repro/exploit.py and
# test_functionality.py on purpose -- each entry point refuses a
# non-localhost target independently, rather than trusting that whatever
# called it already checked).
# ---------------------------------------------------------------------------

_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
_CONTAINER_NAME = "langflow-cve-2026-33017"


def _assert_localhost(url: str) -> None:
    hostname = urllib.parse.urlsplit(url).hostname
    if hostname not in _ALLOWED_HOSTS:
        raise ValueError(
            f"Refusing to target {hostname!r}. This harness is scoped to "
            f"localhost only ({sorted(_ALLOWED_HOSTS)}) -- point it at your "
            f"own isolated Docker container, nothing else."
        )


# ---------------------------------------------------------------------------
# Confidence score
#
# pov_blocked is worth most of the score (0.7 of 1.0) and is all-or-nothing:
# a patch that leaves the exploit working is not a valid fix no matter how
# well the rest of the app behaves. The remaining 0.3 is prorated by the
# functionality pass rate, so a patch that blocks the exploit but breaks
# the app (an over-aggressive fix) is still penalized proportionally,
# rather than scoring identically to a clean patch.
#
# Worked examples:
#   blocked=True,  7/7 functional -> 1.0   (ideal patch)
#   blocked=True,  0/7 functional -> 0.7   (blocks exploit, breaks the app)
#   blocked=False, 7/7 functional -> 0.3   (app fine, exploit still works)
#   blocked=False, 0/7 functional -> 0.0   (total failure / target unreachable)
# ---------------------------------------------------------------------------

_POV_WEIGHT = 0.7
_FUNCTIONALITY_WEIGHT = 0.3


def _confidence_score(pov_blocked: bool, passed: int, total: int) -> float:
    functionality_rate = (passed / total) if total else 0.0
    return round(
        (_POV_WEIGHT if pov_blocked else 0.0) + _FUNCTIONALITY_WEIGHT * functionality_rate,
        3,
    )


def _build_summary(pov_blocked: bool, passed: int, total: int, confidence_score: float) -> str:
    if pov_blocked and passed == total:
        return (
            f"Patch verified: CVE-2026-33017 is blocked (the exploit no longer "
            f"produces nonce-matched RCE evidence) and all {total} functionality "
            f"checks passed, so the app still behaves normally. "
            f"confidence_score={confidence_score}."
        )
    if pov_blocked and passed < total:
        return (
            f"Patch partially verified: CVE-2026-33017 is blocked, but only "
            f"{passed}/{total} functionality checks passed -- the fix may be "
            f"over-aggressive and have broken legitimate behavior. Investigate "
            f"the failing checks before shipping this patch. "
            f"confidence_score={confidence_score}."
        )
    if not pov_blocked and passed == total:
        return (
            f"Patch NOT verified: the app functions normally ({passed}/{total} "
            f"checks passed), but CVE-2026-33017 still succeeds -- this target "
            f"is still exploitable. confidence_score={confidence_score}."
        )
    return (
        f"Patch NOT verified: CVE-2026-33017 still succeeds AND only "
        f"{passed}/{total} functionality checks passed -- the target may be "
        f"unreachable or badly broken. confidence_score={confidence_score}."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def verify_patch(
    target_url: str = "http://127.0.0.1:7860",
    container: str = _CONTAINER_NAME,
) -> dict:
    """
    Runs the CVE-2026-33017 PoV against `target_url` and a functionality
    smoke test against its normal REST API, and returns:

        {
            "pov_blocked": bool,                    # True if the exploit no
                                                      # longer succeeds
            "functionality_tests_passed": int,
            "functionality_tests_total": int,
            "confidence_score": float,               # see _confidence_score()
            "summary": "...",                        # human-readable verdict
        }
    """
    _assert_localhost(target_url)
    target_url = target_url.rstrip("/")

    print(f"[*] re-running CVE-2026-33017 PoV against {target_url} ...")
    exploit_result = run_exploit(target_url, container)
    pov_blocked = not exploit_result["success"]
    print(f"[{'+' if pov_blocked else '-'}] pov_blocked={pov_blocked}")

    print(f"[*] running functionality checks against {target_url} ...")
    passed, total = run_functionality_tests(target_url)
    tag = "+" if passed == total else "-"
    print(f"[{tag}] functionality: {passed}/{total} passed")

    confidence_score = _confidence_score(pov_blocked, passed, total)
    summary = _build_summary(pov_blocked, passed, total, confidence_score)

    return {
        "pov_blocked": pov_blocked,
        "functionality_tests_passed": passed,
        "functionality_tests_total": total,
        "confidence_score": confidence_score,
        "summary": summary,
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:7860"
    container_arg = sys.argv[2] if len(sys.argv) > 2 else _CONTAINER_NAME

    outcome = verify_patch(target, container_arg)

    print("\n" + "=" * 70)
    print(f"pov_blocked   : {outcome['pov_blocked']}")
    print(
        f"functionality : {outcome['functionality_tests_passed']}"
        f"/{outcome['functionality_tests_total']}"
    )
    print(f"confidence    : {outcome['confidence_score']}")
    print(f"summary       : {outcome['summary']}")
    print("=" * 70)
    print(json.dumps(outcome, indent=2, default=str))

    clean_patch = (
        outcome["pov_blocked"]
        and outcome["functionality_tests_passed"] == outcome["functionality_tests_total"]
    )
    sys.exit(0 if clean_patch else 1)
