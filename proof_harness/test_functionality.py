"""
Legitimate-usage functionality checks for a Langflow target.

These hit the SAME app as exploit_repro/exploit.py, but only through
Langflow's normal, authenticated REST API -- health check, version, whoami,
and a full create/read/delete cycle on a flow. The point is orthogonal to
the exploit: after a candidate patch for CVE-2026-33017 is applied, we need
to know not just "is the PoV blocked?" but "did blocking it also break the
app?" -- an overly aggressive patch (e.g. one that guts build_public_tmp
entirely) could satisfy the first question while failing the second.

Deliberately has NO import from exploit_repro: this file only needs
`requests` + stdlib (+ pytest for the test-suite half), so it stays
independently collectible by `pytest proof_harness/` with no sys.path setup,
and the exploit module's own login/build helpers (which exist to set up an
*attack*, not to exercise the app normally) are never reused here -- even
though `_login()` below happens to call the same /api/v1/auto_login endpoint
exploit.py's _auto_login() does, it's used the way a legitimate client would
use it, not as an anonymous bootstrap step preceding an RCE payload.

Every check function is usable two ways:
  1. Directly, via run_functionality_tests(target_url) -> (passed, total),
     which proof_harness/verify.py calls without shelling out to pytest.
  2. Under pytest, via the parametrized test_functionality_check() below,
     for `pytest proof_harness/ -v` as an independent confirmation path.
Both walk the same _CHECKS list, so there's exactly one place that defines
what "functionality" means -- add a check there and it's covered by both.
"""

from __future__ import annotations

import os
import urllib.parse

import pytest
import requests

# ---------------------------------------------------------------------------
# Safety guard (duplicated from exploit_repro/exploit.py on purpose -- see
# proof_harness/verify.py for the rationale: each entry point should refuse
# a non-localhost target on its own, without relying on a caller upstream
# having already checked).
# ---------------------------------------------------------------------------

_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _assert_localhost(url: str) -> None:
    hostname = urllib.parse.urlsplit(url).hostname
    if hostname not in _ALLOWED_HOSTS:
        raise ValueError(
            f"Refusing to target {hostname!r}. This harness is scoped to "
            f"localhost only ({sorted(_ALLOWED_HOSTS)}) -- point it at your "
            f"own isolated Docker container, nothing else."
        )


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def _login(base_url: str) -> str:
    """
    GET /api/v1/auto_login -- the normal client-side login path for an
    AUTO_LOGIN=true deployment (Langflow's default). This is the SAME
    endpoint exploit.py's _auto_login() calls, but used here the way it's
    meant to be used: as ordinary authentication before making legitimate,
    authenticated API calls, not as an anonymous bootstrap step preceding
    an RCE payload.
    """
    resp = requests.get(f"{base_url}/api/v1/auto_login", timeout=10)
    resp.raise_for_status()
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Checks
#
# Each check_* function takes (base_url, token), makes one or more real API
# calls, and raises (AssertionError, or lets requests'/json's own exceptions
# propagate) on failure. This is plain pytest-assert style, and also exactly
# what run_functionality_tests()'s manual try/except loop needs -- no
# separate "pytest version" vs "plain version" of the check logic.
# ---------------------------------------------------------------------------


def check_health(base_url: str, token: str) -> None:
    """GET /health -- basic liveness, no auth required."""
    resp = requests.get(f"{base_url}/health", timeout=10)
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}"
    assert resp.json().get("status") == "ok", f"unexpected body: {resp.text}"


def check_version(base_url: str, token: str) -> None:
    """GET /api/v1/version -- confirms the API is actually Langflow and reports a version."""
    resp = requests.get(f"{base_url}/api/v1/version", timeout=10)
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}"
    body = resp.json()
    assert body.get("version"), f"no 'version' field in response: {body}"


def check_whoami(base_url: str, token: str) -> None:
    """GET /api/v1/users/whoami (authenticated) -- confirms the auto_login token is honored."""
    resp = requests.get(
        f"{base_url}/api/v1/users/whoami",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}"
    body = resp.json()
    assert body.get("is_superuser") is True, f"expected superuser via AUTO_LOGIN, got: {body}"


def check_unauthenticated_request_rejected(base_url: str, token: str) -> None:
    """
    GET /api/v1/users/whoami with NO Authorization header -- confirms normal
    auth enforcement is intact (i.e. the patch didn't accidentally disable
    auth checking on other endpoints while fixing build_public_tmp).
    """
    resp = requests.get(f"{base_url}/api/v1/users/whoami", timeout=10)
    assert resp.status_code in (401, 403), (
        f"expected an auth-rejection status (401/403) for an unauthenticated "
        f"request, got {resp.status_code} -- auth enforcement may be broken"
    )


def check_list_flows(base_url: str, token: str) -> None:
    """GET /api/v1/flows/ (authenticated) -- confirms core data-listing still works."""
    resp = requests.get(
        f"{base_url}/api/v1/flows/",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}"
    assert isinstance(resp.json(), list), f"expected a list body, got: {type(resp.json())}"


def check_flow_crud_lifecycle(base_url: str, token: str) -> None:
    """
    Full create -> read -> delete -> verify-gone cycle on /api/v1/flows/.

    Bundled into one check (rather than four separate ones) so there's no
    inter-check ordering dependency for pytest to get right, and so a
    try/finally can best-effort delete the flow even if an earlier
    assertion fails partway through -- mirroring exploit.py's own
    best-effort _cleanup_evidence_file() pattern.
    """
    headers = {"Authorization": f"Bearer {token}"}
    flow_id = None
    try:
        create_resp = requests.post(
            f"{base_url}/api/v1/flows/",
            headers=headers,
            json={
                "name": "kavach-loop-functest",
                "data": {"nodes": [], "edges": []},
                "access_type": "PRIVATE",
            },
            timeout=10,
        )
        assert create_resp.status_code in (200, 201), (
            f"create failed: {create_resp.status_code} {create_resp.text}"
        )
        flow_id = create_resp.json()["id"]

        get_resp = requests.get(
            f"{base_url}/api/v1/flows/{flow_id}", headers=headers, timeout=10
        )
        assert get_resp.status_code == 200, f"read-back failed: {get_resp.status_code}"
        assert get_resp.json()["id"] == flow_id, "read-back returned a different flow"

        delete_resp = requests.delete(
            f"{base_url}/api/v1/flows/{flow_id}", headers=headers, timeout=10
        )
        assert delete_resp.status_code == 200, f"delete failed: {delete_resp.status_code}"

        verify_resp = requests.get(
            f"{base_url}/api/v1/flows/{flow_id}", headers=headers, timeout=10
        )
        assert verify_resp.status_code == 404, (
            f"expected 404 after delete, got {verify_resp.status_code} -- "
            f"flow was not actually removed"
        )
        flow_id = None  # already cleaned up via the normal path above
    finally:
        if flow_id is not None:
            requests.delete(
                f"{base_url}/api/v1/flows/{flow_id}", headers=headers, timeout=10
            )


def check_openapi_schema(base_url: str, token: str) -> None:
    """GET /openapi.json -- confirms the app is still serving its full route table, not just a stub."""
    resp = requests.get(f"{base_url}/openapi.json", timeout=10)
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}"
    assert "paths" in resp.json(), "openapi document missing 'paths'"


def check_public_flow_build(base_url: str, token: str) -> None:
    """
    POST /api/v1/build_public_tmp/{flow_id}/flow -- the UNAUTHENTICATED
    public-build endpoint that is CVE-2026-33017 itself (see
    exploit_repro/exploit.py). This check exists because patch_gen's first
    generated fix for this CVE was caught, via this exact check, doing the
    wrong thing: it blocked the exploit by making start_flow_build() raise
    TypeError on every call (a missing required keyword argument), which
    "worked" for pov_blocked but silently killed the legitimate public-flow
    feature for every caller, authenticated or not. None of the other
    checks in this file happen to call this endpoint, so that regression
    was invisible to them -- confidence_score would have read 1.0 for a
    patch that broke a real feature. This check closes that blind spot: it
    creates a real PUBLIC flow and builds it the normal way (no attacker
    payload, no auth -- exactly how a legitimate public/shared flow is
    meant to work), and requires a real job_id back, not just "not a 500".
    """
    headers = {"Authorization": f"Bearer {token}"}
    flow_id = None
    try:
        create_resp = requests.post(
            f"{base_url}/api/v1/flows/",
            headers=headers,
            json={
                "name": "kavach-loop-functest-public-build",
                "data": {"nodes": [], "edges": []},
                "access_type": "PUBLIC",
            },
            timeout=10,
        )
        assert create_resp.status_code in (200, 201), (
            f"create failed: {create_resp.status_code} {create_resp.text}"
        )
        flow_id = create_resp.json()["id"]

        # No Authorization header, no `data` body field -- this is exactly
        # how a legitimate anonymous visitor builds a public/shared flow.
        build_resp = requests.post(
            f"{base_url}/api/v1/build_public_tmp/{flow_id}/flow",
            cookies={"client_id": "kavach-loop-functest"},
            timeout=15,
        )
        assert build_resp.status_code == 200, (
            f"legitimate public flow build failed: HTTP {build_resp.status_code} "
            f"{build_resp.text} -- the patch may have broken the public-flow "
            f"feature while blocking the exploit (see this function's docstring)"
        )
        assert "job_id" in build_resp.json(), f"no job_id in response: {build_resp.text}"
    finally:
        if flow_id is not None:
            requests.delete(
                f"{base_url}/api/v1/flows/{flow_id}", headers=headers, timeout=10
            )


_CHECKS = [
    check_health,
    check_version,
    check_whoami,
    check_unauthenticated_request_rejected,
    check_list_flows,
    check_flow_crud_lifecycle,
    check_openapi_schema,
    check_public_flow_build,
]


# ---------------------------------------------------------------------------
# Plain callable -- what proof_harness/verify.py imports and calls directly
# ---------------------------------------------------------------------------


def run_functionality_tests(target_url: str) -> tuple[int, int]:
    """
    Runs every check in _CHECKS against `target_url` and returns
    (passed, total). `total` is always len(_CHECKS), even if login itself
    fails (reported as 0/N, not 0/0), so the ratio stays meaningful to
    whatever computes a confidence score from it.
    """
    _assert_localhost(target_url)
    base_url = target_url.rstrip("/")
    total = len(_CHECKS)

    try:
        token = _login(base_url)
    except Exception as exc:  # noqa: BLE001 -- any login failure means 0/N, by design
        print(f"[-] login failed, cannot run functionality checks: {exc}")
        return 0, total

    passed = 0
    for check in _CHECKS:
        try:
            check(base_url, token)
            passed += 1
            print(f"[+] {check.__name__} passed")
        except Exception as exc:  # noqa: BLE001 -- a failing check should not abort the rest
            print(f"[-] {check.__name__} failed: {exc}")
    return passed, total


# ---------------------------------------------------------------------------
# pytest suite -- `pytest proof_harness/test_functionality.py -v`
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def base_url() -> str:
    url = os.environ.get("KAVACH_TARGET_URL", "http://127.0.0.1:7860")
    _assert_localhost(url)
    return url.rstrip("/")


@pytest.fixture(scope="module")
def token(base_url: str) -> str:
    return _login(base_url)


@pytest.mark.parametrize(
    "check", _CHECKS, ids=[c.__name__.removeprefix("check_") for c in _CHECKS]
)
def test_functionality_check(base_url: str, token: str, check) -> None:
    check(base_url, token)


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:7860"
    passed, total = run_functionality_tests(target)

    print("\n" + "=" * 70)
    print(f"functionality: {passed}/{total} passed")
    print("=" * 70)

    sys.exit(0 if passed == total else 1)
