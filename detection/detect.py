#!/usr/bin/env python3
"""
Static-analysis detection for CVE-2026-33017, feeding patch_gen/'s contract.

This is the piece patch_gen/generate.py originally stood in for with a
hardcoded dict (see get_detection_result() there). This module makes that
real: it runs a Semgrep rule (rules/unauthenticated-exec-sink.yaml) against
a checked-out copy of the vulnerable Langflow source and produces the same
contract shape, but from an actual static-analysis pass over real source,
not a lookup.

WHAT THE RULE ACTUALLY PROVES, AND WHAT IT DOESN'T (read this before
trusting detect_vulnerability()'s output at face value):

The real vulnerability requires tracing attacker-controlled input through
six call-hops to an exec() sink (documented in full in
exploit_repro/exploit.py's module docstring, reused here rather than
re-derived):

    chat.py:build_public_tmp() [SOURCE: `data` param, no auth]
      -> build.py:start_flow_build(data=...) -> generate_flow_events()
      -> build.py:create_graph() -> build_graph_from_data(payload=data.model_dump())
      -> base.py:Graph.from_payload() -> add_nodes_and_edges()
      -> base.py:_instantiate_components_in_vertices()
      -> loading.py:instantiate_class() -> code = custom_params.pop("code")
      -> eval.py:eval_custom_component_code() -> create_class()
      -> validate.py:prepare_global_scope() [SINK: exec(compiled_code, ...)]

Getting Semgrep to trace all six hops on its own, in the time available,
isn't realistic -- and just grepping for `exec(` is explicitly the wrong
approach (exploit.py's docstring makes the same point: the sink function
is generic, shared by legitimate component execution too, so matching on
it alone is pure noise). Instead, this rule detects the one signal that
IS reliably checkable with a single Semgrep pattern: an unauthenticated
FastAPI route handler that forwards a structurally-named body parameter
(data/payload/flow_data/...) into a downstream call at all. That's a
necessary precondition for this class of bug, not proof of it -- every
match still needs a human (or the taint chain above) to confirm it
actually reaches exec(). See the rule file's `message` and `metadata.note`
for the same caveat surfaced at scan time.

detect_vulnerability() runs that rule, and if (and only if) one of its
raw findings lands at the known ground-truth location (chat.py,
build_public_tmp, line 580), enriches THAT finding with hand-authored CVE
narrative text (description/taint_source/cve_reference) to produce the
AGREED CONTRACT dict patch_gen/generate.py consumes. That enrichment step
is explicitly NOT something Semgrep derives -- a pattern match tells you
"attacker input reaches a call", not "here is the CVE ID and a paragraph
explaining the exploit chain". Being honest about that split (rule-found
location vs. hand-authored narrative) is the whole point of this comment.
If the rule's findings do NOT include a match at that location,
detect_vulnerability() raises rather than silently falling back to the
enrichment dict -- a real detection miss should look like a miss, not a
disguised success.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import urllib.parse
from pathlib import Path

# ---------------------------------------------------------------------------
# Safety guards (duplicated from exploit_repro/exploit.py and
# patch_gen/generate.py on purpose -- each entry point in this repo refuses
# a non-localhost target / an unrecognized container on its own, rather
# than trusting that some caller upstream already checked).
# ---------------------------------------------------------------------------

_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
_CONTAINER_PREFIX = "langflow-cve-2026-33017"
_SOURCE_CONTAINER = "langflow-cve-2026-33017"


def _assert_localhost(url: str) -> None:
    hostname = urllib.parse.urlsplit(url).hostname
    if hostname not in _ALLOWED_HOSTS:
        raise ValueError(
            f"Refusing to target {hostname!r}. This tool is scoped to "
            f"localhost only ({sorted(_ALLOWED_HOSTS)})."
        )


def _assert_known_container(container: str) -> None:
    if not container.startswith(_CONTAINER_PREFIX):
        raise ValueError(
            f"Refusing to touch container {container!r}. detection/ only "
            f"reads source from containers named {_CONTAINER_PREFIX}* -- "
            f"nothing else on this machine is this tool's business."
        )


_RULE_PATH = Path(__file__).resolve().parent / "rules" / "unauthenticated-exec-sink.yaml"

# The one location a real finding must land on for detect_vulnerability()
# to treat it as confirmed. Deliberately narrow and explicit -- this is the
# "known ground truth" disambiguation step called out in this module's
# docstring, not something the rule derives on its own.
_CONFIRMED_FILE_SUFFIX = "api/v1/chat.py"
_CONFIRMED_LINE = 580

# Hand-authored CVE narrative, applied ONLY to enrich a confirmed finding
# (see docstring). This is the exact AGREED CONTRACT patch_gen/generate.py
# was built against.
_CONTRACT_ENRICHMENT = {
    "file": "src/backend/base/langflow/api/v1/chat.py",
    "line": 580,
    "sink_type": "exec",
    "taint_source": "HTTP request body (data parameter) on unauthenticated build_public_tmp route",
    "cve_reference": "CVE-2026-33017",
    "description": (
        "build_public_tmp accepts attacker-controlled `data` instead of the "
        "flow's stored definition; the embedded `code` field is later passed "
        "to exec() via prepare_global_scope() with zero sandboxing and no "
        "auth check on this route."
    ),
}


# ---------------------------------------------------------------------------
# Source extraction (mirrors patch_gen/generate.py's docker cp approach --
# same container naming, same "ask the interpreter for the real path
# instead of hardcoding a Python/venv version" pattern)
# ---------------------------------------------------------------------------


def _docker(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, encoding="utf-8", errors="replace", timeout=timeout)


def _find_package_dir(container: str) -> str:
    proc = _docker(["exec", container, "python", "-c", "import langflow, os; print(os.path.dirname(langflow.__file__))"])
    if proc.returncode != 0:
        raise RuntimeError(f"could not locate the langflow package dir in {container!r}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _extract_source(container: str, dest_dir: Path) -> Path:
    """
    docker cp's the real installed langflow/api/ package directory (route
    handlers, chat.py, build.py, ~50 files) out of the running container
    into `dest_dir`, and returns the extracted api/ path. Scanning the
    whole api/ package rather than just chat.py is deliberate: it gives
    the Semgrep rule real breadth to run against (other routes that could
    plausibly false-positive or true-negative, not just the one file we
    already know is vulnerable) -- see rules/unauthenticated-exec-sink.yaml
    for the two auth conventions this codebase actually uses, found by
    reading the real extracted files, not assumed.
    """
    _assert_known_container(container)
    package_dir = _find_package_dir(container)
    cp_proc = _docker(["cp", f"{container}:{package_dir}/api", str(dest_dir / "api")], timeout=30)
    if cp_proc.returncode != 0:
        raise RuntimeError(f"docker cp of api/ from {container!r} failed: {cp_proc.stderr.strip()}")
    return dest_dir / "api"


# ---------------------------------------------------------------------------
# Running the rule
# ---------------------------------------------------------------------------


def _run_semgrep(target_path: str) -> list[dict]:
    """
    Runs rules/unauthenticated-exec-sink.yaml against `target_path` via the
    semgrep CLI (subprocess, matching this repo's established
    shell-out-rather-than-bind pattern -- see exploit.py's docker exec
    calls and generate.py's docker cp calls). Returns the raw list of
    semgrep JSON `results` entries -- callers get every candidate, not a
    pre-filtered one, so noise is visible rather than hidden.
    """
    # A real 50-file / 1-rule scan is normally seconds of work, but on this
    # Windows dev box it was observed taking up to ~3.5 minutes wall-clock
    # with near-zero CPU time consumed (confirmed via `time` -- real 3m29s,
    # user 0.05s), pointing at I/O contention (Windows Defender scanning
    # each file on open, or Docker Desktop/WSL2 still settling after a
    # restart) rather than anything semgrep or this rule is doing. 400s
    # gives comfortable headroom for that without masking a genuine hang.
    proc = subprocess.run(
        [
            "semgrep", "--config", str(_RULE_PATH), target_path,
            "--json", "--metrics=off", "--exclude", "__pycache__",
        ],
        capture_output=True, encoding="utf-8", errors="replace", timeout=400,
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"semgrep did not produce parseable JSON (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:500]}"
        ) from exc
    if payload.get("errors"):
        print(f"[-] semgrep reported {len(payload['errors'])} parse/scan error(s) (non-fatal, continuing): "
              f"{[e.get('message', e) for e in payload['errors'][:3]]}")
    return payload["results"]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def detect_vulnerability(target_path: str | None = None, container: str = _SOURCE_CONTAINER) -> dict:
    """
    Runs the Semgrep rule and returns ONE finding in the AGREED CONTRACT
    shape patch_gen/generate.py consumes:

        {
            "file": str, "line": int, "sink_type": str,
            "taint_source": str, "cve_reference": str, "description": str,
        }

    If `target_path` is None, extracts real source from `container` via
    docker cp first (see _extract_source). All raw findings are printed
    (not just the confirmed one) so a demo/summary can show "the rule
    surfaced N candidate(s), here is the one confirmed against known
    ground truth" honestly. Raises RuntimeError if no finding lands at the
    known-vulnerable location -- see this module's docstring for why that
    must be a hard failure, not a silent fallback to the enrichment dict.
    """
    with tempfile.TemporaryDirectory(prefix="kavach-loop-detect-") as tmp:
        if target_path is None:
            print(f"[*] extracting real source from {container} ...")
            extracted = _extract_source(container, Path(tmp))
            target_path = str(extracted)
            print(f"[+] extracted to {target_path}")

        print(f"[*] running Semgrep rule {_RULE_PATH.name} against {target_path} ...")
        findings = _run_semgrep(target_path)
        print(f"[+] semgrep produced {len(findings)} candidate finding(s)")

        confirmed = None
        for i, finding in enumerate(findings, 1):
            path = finding["path"].replace("\\", "/")
            line = finding["start"]["line"]
            is_ground_truth = path.endswith(_CONFIRMED_FILE_SUFFIX) and line == _CONFIRMED_LINE
            tag = "[+] CONFIRMED (matches known ground truth)" if is_ground_truth else "[*] candidate (not the known CVE location)"
            print(f"    {i}. {tag} -- {path}:{line}")
            if is_ground_truth:
                confirmed = finding

        if confirmed is None:
            raise RuntimeError(
                f"semgrep found {len(findings)} candidate(s) but NONE at the known "
                f"vulnerable location ({_CONFIRMED_FILE_SUFFIX}:{_CONFIRMED_LINE}) -- "
                f"this is a real detection failure (rule regression, or source changed), "
                f"not something to paper over by returning the enrichment dict anyway."
            )

        if len(findings) > 1:
            print(
                f"[*] note: {len(findings) - 1} other candidate(s) were surfaced alongside the "
                f"confirmed one -- this rule flags 'unauthenticated route forwards a structural "
                f"body param to a call', not proof of an exec() sink (see module docstring); "
                f"disambiguating to the one CVE-2026-33017 finding above was a hand-matched step "
                f"against known ground truth, not something Semgrep did unassisted."
            )
        else:
            print("[*] note: exactly one candidate, and it's the known CVE location -- no manual "
                  "disambiguation was needed this run, but see this module's docstring for why "
                  "that won't always be true for an arbitrary codebase.")

        return dict(_CONTRACT_ENRICHMENT)


if __name__ == "__main__":
    import sys

    path_arg = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        outcome = detect_vulnerability(path_arg)
    except RuntimeError as exc:
        print(f"[-] detection failed: {exc}")
        sys.exit(1)

    print("\n" + "=" * 70)
    print(f"file  : {outcome['file']}:{outcome['line']}")
    print(f"cve   : {outcome['cve_reference']}")
    print("=" * 70)
    print(json.dumps(outcome, indent=2, default=str))
    sys.exit(0)
