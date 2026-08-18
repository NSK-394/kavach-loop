#!/usr/bin/env python3
"""
LLM-generated patch for CVE-2026-33017, with live apply + verify_patch()
confirmation.

Pipeline this module completes: detection -> patch_gen -> proof_harness.
detection/ isn't built yet, so get_detection_result() below is a clearly
marked hardcoded stand-in for the AGREED CONTRACT detection/ will eventually
produce -- swapping it for a real call is meant to be a one-function change,
see the comment on get_detection_result().

WHAT THIS ACTUALLY DOES (no mocked steps):
  1. generate_patch()  -- fetches the REAL current source of the vulnerable
     function live from the running container (not a paraphrased snippet),
     retrieves 1-2 short reference fix patterns from reference_fixes.md,
     and asks an LLM for a unified diff + plain-English description.
  2. apply_patch()     -- spins up a second, disposable Langflow container
     (same image, different name/port from the one exploit_repro/ and
     proof_harness/ use for other testing), applies the diff to a real
     copy of the file pulled out of that container via `docker cp`,
     copies the patched file back in, and restarts the container so the
     patched module actually reloads.
  3. __main__           -- runs both, then imports proof_harness.verify and
     calls verify_patch() against the newly patched container for real,
     printing the actual pov_blocked / confidence_score it gets back.

WHY A SECOND CONTAINER, NOT THE LIVE ONE: exploit_repro/ and proof_harness/
both depend on langflow-cve-2026-33017 staying in its known-vulnerable
state for their own testing. patch_gen creates and destroys its own
disposable target (langflow-cve-2026-33017-patched) each run -- same image,
same no-persistent-volume philosophy as
exploit_repro/langflow-cve-2026-33017/docker-compose.yml, just a second
throwaway instance so nothing here can disturb the other two modules.

WHY docker cp + restart, not a rebuilt image: rebuilding the Docker image
from patched source would mean cloning/pinning the exact Langflow source
tree at 1.8.2 and running a full package build -- accurate, but far too
slow for an iterate-in-minutes hackathon loop. Since the vulnerable code is
plain installed Python (found live via `python -c "import langflow"`
inside the container, not hardcoded to one Python/venv version), we can
patch the installed file directly and restart the container's own process
to pick it up. Trade-off: this proves the PATCH ITSELF is correct and
effective against the real running app, but does not prove a from-source
rebuild of the full Langflow package would produce byte-identical behavior
-- for this hackathon's purpose (prove patch_gen produces a real, working
fix) that's the right trade, and it's stated here rather than left implicit.

LOCALHOST-ONLY, same as exploit_repro/exploit.py and proof_harness/verify.py.
patch_gen also only ever touches containers whose name starts with the
project's own container prefix (see _assert_known_container) -- this
machine runs plenty of unrelated Docker containers for other projects, and
a tool that does `docker rm -f`/`docker restart` on an attacker-chosen
name has no business being anything but tightly scoped.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from openai import OpenAI

# ---------------------------------------------------------------------------
# Import-path setup (same rationale as proof_harness/verify.py: this file
# needs `sys` at module level, not just inside __main__, to import its
# sibling package proof_harness before exec() would normally allow it).
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from proof_harness.verify import verify_patch  # noqa: E402

# ---------------------------------------------------------------------------
# Detection input (hardcoded stand-in until detection/ lands)
#
# This is the AGREED CONTRACT between detection/ and patch_gen/. When
# detection/ exists, the only change needed is inside get_detection_result()
# below -- generate_patch()'s signature and every caller stay identical.
# ---------------------------------------------------------------------------

_HARDCODED_DETECTION = {
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


def get_detection_result() -> dict:
    """
    Swap point for detection/. Currently returns the hardcoded stand-in
    above. Once detection/ exists, replace this function's body with
    something like:

        from detection.detect import run_detection
        return run_detection(target_url)

    -- generate_patch(get_detection_result()) elsewhere in this file (and
    any other caller) needs no changes.
    """
    return _HARDCODED_DETECTION


# ---------------------------------------------------------------------------
# Safety guards
# ---------------------------------------------------------------------------

_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

# Both the read-only source container (exploit_repro's) and the disposable
# target this module creates share this name prefix -- see
# _assert_known_container.
_CONTAINER_PREFIX = "langflow-cve-2026-33017"
_SOURCE_CONTAINER = "langflow-cve-2026-33017"          # read real vuln source from here
_PATCHED_CONTAINER = "langflow-cve-2026-33017-patched"  # disposable, created fresh each run
_PATCHED_PORT = 7861
_IMAGE = "langflowai/langflow:1.8.2"

_REFERENCE_FIXES_PATH = Path(__file__).resolve().parent / "reference_fixes.md"

# Cheapest capable chat model for this account, confirmed live before the
# real run (see the run log) -- override with PATCH_GEN_MODEL if your
# account's lineup differs.
_MODEL = os.environ.get("PATCH_GEN_MODEL", "gpt-4o-mini")


def _assert_localhost(url: str) -> None:
    hostname = urllib.parse.urlsplit(url).hostname
    if hostname not in _ALLOWED_HOSTS:
        raise ValueError(
            f"Refusing to target {hostname!r}. This tool is scoped to "
            f"localhost only ({sorted(_ALLOWED_HOSTS)})."
        )


def _assert_known_container(container: str) -> None:
    """
    patch_gen runs `docker rm -f` / `docker restart` on whatever container
    name it's given. This machine has plenty of unrelated Docker containers
    for other projects -- refusing anything outside this project's own
    naming scheme is the same "don't trust the caller, check it yourself"
    posture as _assert_localhost, just for container names instead of URLs.
    """
    if not container.startswith(_CONTAINER_PREFIX):
        raise ValueError(
            f"Refusing to touch container {container!r}. patch_gen only "
            f"operates on containers named {_CONTAINER_PREFIX}* -- nothing "
            f"else on this machine is this tool's business."
        )


# ---------------------------------------------------------------------------
# Docker helpers -- fetching real source, running the disposable target
# ---------------------------------------------------------------------------


def _docker(args: list[str], timeout: int = 30, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, **kwargs)


def _find_package_dir(container: str) -> str:
    """
    Locates the real, installed langflow package directory inside
    `container` via the interpreter itself, rather than hardcoding a
    Python/venv version -- the exact site-packages path (confirmed live:
    /app/.venv/lib/python3.12/site-packages/langflow) is an implementation
    detail of the image build, not something to bake in as a constant.
    """
    proc = _docker(["exec", container, "python", "-c", "import langflow, os; print(os.path.dirname(langflow.__file__))"])
    if proc.returncode != 0:
        raise RuntimeError(f"could not locate the langflow package dir in {container!r}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _fetch_file(container: str, path: str) -> str:
    proc = _docker(["exec", container, "cat", path])
    if proc.returncode != 0:
        raise RuntimeError(f"could not read {path!r} from {container!r}: {proc.stderr.strip()}")
    return proc.stdout


def _wait_for_health(base_url: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=5) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(2)
    return False


def _fetch_vulnerable_context(container: str, detection: dict, context_after: int = 77) -> dict:
    """
    Pulls the REAL current source of the vulnerable function straight from
    the running container -- not the paraphrased snippet in the detection
    contract. Returns the full file split into lines, the 1-indexed
    [start, end] range around the detection's anchor line (matching the
    user-supplied "~lines 580-657" span for this specific CVE), and a
    line-numbered rendering of that range for the prompt.
    """
    package_dir = _find_package_dir(container)
    file_path = f"{package_dir}/api/v1/chat.py"
    content = _fetch_file(container, file_path)
    lines = content.splitlines()

    anchor = detection["line"]
    start = max(1, anchor - 2)
    end = min(len(lines), anchor + context_after)
    numbered = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
    return {"file_path": file_path, "lines": lines, "start": start, "end": end, "numbered_source": numbered}


# ---------------------------------------------------------------------------
# LLM patch generation (retrieval-augmented, not fine-tuned)
#
# "Retrieval" here is deliberately simple: reference_fixes.md holds 1-2
# short, complete examples and we read the whole file into the prompt.
# There's no embedding index because the corpus is two examples -- building
# one would add infrastructure without adding accuracy, and this module is
# scored on being a lightweight solution.
#
# DESIGN NOTE (changed after a live test): the first version of this module
# asked the LLM to hand-write the unified diff directly, including its own
# `@@ -start,count +start,count @@` hunk headers. Live testing against
# gpt-4o-mini showed this fails in exactly the way the task brief warned
# about -- a malformed second hunk header (`@@ -637,7 +636` with no closing
# count/`@@`) and hallucinated `...`/comment lines that don't exist in the
# real file. LLMs are unreliable at hand-computing diff line arithmetic;
# they're reliable at "reproduce this block, changing only what needs to
# change." So the LLM is now asked for the full corrected replacement block
# instead of a diff, and the unified diff (with correct hunk headers) is
# computed locally with difflib -- the LLM still decides WHAT changes, this
# module just stops trusting it to also get line-number bookkeeping right.
# ---------------------------------------------------------------------------

_CODE_FENCE_RE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.DOTALL)

# A live test showed gpt-4o-mini sometimes copies the "580: " line-number
# prefixes from the prompt's numbered source into its "verbatim" reproduction
# despite being told not to -- which then made every single line look
# changed to difflib, since none of them matched the real (unnumbered)
# source. This pattern can never legitimately start a Python source line in
# this context, so stripping it unconditionally is safe insurance rather
# than relying purely on the model following the instruction.
_LINE_NUM_PREFIX_RE = re.compile(r"^\d+:\s?")


def _strip_line_number_prefixes(text: str) -> str:
    return "\n".join(_LINE_NUM_PREFIX_RE.sub("", line, count=1) for line in text.splitlines())
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@$", re.MULTILINE)


def _load_reference_fixes() -> str:
    return _REFERENCE_FIXES_PATH.read_text(encoding="utf-8")


def _build_prompt(detection: dict, context: dict, reference_fixes: str, retry_hint: str | None) -> list[dict]:
    system = (
        "You are a precise security patch generator. You will be given a "
        "vulnerability finding, the EXACT current source of the surrounding "
        "region (with real line numbers), and 1-2 reference fix patterns for "
        "similar vulnerability shapes.\n\n"
        "Output format, exactly:\n"
        "1. A fenced ```python code block containing the FULL corrected "
        "version of EVERY line in the given range (from the first line "
        "number shown to the last), reproduced VERBATIM except for the "
        "minimal edit needed to close the vulnerability. Do not omit, "
        "elide, abbreviate, or summarize any line -- copy every unchanged "
        "line exactly as given, including exact whitespace/indentation, "
        "blank lines, and every OTHER parameter/argument in the function "
        "signature and call sites even though they are unrelated to the "
        "fix. It is critical that you do not drop any parameter, argument, "
        "or line that isn't the one being fixed -- a dropped parameter that "
        "is still referenced elsewhere in the function will crash at "
        "runtime. Never use '...' or any other placeholder. Do not include "
        "the line-number prefixes from the source below -- output plain "
        "source code only.\n"
        "2. Then a line reading exactly 'DESCRIPTION:' followed by a short "
        "plain-English paragraph explaining what changed and why it closes "
        "the vulnerability.\n"
        "Nothing else outside those two sections."
    )

    user = f"""VULNERABILITY FINDING
    file: {detection['file']}
    line: {detection['line']}
    sink_type: {detection['sink_type']}
    taint_source: {detection['taint_source']}
    cve_reference: {detection['cve_reference']}
    description: {detection['description']}

REAL CURRENT SOURCE, lines {context['start']}-{context['end']} (fetched live from the running target at {context['file_path']}; reproduce this exact range, corrected):
{context['numbered_source']}

IMPORTANT CONTEXT you must respect: this file also defines an AUTHENTICATED
sibling route, `/build/{{flow_id}}/flow` (requires a `current_user`
dependency), which legitimately accepts a `data` parameter and shares the
same downstream helper, `start_flow_build()` in langflow/api/build.py. Do
NOT modify start_flow_build, generate_flow_events, create_graph, or
anything else in build.py -- fixing the shared code would break the
legitimate authenticated route. The fix belongs ONLY in the vulnerable
function's own parameter list and its own call site, both of which are
within the range shown above.

CRITICAL: start_flow_build() declares `data` as a REQUIRED keyword
argument with NO default value (`data: FlowDataRequest | None,` -- note
there is no `= None`). This means when you remove the `data` parameter
from build_public_tmp's own signature, you must still pass `data=None`
explicitly in the call to start_flow_build -- do NOT simply delete the
`data=data,` line from the call. Omitting the keyword entirely will raise
`TypeError: missing required keyword-only argument: 'data'` on every call,
which breaks the legitimate public-flow-build feature completely (not just
the exploit) even though it happens to also block the exploit. Replace
`data=data,` with `data=None,` (a trusted constant, never the attacker's
value) -- do not delete that line.

REFERENCE FIX PATTERNS
{reference_fixes}
"""

    if retry_hint:
        user += f"\nYOUR PREVIOUS ATTEMPT FAILED: {retry_hint}\nProduce a corrected full replacement block for the exact same line range shown above.\n"

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _parse_llm_response(raw: str) -> tuple[str, str]:
    """
    Tolerates the two common ways LLMs deviate from "just the code block":
    wrapping it in a markdown fence, and/or adding commentary before or
    after. Returns (corrected_block_text, description_text).
    """
    fence = _CODE_FENCE_RE.search(raw)
    if fence:
        corrected_text = fence.group(1).rstrip("\n")
        remainder = raw[fence.end():]
    else:
        corrected_text = raw.strip("\n")
        remainder = ""

    corrected_text = _strip_line_number_prefixes(corrected_text)

    marker = "DESCRIPTION:"
    idx = remainder.find(marker)
    description = remainder[idx + len(marker):].strip() if idx != -1 else (remainder.strip() or "(model did not provide a separate description)")
    return corrected_text, description


def _build_diff(original_lines: list[str], start: int, end: int, corrected_text: str, file_label: str = "chat.py") -> str:
    """
    Computes a real unified diff between the original [start, end] (1-indexed,
    inclusive) slice of `original_lines` and the LLM's corrected replacement
    -- locally, with difflib, so the hunk header arithmetic is always
    correct. difflib.unified_diff() numbers hunks relative to the slice
    (starting at line 1); _HUNK_HEADER_RE shifts them by (start - 1) so the
    header matches the real file, which is what lets `patch -p0` apply this
    against the full file without any fuzz/guessing.
    """
    original_slice = original_lines[start - 1:end]
    corrected_lines = corrected_text.splitlines()

    raw_diff = "\n".join(
        difflib.unified_diff(
            original_slice, corrected_lines,
            fromfile=file_label, tofile=file_label, lineterm="", n=3,
        )
    )

    offset = start - 1

    def _shift(match: re.Match) -> str:
        old_start = int(match.group(1)) + offset
        old_count = match.group(2)
        new_start = int(match.group(3)) + offset
        new_count = match.group(4)
        old_part = str(old_start) + (f",{old_count}" if old_count is not None else "")
        new_part = str(new_start) + (f",{new_count}" if new_count is not None else "")
        return f"@@ -{old_part} +{new_part} @@"

    return _HUNK_HEADER_RE.sub(_shift, raw_diff)


def _validate_diff_shape(diff_text: str) -> None:
    """Structural sanity check, not proof it applies -- that's apply_patch()'s job."""
    lines = diff_text.splitlines()
    if not any(line.startswith("--- ") for line in lines):
        raise ValueError("no '--- ' header line -- doesn't look like a unified diff")
    if not any(line.startswith("+++ ") for line in lines):
        raise ValueError("no '+++ ' header line -- doesn't look like a unified diff")
    if not any(line.startswith("@@") for line in lines):
        raise ValueError("no '@@' hunk header -- doesn't look like a unified diff")
    if not any(line.startswith(("+", "-")) and not line.startswith(("+++", "---")) for line in lines):
        raise ValueError("diff has headers but no actual +/- change lines -- the model reproduced the source unchanged")


# For CVE-2026-33017 specifically, the known-correct fix (confirmed against
# the real running source, see reference_fixes.md) only ever removes lines
# that mention the `data` parameter -- its declaration, its docstring
# entry, and its one call-site usage. This is intentionally scoped to this
# detection, not a general-purpose semantic checker.
_EXPECTED_REMOVAL_KEYWORD = "data"


def _check_removed_lines_are_scoped(diff_text: str, keyword: str = _EXPECTED_REMOVAL_KEYWORD) -> None:
    """
    Catches a real failure mode a live test turned up: gpt-4o-mini's first
    "full replacement block" attempt silently dropped an unrelated
    parameter (`background_tasks: LimitVertexBuildBackgroundTasks,`) from
    the function signature while still referencing it at the call site --
    syntactically valid, but a NameError at runtime that would break the
    legitimate public-flow feature entirely. None of proof_harness's
    functionality checks happen to call build_public_tmp, so that breakage
    would NOT show up in functionality_tests_passed -- it would silently
    pass verification. This guard raises before that patch ever reaches
    apply_patch(), by refusing any removed line that doesn't mention the
    parameter this fix is actually supposed to touch.
    """
    removed_lines = [line[1:] for line in diff_text.splitlines() if line.startswith("-") and not line.startswith("---")]
    suspicious = [line for line in removed_lines if line.strip() and keyword not in line.lower()]
    if suspicious:
        raise ValueError(
            f"the generated patch removed line(s) unrelated to the `{keyword}` "
            f"parameter, which this fix should never touch: {suspicious!r}"
        )


_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI()  # reads OPENAI_API_KEY from the environment
    return _client


def generate_patch(detection: dict, *, retry_hint: str | None = None) -> dict:
    """
    Generates a patch for `detection` (the hardcoded stand-in contract, or
    eventually detection/'s real output). Fetches the real vulnerable
    source live from _SOURCE_CONTAINER, retrieves reference_fixes.md, calls
    the LLM, and returns:

        {
            "patch_diff": "<unified diff>",
            "patch_description": "<plain English>",
            "model": "<model id>",
            "tokens_used": {"prompt": N, "completion": N},
            "generation_time_seconds": float,
        }

    `retry_hint` is an internal knob (not part of the public contract
    surface __main__ uses on the happy path) letting the __main__ loop feed
    back a concrete apply failure and ask for a corrected diff, instead of
    silently reporting a false success.
    """
    print(f"[*] fetching real vulnerable source from {_SOURCE_CONTAINER} ...")
    context = _fetch_vulnerable_context(_SOURCE_CONTAINER, detection)
    print(
        f"[+] got live source around {detection['file']}:{detection['line']} "
        f"(lines {context['start']}-{context['end']} of {context['file_path']} inside the container)"
    )

    reference_fixes = _load_reference_fixes()
    messages = _build_prompt(detection, context, reference_fixes, retry_hint)

    print(f"[*] calling {_MODEL} to generate the corrected code ...")
    start = time.time()
    response = _get_client().chat.completions.create(
        model=_MODEL,
        messages=messages,
        temperature=0,
    )
    elapsed = time.time() - start

    raw = response.choices[0].message.content or ""
    corrected_text, description = _parse_llm_response(raw)
    diff_text = _build_diff(context["lines"], context["start"], context["end"], corrected_text)
    _validate_diff_shape(diff_text)  # raises ValueError on a malformed/empty diff
    _check_removed_lines_are_scoped(diff_text)  # raises ValueError on an out-of-scope removal

    usage = response.usage
    tokens_used = {
        "prompt": usage.prompt_tokens if usage else 0,
        "completion": usage.completion_tokens if usage else 0,
    }
    print(f"[+] got a parseable diff -- {tokens_used['prompt']}+{tokens_used['completion']} tokens, {elapsed:.2f}s")

    return {
        "patch_diff": diff_text,
        "patch_description": description,
        "model": _MODEL,
        "tokens_used": tokens_used,
        "generation_time_seconds": elapsed,
    }


# ---------------------------------------------------------------------------
# Patch application -- disposable second container, docker cp + restart
# ---------------------------------------------------------------------------


def apply_patch(patch_diff: str, target_container: str = _PATCHED_CONTAINER) -> dict:
    """
    Applies `patch_diff` to a fresh, disposable copy of the vulnerable
    target and returns:

        {
            "applied": bool,
            "container": str,
            "target_url": "http://127.0.0.1:<port>",
            "file_path_in_container": str | None,
            "diff_applied_cleanly": bool,
            "before_after_diff": str,   # the REAL before/after diff, computed
                                         # locally with difflib -- independent
                                         # of whatever the LLM's diff claimed
            "errors": [str, ...],
        }

    Recreates `target_container` from scratch every call (docker rm -f then
    docker run) so each attempt starts from the known-vulnerable baseline,
    same disposable-target philosophy as exploit_repro's docker-compose.yml.
    """
    _assert_known_container(target_container)
    port = _PATCHED_PORT
    result = {
        "applied": False,
        "container": target_container,
        "target_url": f"http://127.0.0.1:{port}",
        "file_path_in_container": None,
        "diff_applied_cleanly": False,
        "before_after_diff": "",
        "errors": [],
    }

    print(f"[*] recreating disposable target {target_container!r} from {_IMAGE} ...")
    _docker(["rm", "-f", target_container])  # best-effort; fine if it didn't exist
    run_proc = _docker(
        [
            "run", "-d",
            "--name", target_container,
            "-p", f"127.0.0.1:{port}:7860",
            "-e", "AUTO_LOGIN=true",
            "-e", "DO_NOT_TRACK=true",
            _IMAGE,
        ],
        timeout=60,
    )
    if run_proc.returncode != 0:
        result["errors"].append(f"docker run failed: {run_proc.stderr.strip()}")
        return result
    print(f"[+] container started: {run_proc.stdout.strip()[:12]}")

    try:
        package_dir = _find_package_dir(target_container)
    except RuntimeError as exc:
        result["errors"].append(str(exc))
        return result
    file_path = f"{package_dir}/api/v1/chat.py"
    result["file_path_in_container"] = file_path

    try:
        before_content = _fetch_file(target_container, file_path)
    except RuntimeError as exc:
        result["errors"].append(str(exc))
        return result

    with tempfile.TemporaryDirectory() as tmp:
        local_file = Path(tmp) / "chat.py"
        local_file.write_text(before_content, encoding="utf-8", newline="\n")

        diff_input = patch_diff if patch_diff.endswith("\n") else patch_diff + "\n"

        print("[*] dry-run applying the generated diff to a local copy ...")
        dry = subprocess.run(
            ["patch", "--dry-run", "-p0", str(local_file)],
            input=diff_input, capture_output=True, text=True, timeout=15,
        )
        if dry.returncode != 0:
            result["errors"].append(
                f"diff did not apply cleanly (dry-run failed): {dry.stdout.strip()} {dry.stderr.strip()}"
            )
            return result

        real = subprocess.run(
            ["patch", "-p0", str(local_file)],
            input=diff_input, capture_output=True, text=True, timeout=15,
        )
        if real.returncode != 0:
            result["errors"].append(
                f"patch apply failed after a successful dry-run (unexpected): {real.stdout.strip()} {real.stderr.strip()}"
            )
            return result

        after_content = local_file.read_text(encoding="utf-8")
        if after_content == before_content:
            result["errors"].append("patch exited 0 but the file content is unchanged -- treating as not applied")
            return result

        result["before_after_diff"] = "\n".join(
            difflib.unified_diff(
                before_content.splitlines(), after_content.splitlines(),
                fromfile=f"{file_path} (before)", tofile=f"{file_path} (after)", lineterm="",
            )
        )
        result["diff_applied_cleanly"] = True

        print("[*] copying the patched file back into the container ...")
        cp_proc = subprocess.run(
            ["docker", "cp", str(local_file), f"{target_container}:{file_path}"],
            capture_output=True, text=True, timeout=15,
        )
        if cp_proc.returncode != 0:
            result["errors"].append(f"docker cp back into the container failed: {cp_proc.stderr.strip()}")
            return result

    print("[*] restarting the container so the patched module reloads ...")
    restart_proc = _docker(["restart", target_container], timeout=60)
    if restart_proc.returncode != 0:
        result["errors"].append(f"docker restart failed: {restart_proc.stderr.strip()}")
        return result

    # A fresh (never-before-initialized) Langflow container's first full
    # boot -- loading components, adding starter projects, etc. -- was
    # measured live in this environment to take up to ~2 minutes, well past
    # what a warm restart of an already-initialized container needs (the
    # other two containers in this repo restart in single-digit seconds
    # because their DB/component cache is already warm). 180s gives
    # comfortable headroom for a genuine cold boot without masking a real
    # hang.
    _HEALTH_TIMEOUT = 180
    print(f"[*] waiting for {result['target_url']}/health to come back up (cold boot, can take ~1-2 min) ...")
    if not _wait_for_health(result["target_url"], timeout=_HEALTH_TIMEOUT):
        result["errors"].append(f"{target_container} restarted but /health never returned 200 within {_HEALTH_TIMEOUT}s")
        return result

    result["applied"] = True
    print(f"[+] patch applied; {target_container} is back up at {result['target_url']}")
    return result


# ---------------------------------------------------------------------------
# Entry point -- generate -> apply -> verify_patch(), with one retry loop
# if the first generated diff doesn't apply cleanly
# ---------------------------------------------------------------------------

_MAX_ATTEMPTS = 3

if __name__ == "__main__":
    detection = get_detection_result()
    print("[*] detection input (hardcoded stand-in for detection/):")
    print(json.dumps(detection, indent=2))

    gen = None
    applied = None
    retry_hint = None

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        print(f"\n[*] generation attempt {attempt}/{_MAX_ATTEMPTS} ...")
        try:
            gen = generate_patch(detection, retry_hint=retry_hint)
        except ValueError as exc:
            print(f"[-] generated output wasn't a valid diff: {exc}")
            retry_hint = str(exc)
            continue

        print("\n" + "-" * 75)
        print("# Generated diff")
        print("-" * 75)
        print(gen["patch_diff"])
        print("\n" + "-" * 75)
        print("# Description")
        print("-" * 75)
        print(gen["patch_description"])

        print(f"\n[*] applying patch (attempt {attempt}) ...")
        applied = apply_patch(gen["patch_diff"], _PATCHED_CONTAINER)
        if applied["applied"]:
            break

        retry_hint = "; ".join(applied["errors"]) or "patch did not apply cleanly"
        print(f"[-] attempt {attempt} failed to apply: {retry_hint}")

    print("\n" + "=" * 70)
    print("# apply_patch() result")
    print("=" * 70)
    print(json.dumps(applied, indent=2, default=str))

    if not applied or not applied["applied"]:
        print("\n[-] patch did not apply cleanly after all attempts -- aborting before verify_patch()")
        sys.exit(1)

    print(f"\n[*] running verify_patch() against {applied['target_url']} ...")
    verdict = verify_patch(applied["target_url"], applied["container"])

    print("\n" + "=" * 70)
    print(f"pov_blocked   : {verdict['pov_blocked']}")
    print(f"functionality : {verdict['functionality_tests_passed']}/{verdict['functionality_tests_total']}")
    print(f"confidence    : {verdict['confidence_score']}")
    print(f"summary       : {verdict['summary']}")
    print("=" * 70)
    print(json.dumps({"generate": gen, "apply": applied, "verify": verdict}, indent=2, default=str))

    clean = verdict["pov_blocked"] and verdict["functionality_tests_passed"] == verdict["functionality_tests_total"]
    sys.exit(0 if clean else 1)
