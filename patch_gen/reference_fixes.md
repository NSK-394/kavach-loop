# Reference fix patterns

Retrieval corpus for `generate_patch()`. Two short, real examples of the same
vulnerability shape: an endpoint that is unauthenticated *by design* (a
public-facing route) but wrongly trusts attacker-supplied structural input
instead of only using the trusted, stored version of that input. This is
deliberately small -- two examples read in full and dropped into the prompt
verbatim, not a vector-searched corpus. For a fix this narrow (one function,
one parameter to remove), embedding-based retrieval over a large corpus
would add infrastructure and latency without improving the answer; reading
~40 lines of markdown is cheaper and just as effective. That's the
"lightweight" choice this module is scored on.

---

## Reference 1: CVE-2026-33017 itself (GHSA-vwmf-pq79-vjvx), official advisory fix

**Vulnerable pattern** -- a public/unauthenticated route accepts a `data`
body parameter and forwards it into the same code path an authenticated
route uses to build structural objects from client input:

```python
@router.post("/build_public_tmp/{flow_id}/flow")
async def build_public_tmp(
    *,
    flow_id: uuid.UUID,
    data: Annotated[FlowDataRequest | None, Body(embed=True)] = None,
    ...
):
    ...
    job_id = await start_flow_build(
        flow_id=new_flow_id,
        data=data,   # attacker-controlled, reaches exec() deep in the build path
        ...
    )
```

**Fix** -- for the *public, unauthenticated* route specifically, remove the
`data` parameter entirely so the build can only ever come from the flow's
own stored, trusted database definition. `inputs` (runtime values, not
structure) is fine to keep -- it can't inject new code, only fill in
existing input slots.

```python
@router.post("/build_public_tmp/{flow_id}/flow")
async def build_public_tmp(
    *,
    flow_id: uuid.UUID,
    inputs: Annotated[InputValueRequest | None, Body(embed=True)] = None,
    # REMOVED: data parameter -- public/unauthenticated builds must only
    # ever come from the flow's stored DB definition, never client input.
    ...
):
    ...
    job_id = await start_flow_build(
        flow_id=new_flow_id,
        inputs=inputs,
        data=None,  # ALWAYS None here -- never forward attacker input,
                    # but the callee requires this keyword, so pass a
                    # trusted constant rather than omitting it.
        ...
    )
```

**Sharp edge that's easy to get wrong (caught via live testing against the
real target, not caught by just reading the advisory)**: the shared helper
being called (`start_flow_build`, and the `generate_flow_events` /
`create_graph` it delegates to) declares `data` as a REQUIRED keyword
argument with NO default value. If the fix simply *omits* `data=data` from
the call instead of passing `data=None`, every call raises
`TypeError: missing required keyword-only argument: 'data'` -- which
happens to also block the exploit (the request 500s before the malicious
code ever runs), but it does so by breaking the legitimate public-flow
feature entirely, for every caller, not just the attacker. That is a
functionality regression wearing a security-fix costume: a test suite that
never happens to call this specific endpoint would see the exploit
blocked, all its (unrelated) checks pass, and report a clean, high-confidence
patch -- while the real public-build feature is completely dead. Always
verify by actually calling the patched endpoint the way a legitimate
caller would, not just by confirming the exploit no longer succeeds.

**Important scoping note**: the *authenticated* sibling route (in this
codebase, `/build/{flow_id}/flow`, which requires a `current_user`
dependency) legitimately needs `data` -- it's how the flow editor builds
unsaved in-progress changes for a logged-in user who owns them. The shared
downstream helper both routes call (`start_flow_build` /
`generate_flow_events` / `create_graph`) must NOT be changed, since that
would also break the authenticated route. The fix belongs only at the
unauthenticated route's own parameter list and its own call site -- the
smallest change that closes the hole without touching legitimate behavior
elsewhere.

---

## Reference 2: general pattern -- untrusted structural input on a
no-auth route reaching code execution

This is a recurring shape across many frameworks, not specific to one CVE:
a route intentionally has no auth check (because it's meant to be public --
a webhook receiver, a public demo endpoint, a share link) but accepts a
field that describes *what code/logic to run*, rather than just *data to
plug into already-trusted logic*. The fix is never "add auth" (the route is
supposed to be public) -- it's "stop accepting structure/code from the
caller on this specific route; only accept plain data values, and only ever
execute/interpret the structure that's already stored server-side."

```python
# Vulnerable shape
@router.post("/public/run/{job_id}")
async def run_public_job(job_id: str, script: str | None = None):
    stored = get_stored_job(job_id)
    code_to_run = script if script is not None else stored.script  # attacker wins
    exec(compile(code_to_run, "<job>", "exec"))

# Fixed shape
@router.post("/public/run/{job_id}")
async def run_public_job(job_id: str, inputs: dict | None = None):
    stored = get_stored_job(job_id)
    exec(compile(stored.script, "<job>", "exec"), {"inputs": inputs or {}})
```

The parameter that let the caller supply *code/structure* is removed from
the public route entirely; only plain, non-executable *data* parameters
remain, and the thing that actually gets executed always comes from the
trusted, server-side stored copy.
