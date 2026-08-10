# kavach-loop

kavach-loop is a closed-loop vulnerability remediation pipeline that detects a vulnerability, reproduces the exploit to confirm it is real, generates a candidate patch, and verifies that patch against a proof harness before it is trusted — chaining the `detection`, `exploit_repro`, `patch_gen`, and `proof_harness` modules into a single automated cycle.
