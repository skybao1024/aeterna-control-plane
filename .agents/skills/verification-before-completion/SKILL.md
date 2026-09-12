---
name: verification-before-completion
description: Use before claiming that code is correct, tests pass, a build succeeds, or requested work is complete.
---

# Verification Before Completion

Evidence must precede a success claim. This project-local adaptation is based
on Superpowers 6.3.0. See `../SUPERPOWERS_LICENSE.txt`.

## Gate

Before stating or implying success:

1. Identify the command or observation that proves the exact claim.
2. Run it now; stale output and another agent's report are not evidence.
3. Read the full relevant output and exit status.
4. Check that the command actually covers the changed behavior.
5. State the result with the evidence. If verification did not run or failed,
   state the real status and remaining risk.

## Claim-to-Evidence Mapping

| Claim | Required fresh evidence |
| --- | --- |
| Test passes | Relevant test command exits successfully with zero failures |
| Regression fixed | Reproduction fails before the fix and passes after it |
| Frontend compiles | `pnpm type-check` or required build exits successfully |
| Integration works | Docker-based API or service check succeeds |
| Requirements met | Re-read the request and verify each acceptance item |
| Review clean | Inspect the actual diff and report residual risks |

## Project Verification Rules

- Use Docker for integration, API, migrations, and service-level checks.
- Use focused verification first; add broader checks in proportion to risk.
- For TypeScript changes, run the required `pnpm` checks from `frontend/`.
- Never inspect runtime environment files or expose secret values in evidence.
- Do not substitute lint output for compilation or integration evidence.
- Do not claim unrun checks passed.

This gate applies before commits, pull requests, task completion, handoff, and
any positive statement about correctness or readiness.
