---
name: systematic-debugging
description: Use when a bug, failing test, performance regression, or unexpected behavior must be diagnosed before proposing a fix.
---

# Systematic Debugging

Find the root cause before changing code. Do not stack speculative fixes.

This project-local adaptation is based on Superpowers 6.3.0. See
`../SUPERPOWERS_LICENSE.txt`.

## Phase 1: Establish Evidence

1. Read the complete error, stack trace, logs, and exit status.
2. Reproduce the problem with the smallest reliable command.
3. Identify the last known-good behavior and relevant recent changes.
4. Trace inputs and state across component boundaries.
5. Do not read runtime `.env` files or print environment values. Use
   `.env.example`, variable names, presence-only checks, and sanitized output.

For full-stack failures, inspect each boundary separately:

```text
Browser -> frontend client -> HTTP contract -> route -> service -> database/task
```

Record what enters and leaves each boundary without exposing secrets.

## Phase 2: Compare Patterns

1. Find a working example in the repository.
2. Compare structure, dependencies, configuration, and data flow.
3. List every meaningful difference before deciding which one matters.
4. Follow the repository's established architecture rather than inventing a
   parallel pattern.

## Phase 3: Test One Hypothesis

State one falsifiable hypothesis and the evidence supporting it. Make the
smallest diagnostic change or run the narrowest command that can disprove it.
If disproved, discard it and form a new hypothesis; do not accumulate fixes.

If three independent fix attempts fail, stop and reassess the design or
boundary assumptions before attempting another change.

## Phase 4: Fix and Verify

1. Add or identify a failing reproduction where practical.
2. Fix the cause at its source, not only the visible symptom.
3. Add validation at appropriate entry, service, persistence, and operational
   boundaries when the same invalid state could re-enter elsewhere.
4. Replace arbitrary sleeps with condition-based waits unless timing itself is
   the behavior under test.
5. Run focused checks, then the broader checks required by `AGENTS.md`.
6. Apply `verification-before-completion` before claiming success.

## Project Command Rules

- Use Docker for integration, API, migration, and service verification.
- Use `pnpm`, never npm or yarn, for frontend work.
- Do not start the application on the host with `python main.py`.
- Never expose credentials while diagnosing external services.

## Stop Conditions

Pause and report evidence when reproduction is impossible, required authority
is missing, the proposed fix expands scope materially, or the same failure has
survived three distinct hypotheses.
