---
name: test-driven-development
description: Use explicitly when implementing a feature or bug fix with a test-first red-green-refactor workflow.
---

# Test-Driven Development

Use a short red-green-refactor loop. This project-local adaptation is based on
Superpowers 6.3.0. See `../SUPERPOWERS_LICENSE.txt`.

This Skill is intentionally explicit-only so an interview POC can choose the
right verification depth for its timebox.

## Red

1. Name the exact production break the test should catch.
2. Write one focused behavioral test with independently derived expectations.
3. Run it and confirm it fails for the expected reason, not because of setup,
   imports, syntax, or missing infrastructure.
4. If it passes immediately, improve the test or confirm the behavior already
   exists before writing implementation code.

## Green

1. Add the smallest production change that makes the test pass.
2. Avoid speculative abstractions, unrelated cleanup, and extra features.
3. Run the focused test and read its exit status and output.

## Refactor

1. Improve names and structure without changing behavior.
2. Keep route handlers thin, business logic in services, and frontend/backend
   contracts aligned as required by `AGENTS.md`.
3. Re-run the focused test after each meaningful refactor.
4. Run the relevant broader suite before completion.

## Test Quality Gates

- Assert observable behavior, not private structure or exact source text.
- Prefer real components; mock only slow, external, or nondeterministic edges.
- Mock responses must match the complete real contract used by the code.
- Do not assert that a mock exists; assert the real outcome.
- Cover realistic mutations: wrong branch, wrong argument, missing side effect,
  empty result, malformed input, unauthorized access, and boundary values.
- Do not add tests only to increase coverage.

## Project Commands

- Follow the Docker-first verification rules in `AGENTS.md`.
- Use `pnpm` for frontend commands; never use npm or yarn.
- Use the repository's existing Python test tooling after activating
  `backend/venv`; do not create an ad-hoc environment silently.

Finish by applying `verification-before-completion`.
