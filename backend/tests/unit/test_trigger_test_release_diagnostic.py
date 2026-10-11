"""Read-only release diagnostics reject drift and never print private values."""

from __future__ import annotations

import json
import logging
import sys
import warnings
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.diagnose_trigger_test_release import (
    CHECK_NAMES,
    CHECK_TIMEOUT_SECONDS,
    QUEUE_NAME,
    SCHEDULE_NAME,
    TASK_NAME,
    ReleaseDiagnosticChecks,
    diagnose,
    main,
    read_database_heads,
    read_source_heads,
    read_worker_registration,
)

HOSTNAME = "synthetic-worker-0123"
REVISION = "a74fa3967484"
NOTICE_ORIGIN = "https://synthetic-api.example.test"


def valid_checks() -> ReleaseDiagnosticChecks:
    async def database_heads():
        return (REVISION,)

    return ReleaseDiagnosticChecks(
        source_heads=lambda: (REVISION,),
        database_heads=database_heads,
        worker_registration=lambda hostname: {f"celery@{hostname}": [TASK_NAME]},
        beat_schedule=lambda: {
            SCHEDULE_NAME: {
                "task": TASK_NAME,
                "schedule": 10.0,
                "options": {"queue": QUEUE_NAME},
            }
        },
        notice_configuration=lambda: (NOTICE_ORIGIN, "production"),
    )


def assert_fixed_report(report):
    assert set(report) == {"diagnostic_version", "status", *CHECK_NAMES}
    assert report["diagnostic_version"] == 1
    assert report["status"] in {"ready", "disabled", "failed"}
    assert all(type(report[name]) is bool for name in CHECK_NAMES)


@pytest.mark.asyncio
async def test_healthy_release_is_ready_and_contains_only_fixed_safe_fields():
    report = await diagnose(HOSTNAME, True, valid_checks())
    assert_fixed_report(report)
    assert report["status"] == "ready"
    assert all(report[name] for name in CHECK_NAMES)
    serialized = json.dumps(report)
    assert HOSTNAME not in serialized
    assert REVISION not in serialized
    assert NOTICE_ORIGIN not in serialized


@pytest.mark.asyncio
async def test_empty_origin_is_disabled_only_when_other_release_checks_pass():
    checks = replace(valid_checks(), notice_configuration=lambda: ("", "production"))
    report = await diagnose(HOSTNAME, True, checks)
    assert report["status"] == "disabled"
    assert report["notice_origin_allowed"] is True
    assert report["notice_origin_configured"] is False
    report = await diagnose(
        HOSTNAME, True, replace(checks, worker_registration=lambda hostname: None)
    )
    assert report["status"] == "failed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "origin,environment,allowed",
    [
        ("http://remote.example.test", "production", False),
        ("https://synthetic-api.example.test/path", "production", False),
        ("https://user:synthetic@synthetic-api.example.test", "production", False),
        ("https://synthetic-api.example.test?token=synthetic", "production", False),
        ("https://synthetic-api.example.test\n", "production", False),
        (" ", "production", False),
        ("http://127.0.0.1:8001", "production", False),
        ("http://127.0.0.1:8001", "development", True),
        ("https://synthetic-api.example.test/", "production", True),
    ],
)
async def test_notice_origin_uses_existing_environment_policy(
    origin, environment, allowed
):
    report = await diagnose(
        HOSTNAME,
        True,
        replace(valid_checks(), notice_configuration=lambda: (origin, environment)),
    )
    assert report["notice_origin_configured"] is True
    assert report["notice_origin_allowed"] is allowed
    assert report["status"] == ("ready" if allowed else "failed")
    assert origin not in json.dumps(report, separators=(",", ":"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source,database",
    [
        ((), (REVISION,)),
        ((REVISION, "synthetic-other-head"), (REVISION,)),
        ((REVISION,), ()),
        ((REVISION,), (REVISION, "synthetic-other-head")),
        ((REVISION,), ("synthetic-old-revision",)),
        (REVISION, (REVISION,)),
        ((REVISION,), REVISION),
        ((None,), (REVISION,)),
    ],
)
async def test_database_check_requires_one_matching_source_and_database_head(
    source, database
):
    async def database_heads():
        return database

    report = await diagnose(
        HOSTNAME,
        True,
        replace(
            valid_checks(), source_heads=lambda: source, database_heads=database_heads
        ),
    )
    assert report["status"] == "failed"
    assert report["database_head_matches"] is False
    assert report["worker_registered"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["query", "timeout"])
async def test_database_failure_is_redacted_without_hiding_other_check_results(failure):
    async def database_heads():
        if failure == "timeout":
            raise TimeoutError("synthetic-sensitive-database-information")
        raise RuntimeError("synthetic-sensitive-database-information")

    report = await diagnose(
        HOSTNAME, True, replace(valid_checks(), database_heads=database_heads)
    )
    assert report["database_head_matches"] is False
    assert report["worker_registered"] is True
    assert report["status"] == "failed"
    assert "synthetic-sensitive" not in json.dumps(report)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "registration",
    [
        None,
        {},
        {"celery@other-worker": [TASK_NAME]},
        {f"celery@{HOSTNAME}": []},
        {f"celery@{HOSTNAME}": ["app.schedule.jobs.account_policy.scan"]},
        {f"celery@{HOSTNAME}": TASK_NAME},
        {f"celery@{HOSTNAME}": [TASK_NAME, None]},
        {f"celery@{HOSTNAME}": [TASK_NAME], "celery@other-worker": [TASK_NAME]},
    ],
)
async def test_worker_must_reply_from_the_exact_target_with_the_exact_task(
    registration,
):
    report = await diagnose(
        HOSTNAME,
        True,
        replace(valid_checks(), worker_registration=lambda hostname: registration),
    )
    assert report["status"] == "failed"
    assert report["worker_registered"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entry",
    [
        None,
        {},
        {"task": TASK_NAME, "schedule": 60.0, "options": {"queue": QUEUE_NAME}},
        {"task": TASK_NAME, "schedule": "10.0", "options": {"queue": QUEUE_NAME}},
        {"task": TASK_NAME, "schedule": True, "options": {"queue": QUEUE_NAME}},
        {"task": TASK_NAME, "schedule": 10.0, "options": {"queue": "default"}},
        {
            "task": "synthetic-other-task",
            "schedule": 10.0,
            "options": {"queue": QUEUE_NAME},
        },
        {"task": TASK_NAME, "schedule": 10.0, "options": QUEUE_NAME},
        {
            "task": TASK_NAME,
            "schedule": 10.0,
            "options": {"queue": QUEUE_NAME},
            "args": [1],
        },
    ],
)
async def test_beat_configuration_rejects_changed_task_interval_or_queue(entry):
    report = await diagnose(
        HOSTNAME,
        True,
        replace(valid_checks(), beat_schedule=lambda: {SCHEDULE_NAME: entry}),
    )
    assert report["status"] == "failed"
    assert report["beat_schedule_correct"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hostname,verified",
    [
        ("", True),
        ("a" * 64, True),
        ("-worker", True),
        ("worker-", True),
        ("worker.example.test", True),
        ("worker\nprivate", True),
        ("worker;echo-private", True),
        ("celery@worker", True),
        (HOSTNAME, False),
        (HOSTNAME, 1),
    ],
)
async def test_invalid_runtime_assertion_or_hostname_prevents_dependency_calls(
    hostname, verified
):
    def forbidden():
        raise AssertionError("Dependencies must not be reached")

    checks = replace(valid_checks(), source_heads=forbidden)
    report = await diagnose(hostname, verified, checks)
    assert_fixed_report(report)
    assert report["status"] == "failed"
    assert all(report[name] is False for name in CHECK_NAMES)


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--worker-hostname", HOSTNAME],
        ["--runtime-containers-verified"],
        [
            "--worker-hostname",
            "synthetic-sensitive\nargument",
            "--runtime-containers-verified",
        ],
        [
            "--worker-hostname",
            HOSTNAME,
            "--runtime-containers-verified",
            "--synthetic-secret",
        ],
        ["--help"],
    ],
)
def test_invalid_cli_always_prints_one_fixed_failure_line_and_no_stderr(
    arguments, capsys
):
    assert main(arguments, checks=valid_checks()) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert len(captured.out.splitlines()) == 1
    report = json.loads(captured.out)
    assert_fixed_report(report)
    assert report["status"] == "failed"
    assert "synthetic-sensitive" not in captured.out
    assert "synthetic-secret" not in captured.out


def test_cli_suppresses_dependency_output_and_restores_process_context(capsys):
    previous_directory = Path.cwd()
    previous_logging_level = logging.root.manager.disable

    def noisy_source_heads():
        assert Path.cwd() != previous_directory
        assert not tuple(Path.cwd().iterdir())
        print("synthetic-sensitive-stdout")
        print("synthetic-sensitive-stderr", file=sys.stderr)
        logging.error("synthetic-sensitive-log")
        warnings.warn("synthetic-sensitive-warning", RuntimeWarning, stacklevel=1)
        raise RuntimeError("synthetic-sensitive-exception")

    assert (
        main(
            ["--worker-hostname", HOSTNAME, "--runtime-containers-verified"],
            checks=replace(valid_checks(), source_heads=noisy_source_heads),
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    assert len(captured.out.splitlines()) == 1
    assert "synthetic-sensitive" not in captured.out
    report = json.loads(captured.out)
    assert report["status"] == "failed"
    assert report["worker_registered"] is True
    assert Path.cwd() == previous_directory
    assert logging.root.manager.disable == previous_logging_level


@pytest.mark.parametrize("origin,status", [(NOTICE_ORIGIN, "ready"), ("", "disabled")])
def test_cli_accepts_ready_or_explicit_disabled_only(origin, status, capsys):
    assert (
        main(
            ["--worker-hostname", HOSTNAME, "--runtime-containers-verified"],
            checks=replace(
                valid_checks(), notice_configuration=lambda: (origin, "production")
            ),
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["status"] == status
    assert_fixed_report(report)


def test_worker_inspection_is_targeted_bounded_and_does_not_send_a_task():
    calls = []

    def inspect(**arguments):
        calls.append(arguments)
        return SimpleNamespace(registered=lambda: {f"celery@{HOSTNAME}": [TASK_NAME]})

    app = SimpleNamespace(control=SimpleNamespace(inspect=inspect))
    result = read_worker_registration(HOSTNAME, app)
    assert result == {f"celery@{HOSTNAME}": [TASK_NAME]}
    assert calls == [
        {"destination": [f"celery@{HOSTNAME}"], "timeout": CHECK_TIMEOUT_SECONDS}
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("query_fails", [False, True])
async def test_database_reader_executes_only_metadata_select_and_disposes(query_fails):
    statements = []

    class Result:
        def scalars(self):
            return self

        def all(self):
            return [REVISION]

    class Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *arguments):
            return False

        async def execute(self, statement):
            statements.append(str(statement))
            if query_fails:
                raise RuntimeError("Synthetic query failure")
            return Result()

    class Engine:
        echo = True
        disposed = False

        def connect(self):
            return Connection()

        async def dispose(self):
            self.disposed = True

    engine = Engine()
    if query_fails:
        with pytest.raises(RuntimeError, match="Synthetic query failure"):
            await read_database_heads(lambda: engine)
    else:
        assert await read_database_heads(lambda: engine) == (REVISION,)
    assert statements == ["SELECT version_num FROM alembic_version"]
    assert engine.echo is False
    assert engine.disposed is True


def test_packaged_source_head_is_read_without_running_migration_environment():
    assert tuple(read_source_heads()) == (REVISION,)


def test_source_reader_reports_branching_without_running_environment(tmp_path):
    (tmp_path / "alembic.ini").write_text("[alembic]\n", encoding="utf-8")
    migrations = tmp_path / "migrations"
    versions = migrations / "versions"
    versions.mkdir(parents=True)
    (migrations / "env.py").write_text(
        "raise AssertionError('Migration environment must not execute')\n",
        encoding="utf-8",
    )
    for revision in ("aa0000000001", "aa0000000002"):
        (versions / f"{revision}.py").write_text(
            f"revision = {revision!r}\ndown_revision = None\n",
            encoding="utf-8",
        )
    assert set(read_source_heads(tmp_path)) == {"aa0000000001", "aa0000000002"}
