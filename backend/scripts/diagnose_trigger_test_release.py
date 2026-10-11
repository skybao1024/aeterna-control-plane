"""Print a fixed, redacted trigger-test release receipt inside the backend container.

Working directory: /app. Run python -m scripts.diagnose_trigger_test_release
--worker-hostname <Docker-hostname> --runtime-containers-verified. The trusted
release shell supplies the verification flag only after checking the backend,
worker, and beat image identity and container health. This process has no Docker
socket access and does not independently inspect those containers.

Only packaged migration metadata, SELECT from alembic_version, targeted Celery
registration inspection, process configuration, and beat configuration are read.
The beat check verifies configuration, not observed scheduler execution. No
runtime environment files, secret providers, email probes, or tasks are invoked.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import re
import sys
import tempfile
import warnings
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from celery import Celery
    from sqlalchemy.ext.asyncio import AsyncEngine

DIAGNOSTIC_VERSION = 1
TASK_NAME = "app.schedule.jobs.trigger_test.run"
SCHEDULE_NAME = "run-isolated-trigger-tests"
QUEUE_NAME = "scheduled_tasks"
CHECK_TIMEOUT_SECONDS = 8
WORKER_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
SOURCE_ROOT = Path(__file__).resolve().parents[1]
CHECK_NAMES = (
    "database_head_matches",
    "worker_registered",
    "beat_schedule_correct",
    "notice_origin_allowed",
    "notice_origin_configured",
    "runtime_images_match",
    "runtime_services_healthy",
)


class DiagnosticArgumentError(ValueError):
    """Reject arguments without including their contents in an error."""


class DiagnosticArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise DiagnosticArgumentError() from None


@dataclass(frozen=True)
class ReleaseDiagnosticChecks:
    source_heads: Callable[[], Sequence[str]]
    database_heads: Callable[[], Awaitable[Sequence[str]]]
    worker_registration: Callable[[str], object]
    beat_schedule: Callable[[], object]
    notice_configuration: Callable[[], tuple[str, str]]


def failed_report() -> dict[str, int | str | bool]:
    return {
        "diagnostic_version": DIAGNOSTIC_VERSION,
        "status": "failed",
        **{name: False for name in CHECK_NAMES},
    }


def read_source_heads(source_root: Path = SOURCE_ROOT) -> Sequence[str]:
    """Read packaged revisions without running Alembic's migration environment."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    configuration = Config(str(source_root / "alembic.ini"))
    configuration.set_main_option("script_location", str(source_root / "migrations"))
    return tuple(ScriptDirectory.from_config(configuration).get_heads())


async def read_database_heads(
    engine_provider: Callable[[], AsyncEngine] | None = None,
) -> Sequence[str]:
    """Use the application's async engine for one read-only metadata query."""
    from sqlalchemy import text

    if engine_provider is None:
        from app.db.base import get_engine

        engine_provider = get_engine
    engine = engine_provider()
    engine.echo = False
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text("SELECT version_num FROM alembic_version")
            )
            return tuple(result.scalars().all())
    finally:
        await engine.dispose()


def read_worker_registration(hostname: str, app: Celery | None = None) -> object:
    """Inspect only the release's worker, without dispatching a business task."""
    if app is None:
        from app.core.celery_app import celery_app

        app = celery_app
    inspector = app.control.inspect(
        destination=[f"celery@{hostname}"], timeout=CHECK_TIMEOUT_SECONDS
    )
    return inspector.registered()


def read_beat_schedule() -> object:
    from app.core.celery_app import celery_app

    return celery_app.conf.beat_schedule


def read_notice_configuration() -> tuple[str, str]:
    from app.core.config import settings

    return settings.AETERNA_TRIGGER_TEST_NOTICE_ORIGIN, settings.ENV


def runtime_checks() -> ReleaseDiagnosticChecks:
    return ReleaseDiagnosticChecks(
        source_heads=read_source_heads,
        database_heads=read_database_heads,
        worker_registration=read_worker_registration,
        beat_schedule=read_beat_schedule,
        notice_configuration=read_notice_configuration,
    )


def single_revision(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or len(value) != 1
        or not isinstance(value[0], str)
        or not value[0]
        or len(value[0]) > 255
    ):
        return ()
    return (value[0],)


def worker_registered(value: object, hostname: str) -> bool:
    target = f"celery@{hostname}"
    if not isinstance(value, Mapping) or set(value) != {target}:
        return False
    tasks = value[target]
    return (
        isinstance(tasks, Sequence)
        and not isinstance(tasks, (str, bytes))
        and all(isinstance(task, str) for task in tasks)
        and TASK_NAME in tasks
    )


def beat_schedule_correct(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    entry = value.get(SCHEDULE_NAME)
    if not isinstance(entry, Mapping) or set(entry) != {"task", "schedule", "options"}:
        return False
    options = entry["options"]
    interval = entry["schedule"]
    return (
        entry["task"] == TASK_NAME
        and isinstance(interval, (int, float))
        and not isinstance(interval, bool)
        and interval == 10.0
        and isinstance(options, Mapping)
        and set(options) == {"queue"}
        and options["queue"] == QUEUE_NAME
    )


async def diagnose(
    hostname: str,
    runtime_containers_verified: bool,
    checks: ReleaseDiagnosticChecks,
) -> dict[str, int | str | bool]:
    """Evaluate independent checks and retain only fixed boolean results."""
    report = failed_report()
    if (
        not isinstance(hostname, str)
        or WORKER_HOSTNAME.fullmatch(hostname) is None
        or runtime_containers_verified is not True
    ):
        return report
    report["runtime_images_match"] = True
    report["runtime_services_healthy"] = True

    try:
        expected = single_revision(checks.source_heads())
        observed = single_revision(
            await asyncio.wait_for(
                checks.database_heads(), timeout=CHECK_TIMEOUT_SECONDS
            )
        )
        report["database_head_matches"] = bool(expected) and observed == expected
    except Exception:
        pass
    try:
        report["worker_registered"] = worker_registered(
            checks.worker_registration(hostname), hostname
        )
    except Exception:
        pass
    try:
        report["beat_schedule_correct"] = beat_schedule_correct(checks.beat_schedule())
    except Exception:
        pass
    try:
        from app.services.common.aeterna_trigger_test_origin import (
            validated_test_notice_origin,
        )

        origin, environment = checks.notice_configuration()
        if isinstance(origin, str) and isinstance(environment, str):
            report["notice_origin_configured"] = bool(origin)
            report["notice_origin_allowed"] = not origin or bool(
                validated_test_notice_origin(origin, environment)
            )
    except Exception:
        pass

    required = (name for name in CHECK_NAMES if name != "notice_origin_configured")
    if all(report[name] is True for name in required):
        report["status"] = "ready" if report["notice_origin_configured"] else "disabled"
    return report


@contextlib.contextmanager
def private_runtime_context() -> Iterator[None]:
    """Suppress dependency diagnostics and prevent implicit relative .env loading."""
    previous_logging_level = logging.root.manager.disable
    previous_directory = Path.cwd()
    try:
        with tempfile.TemporaryDirectory(
            prefix="aeterna-trigger-test-diagnostic-"
        ) as directory, open(os.devnull, "w", encoding="utf-8") as sink:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    logging.disable(logging.CRITICAL)
                    os.chdir(directory)
                    try:
                        yield
                    finally:
                        os.chdir(previous_directory)
    finally:
        logging.disable(previous_logging_level)


def main(
    argv: Sequence[str] | None = None,
    *,
    checks: ReleaseDiagnosticChecks | None = None,
) -> int:
    report = failed_report()
    try:
        with private_runtime_context():
            parser = DiagnosticArgumentParser(add_help=False)
            parser.add_argument("--worker-hostname", required=True)
            parser.add_argument(
                "--runtime-containers-verified", action="store_true", required=True
            )
            arguments = parser.parse_args(argv)
            report = asyncio.run(
                diagnose(
                    arguments.worker_hostname,
                    arguments.runtime_containers_verified,
                    runtime_checks() if checks is None else checks,
                )
            )
    except (Exception, KeyboardInterrupt, SystemExit):
        report = failed_report()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] in {"ready", "disabled"} else 1


if __name__ == "__main__":
    sys.exit(main())
