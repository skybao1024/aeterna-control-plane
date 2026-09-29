"""Check ORM relationships after the application imports its route modules."""

import subprocess
import sys


def test_application_import_registers_related_models():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import main; from sqlalchemy.orm import configure_mappers; "
            "configure_mappers()",
        ],
        capture_output=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0
