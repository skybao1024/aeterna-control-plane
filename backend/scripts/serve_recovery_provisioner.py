"""Serve the recovery KMS provisioner through a private Unix socket.

Working directory: /app. Run inside the recovery-provisioner container with
``python -m scripts.serve_recovery_provisioner``. The process accepts no
arguments and never reads application database, JWT, email, or identity keys.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import uvicorn

from app.services.common.aeterna_recovery_key import RecoveryKeyUnavailable
from app.services.internal.aeterna_recovery_provisioner import (
    configuration_from_environment,
    create_recovery_provisioner_app,
)


def main() -> int:
    try:
        configuration = configuration_from_environment(os.environ)
        socket_path = Path(configuration.socket_path)
        parent = socket_path.parent
        if not parent.is_dir() or parent.is_symlink():
            raise RecoveryKeyUnavailable(
                "Recovery provisioner socket directory is invalid"
            )
        if socket_path.exists() or socket_path.is_symlink():
            metadata = socket_path.lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise RecoveryKeyUnavailable(
                    "Recovery provisioner socket path is invalid"
                )
            socket_path.unlink()
        os.umask(0o077)
        uvicorn.run(
            create_recovery_provisioner_app(configuration),
            uds=str(socket_path),
            access_log=False,
            proxy_headers=False,
            server_header=False,
            workers=1,
        )
        return 0
    except RecoveryKeyUnavailable:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
