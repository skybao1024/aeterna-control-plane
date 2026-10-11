"""Check the private recovery provisioner without generating key material.

Working directory: /app. Run inside either backend container with
``python -m scripts.check_recovery_provisioner``. Output is a fixed status label
and contains no credential, key ARN, socket path, or provider diagnostics.
"""

from __future__ import annotations

import os

import httpx

from app.services.common.aeterna_recovery_key import DEFAULT_PROVISIONER_SOCKET


def main() -> int:
    socket_path = os.environ.get(
        "AETERNA_RECOVERY_PROVISIONER_SOCKET", DEFAULT_PROVISIONER_SOCKET
    )
    try:
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=socket_path),
            base_url="http://recovery-provisioner",
            timeout=httpx.Timeout(3.0),
        ) as client:
            response = client.get("/health")
            response.raise_for_status()
            healthy = response.json() == {"status": "healthy"}
    except Exception:
        healthy = False
    print(
        "recovery_provisioner_healthy"
        if healthy
        else "recovery_provisioner_unavailable"
    )
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
