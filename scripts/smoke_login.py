"""Fresh-clone smoke test: boot the real app on the configured database and log in.

Usage (after `python -m app.db.seed`):
    IDENTITYGUARD_SEED_PASSWORD=... python -m scripts.smoke_login
Exits non-zero if the app cannot start, log in, or authorize the demo admin.
"""
import os
import sys

from fastapi.testclient import TestClient

from app.main import app


def main() -> int:
    password = os.environ.get("IDENTITYGUARD_SEED_PASSWORD")
    if not password:
        print("Set IDENTITYGUARD_SEED_PASSWORD to the password used when seeding.")
        return 2

    with TestClient(app) as client:  # `with` runs the startup lifespan
        assert client.get("/health").json()["status"] == "ok"

        login = client.post(
            "/auth/login",
            json={"username": "identityguard.admin", "password": password},
        )
        assert login.status_code == 200, f"login failed: {login.status_code}"

        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        me = client.get("/auth/me", headers=headers).json()
        assert "IdentityGuard:role.assign_privileged" in me["permissions"], me
        report = client.get("/reports/sod-violations", headers=headers)
        assert report.status_code == 200, report.status_code

    print("SMOKE TEST OK: app boots, admin can log in and is authorized.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
