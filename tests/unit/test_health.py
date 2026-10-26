from fastapi.testclient import TestClient

import app.main as main
from app.main import app

client = TestClient(app)


def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_degraded_after_repeated_sweep_failures():
    # The module-level client's sweeper already ran once at startup, so set
    # consecutive failures directly and read health before the next sweep
    # (30s window) can reset it.
    main._pam_expiry_consecutive_failures = (
        main.PAM_EXPIRY_HEALTH_FAILURE_THRESHOLD
    )
    main._pam_expiry_last_error = "sweep database unavailable"
    try:
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["pam_expiry"]["consecutive_failures"] == 3
        assert body["pam_expiry"]["last_error"] == "sweep database unavailable"
    finally:
        main._record_pam_expiry_success()


def test_health_recovers_after_success():
    main._pam_expiry_consecutive_failures = 5
    main._pam_expiry_last_error = "old error"
    main._record_pam_expiry_success()

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["pam_expiry"]["consecutive_failures"] == 0
    assert response.json()["pam_expiry"]["last_error"] is None
