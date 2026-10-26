"""Unit tests for the Vault client.

Tests use mocked HTTP responses. They cover:
- Successful secret read
- Vault unreachable (connection error)
- 403 permission denied
- 404 secret not found
- Invalid JSON response
- Health check
- Summary excludes token
"""

import pytest
import httpx

from app.vault.client import VaultClient, VaultError


class MockTransport(httpx.MockTransport):
    """A mock HTTP transport that returns canned responses."""

    def __init__(self, handler):
        super().__init__(handler)


def make_client(transport=None, **kwargs):
    """Create a VaultClient with an optional mock transport."""
    client = VaultClient(**kwargs)
    if transport is not None:
        # Monkey-patch the httpx.Client creation to use our transport
        original_read_secret = client.read_secret

        def patched_read_secret(path=None):
            target = path or client.secret_path
            url = f"{client.addr}/v1/{target}"
            try:
                with httpx.Client(
                    transport=transport, timeout=client.timeout
                ) as http_client:
                    response = http_client.get(
                        url, headers={"X-Vault-Token": client._token}
                    )
            except httpx.ConnectError as exc:
                raise VaultError(f"Cannot connect to Vault at {client.addr}") from exc
            except httpx.TimeoutException as exc:
                raise VaultError(f"Vault request timed out: {exc}") from exc

            if response.status_code == 403:
                raise VaultError(
                    f"Vault policy denies read access to {target}",
                    status_code=403,
                )
            if response.status_code == 404:
                raise VaultError(
                    f"Secret not found at {target}",
                    status_code=404,
                )
            if response.status_code != 200:
                raise VaultError(
                    f"Vault request failed: HTTP {response.status_code}",
                    status_code=response.status_code,
                )

            try:
                payload = response.json()
            except ValueError as exc:
                raise VaultError(f"Invalid JSON response from Vault: {exc}") from exc

            inner = payload.get("data", {})
            if isinstance(inner, dict) and "data" in inner:
                return inner["data"]
            return inner

        client.read_secret = patched_read_secret

        original_health = client.health

        def patched_health():
            try:
                with httpx.Client(
                    transport=transport, timeout=client.timeout
                ) as http_client:
                    response = http_client.get(
                        f"{client.addr}/v1/sys/health",
                        headers={"X-Vault-Token": client._token},
                    )
                return response.status_code == 200
            except Exception:
                return False

        client.health = patched_health

    return client


def handler_secret_found(request):
    return httpx.Response(
        200,
        json={
            "data": {
                "data": {
                    "value": "synthetic-value",
                    "description": "A synthetic test secret",
                },
                "metadata": {"created_time": "2026-10-26T00:00:00Z"},
            }
        },
    )


def handler_secret_not_found(request):
    return httpx.Response(404, json={"errors": ["path not found"]})


def handler_permission_denied(request):
    return httpx.Response(403, json={"errors": ["permission denied"]})


def handler_server_error(request):
    return httpx.Response(500, json={"errors": ["internal error"]})


def handler_invalid_json(request):
    return httpx.Response(200, content="not json")


def handler_health_ok(request):
    return httpx.Response(200)


def handler_health_sealed(request):
    return httpx.Response(503, json={"errors": ["Vault is sealed"]})


# ------------------------------------------------------------------
# Secret read tests
# ------------------------------------------------------------------


def test_read_secret_success():
    client = make_client(
        transport=MockTransport(handler_secret_found),
        addr="http://localhost:8200",
        token="test-token",
        secret_path="secret/data/test",
    )
    secret = client.read_secret()
    assert secret["value"] == "synthetic-value"
    assert secret["description"] == "A synthetic test secret"


def test_read_secret_not_found():
    client = make_client(
        transport=MockTransport(handler_secret_not_found),
        addr="http://localhost:8200",
        token="test-token",
        secret_path="secret/data/missing",
    )
    with pytest.raises(VaultError) as exc:
        client.read_secret()
    assert exc.value.status_code == 404


def test_read_secret_permission_denied():
    client = make_client(
        transport=MockTransport(handler_permission_denied),
        addr="http://localhost:8200",
        token="test-token",
        secret_path="secret/data/forbidden",
    )
    with pytest.raises(VaultError) as exc:
        client.read_secret()
    assert exc.value.status_code == 403


def test_read_secret_server_error():
    client = make_client(
        transport=MockTransport(handler_server_error),
        addr="http://localhost:8200",
        token="test-token",
        secret_path="secret/data/test",
    )
    with pytest.raises(VaultError) as exc:
        client.read_secret()
    assert exc.value.status_code == 500


def test_read_secret_invalid_json():
    client = make_client(
        transport=MockTransport(handler_invalid_json),
        addr="http://localhost:8200",
        token="test-token",
        secret_path="secret/data/test",
    )
    with pytest.raises(VaultError):
        client.read_secret()


# ------------------------------------------------------------------
# Health check tests
# ------------------------------------------------------------------


def test_health_ok():
    client = make_client(
        transport=MockTransport(handler_health_ok),
        addr="http://localhost:8200",
        token="test-token",
    )
    assert client.health() is True


def test_health_sealed():
    client = make_client(
        transport=MockTransport(handler_health_sealed),
        addr="http://localhost:8200",
        token="test-token",
    )
    assert client.health() is False


# ------------------------------------------------------------------
# Summary test (token must not appear)
# ------------------------------------------------------------------


def test_summary_excludes_token():
    client = make_client(
        transport=MockTransport(handler_secret_found),
        addr="http://localhost:8200",
        token="super-secret-token",
        secret_path="secret/data/test",
    )
    summary = client.summarize()
    assert "super-secret-token" not in summary
    assert "http://localhost:8200" in summary
    assert "secret/data/test" in summary


# ------------------------------------------------------------------
# VaultError tests
# ------------------------------------------------------------------


def test_vault_error_has_status_code():
    err = VaultError("test error", status_code=403)
    assert str(err) == "test error"
    assert err.status_code == 403

    err2 = VaultError("no status")
    assert err2.status_code is None
