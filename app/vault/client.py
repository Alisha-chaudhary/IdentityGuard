"""HashiCorp Vault client for IdentityGuard synthetic secret management.

Provides read-only access to synthetic test secrets stored in Vault.
All configuration is read from environment variables. Vault tokens are
never stored in IdentityGuard's database, logs, or audit reasons.

Configuration (environment variables):

    IDENTITYGUARD_VAULT_ADDR        http://127.0.0.1:8200
    IDENTITYGUARD_VAULT_TOKEN       (vault token, runtime only - never committed)
    IDENTITYGUARD_VAULT_SECRET_PATH identityguard-lab/data/synthetic/test-secret
    IDENTITYGUARD_VAULT_TIMEOUT     10   (seconds)
"""

from __future__ import annotations

import os
from typing import Optional

import httpx


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


class VaultClient:
    """A read-only Vault client for synthetic test secrets.

    Uses Vault's HTTP API with a token-based authentication method.
    The token is never logged and never returned in responses.

    This client only performs secret READ operations. It does not
    write secrets, create policies, or manage tokens.
    """

    def __init__(
        self,
        addr: str = "http://127.0.0.1:8200",
        token: str = "",
        secret_path: str = "",
        timeout: int = 10,
    ) -> None:
        self.addr = addr.rstrip("/")
        self._token = token
        self.secret_path = secret_path
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "VaultClient":
        """Build a client from environment variables."""
        return cls(
            addr=_env("IDENTITYGUARD_VAULT_ADDR", "http://127.0.0.1:8200"),
            token=_env("IDENTITYGUARD_VAULT_TOKEN", ""),
            secret_path=_env(
                "IDENTITYGUARD_VAULT_SECRET_PATH",
                "identityguard-lab/data/synthetic/test-secret",
            ),
            timeout=_env_int("IDENTITYGUARD_VAULT_TIMEOUT", 10),
        )

    def read_secret(self, path: Optional[str] = None) -> dict:
        """Read a secret from Vault's KV v2 secrets engine.

        Returns the secret data dictionary (the "data" field of the
        KV v2 response). Raises VaultError on failure.

        The secret value is returned to the caller but is never logged
        by this client.
        """
        target = path or self.secret_path
        url = f"{self.addr}/v1/{target}"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    url,
                    headers={"X-Vault-Token": self._token},
                )
        except httpx.ConnectError as exc:
            raise VaultError(f"Cannot connect to Vault at {self.addr}") from exc
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

        # KV v2 response structure: { data: { data: { ... }, metadata: ... } }
        inner = payload.get("data", {})
        if isinstance(inner, dict) and "data" in inner:
            return inner["data"]
        return inner

    def health(self) -> bool:
        """Check if Vault is reachable and unsealed.

        Returns True if Vault is healthy, False otherwise.
        Never logs the token.
        """
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    f"{self.addr}/v1/sys/health",
                    headers={"X-Vault-Token": self._token},
                )
            return response.status_code == 200
        except Exception:
            return False

    def summarize(self) -> str:
        """Return a safe, human-readable summary.

        Never includes the Vault token.
        """
        return (
            f"Vault server: {self.addr}\n"
            f"Secret path: {self.secret_path}\n"
            f"Timeout: {self.timeout}s\n"
            f"Token configured: {'yes' if self._token else 'no'}"
        )


class VaultError(Exception):
    """Raised when a Vault operation fails."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
