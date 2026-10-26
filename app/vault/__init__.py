"""Vault integration package for IdentityGuard.

Provides a read-only client for synthetic test secrets stored in
HashiCorp Vault. Vault tokens are never stored in IdentityGuard's
database, logs, or audit reasons.
"""

from app.vault.client import VaultClient, VaultError

__all__ = ["VaultClient", "VaultError"]
