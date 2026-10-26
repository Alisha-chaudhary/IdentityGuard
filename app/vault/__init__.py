"""Vault integration package for IdentityGuard.

Provides a read-only client for synthetic test secrets stored in
HashiCorp Vault, and a workflow service that connects IdentityGuard's
approval workflow with Vault's own policy enforcement.

Vault tokens are never stored in IdentityGuard's database, logs, or
audit reasons.
"""

from app.vault.client import VaultClient, VaultError
from app.vault.integration import VaultAccessError, VaultSecretAccessService

__all__ = ["VaultClient", "VaultError", "VaultAccessError", "VaultSecretAccessService"]
