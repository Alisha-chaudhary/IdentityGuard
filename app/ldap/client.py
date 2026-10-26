"""Read-only LDAP client for IdentityGuard directory discovery.

Connects to a configured LDAP server, binds with read-only credentials,
and performs bounded searches for users and groups. All operations are
read-only: this module never creates, modifies, or deletes directory
entries, never changes passwords, and never modifies groups.

Configuration is read from environment variables:

    IDENTITYGUARD_LDAP_URI          ldap://localhost:389
    IDENTITYGUARD_LDAP_BIND_DN      (empty = anonymous bind)
    IDENTITYGUARD_LDAP_BIND_PASSWORD (empty = no password)
    IDENTITYGUARD_LDAP_BASE_DN      dc=example,dc=test
    IDENTITYGUARD_LDAP_USER_FILTER  (objectClass=inetOrgPerson)
    IDENTITYGUARD_LDAP_GROUP_FILTER (objectClass=posixGroup)
    IDENTITYGUARD_LDAP_TIMEOUT      10   (seconds, for connect and operations)

Bind secrets are never logged and never returned in search results.
"""

from __future__ import annotations

import os
from typing import Optional

from ldap3 import Server, Connection, SUBTREE
from ldap3.core.exceptions import (
    LDAPException,
    LDAPBindError,
    LDAPSocketOpenError,
    LDAPOperationResult,
)
from ldap3.core.results import RESULT_SUCCESS

from app.ldap.models import DirectoryGroup, DirectorySearchResult, DirectoryUser

# Attributes retrieved for user entries. Intentionally excludes userPassword
# and any other secret-bearing attributes.
USER_ATTRIBUTES = [
    "entryUUID",
    "uid",
    "cn",
    "mail",
    "objectClass",
]

# Attributes retrieved for group entries.
GROUP_ATTRIBUTES = [
    "entryUUID",
    "cn",
    "memberUid",
    "objectClass",
]


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


class LdapClient:
    """A read-only LDAP client.

    Example::

        client = LdapClient.from_env()
        try:
            result = client.search_all()
            for user in result.users:
                print(user.uid, user.entry_uuid)
        finally:
            client.close()
    """

    def __init__(
        self,
        uri: str = "ldap://localhost:389",
        bind_dn: str = "",
        bind_password: str = "",
        base_dn: str = "",
        user_filter: str = "(objectClass=inetOrgPerson)",
        group_filter: str = "(objectClass=posixGroup)",
        timeout: int = 10,
    ) -> None:
        self.uri = uri
        self.bind_dn = bind_dn
        self._bind_password = bind_password
        self.base_dn = base_dn
        self.user_filter = user_filter
        self.group_filter = group_filter
        self.timeout = timeout

        self._server: Optional[Server] = None
        self._conn: Optional[Connection] = None
        self._bound = False

    @classmethod
    def from_env(cls) -> "LdapClient":
        """Build a client from environment variables."""
        return cls(
            uri=_env("IDENTITYGUARD_LDAP_URI", "ldap://localhost:389"),
            bind_dn=_env("IDENTITYGUARD_LDAP_BIND_DN", ""),
            bind_password=_env("IDENTITYGUARD_LDAP_BIND_PASSWORD", ""),
            base_dn=_env("IDENTITYGUARD_LDAP_BASE_DN", ""),
            user_filter=_env(
                "IDENTITYGUARD_LDAP_USER_FILTER", "(objectClass=inetOrgPerson)"
            ),
            group_filter=_env(
                "IDENTITYGUARD_LDAP_GROUP_FILTER", "(objectClass=posixGroup)"
            ),
            timeout=_env_int("IDENTITYGUARD_LDAP_TIMEOUT", 10),
        )

    def _log_safe(self, message: str) -> None:
        """Log a message that never contains secrets.

        The bind password is intentionally excluded from all log output.
        """
        import logging

        logging.getLogger("identityguard.ldap").info(message)

    def open(self) -> None:
        """Open a connection to the LDAP server.

        Raises:
            LDAPSocketOpenError: if the server cannot be reached.
            LDAPException: for other connection errors.
        """
        self._server = Server(self.uri, connect_timeout=self.timeout)
        self._conn = Connection(
            self._server,
            user=self.bind_dn or None,
            password=self._bind_password or None,
            auto_bind=False,
            receive_timeout=self.timeout,
        )
        try:
            self._conn.open()
        except LDAPSocketOpenError:
            self._log_safe(f"LDAP server unreachable: {self.uri}")
            raise
        except LDAPException as exc:  # pragma: no cover - network errors
            self._log_safe(f"LDAP connection error: {type(exc).__name__}")
            raise

    def bind(self) -> None:
        """Bind to the LDAP server.

        Uses simple authentication when bind_dn is configured; otherwise
        performs an anonymous bind. Raises LDAPBindError on failure.
        """
        if self._conn is None:
            raise LDAPException("Connection not opened. Call open() first.")
        try:
            self._conn.bind()
        except LDAPBindError:
            self._log_safe("LDAP bind failed: invalid credentials")
            raise
        self._bound = True

    def close(self) -> None:
        """Close the LDAP connection, if open."""
        if self._conn is not None:
            try:
                self._conn.unbind()
            except Exception:  # pragma: no cover - best effort cleanup
                pass
            self._conn = None
        self._bound = False

    def _search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str],
    ) -> list[dict]:
        """Perform a raw LDAP search and return entry attribute dicts.

        Raises LDAPException on connection or operation failure.
        """
        if self._conn is None:
            raise LDAPException("Connection not opened. Call open() first.")

        self._conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
        )

        if self._conn.result.get("result") != RESULT_SUCCESS:
            raise LDAPOperationResult(
                f"LDAP search failed: {self._conn.result.get('description', 'unknown error')}"
            )

        entries: list[dict] = []
        for entry in self._conn.entries:
            entry_dict: dict[str, list[str] | str] = {}

            # ldap3 Entry objects are not dictionaries and do not support
            # .get(). Convert the entry's attributes to a dictionary first.
            attributes_dict = entry.entry_attributes_as_dict

            for attr in attributes:
                values = attributes_dict.get(attr)
                if values is not None:
                    # ldap3 commonly returns attribute values as lists.
                    if isinstance(values, list):
                        entry_dict[attr] = [str(value) for value in values]
                    else:
                        entry_dict[attr] = str(values)

            entry_dict["dn"] = str(entry.entry_dn)
            entries.append(entry_dict)

        return entries

    def search_users(self, base_dn: Optional[str] = None) -> list[DirectoryUser]:
        """Search for directory users and return normalized records."""
        base = base_dn or self.base_dn
        raw_entries = self._search(base, self.user_filter, USER_ATTRIBUTES)

        users: list[DirectoryUser] = []
        for raw in raw_entries:
            entry_uuid = _first_value(raw.get("entryUUID"))
            uid = _first_value(raw.get("uid"))
            if not entry_uuid or not uid:
                # Skip entries without the attributes we need for matching.
                continue
            users.append(
                DirectoryUser(
                    uid=uid,
                    entry_uuid=entry_uuid,
                    dn=str(raw.get("dn", "")),
                    cn=_first_value(raw.get("cn")),
                    mail=_first_value(raw.get("mail")),
                    account_status=None,  # LDAP has no standard disabled flag
                    raw_attributes=raw,
                )
            )
        return users

    def search_groups(self, base_dn: Optional[str] = None) -> list[DirectoryGroup]:
        """Search for directory groups and return normalized records."""
        base = base_dn or self.base_dn
        raw_entries = self._search(base, self.group_filter, GROUP_ATTRIBUTES)

        groups: list[DirectoryGroup] = []
        for raw in raw_entries:
            entry_uuid = _first_value(raw.get("entryUUID"))
            cn = _first_value(raw.get("cn"))
            if not entry_uuid or not cn:
                continue
            member_uids = raw.get("memberUid", [])
            if isinstance(member_uids, str):
                member_uids = [member_uids]
            groups.append(
                DirectoryGroup(
                    cn=cn,
                    entry_uuid=entry_uuid,
                    dn=str(raw.get("dn", "")),
                    member_uids=list(member_uids),
                    raw_attributes=raw,
                )
            )
        return groups

    def search_all(self) -> DirectorySearchResult:
        """Search for both users and groups.

        Returns a DirectorySearchResult. If one search fails, the other
        may still contain results; `error` describes the failure.
        """
        result = DirectorySearchResult()

        try:
            result.users = self.search_users()
        except LDAPException as exc:
            result.error = f"user search failed: {type(exc).__name__}"
            result.complete = False

        try:
            result.groups = self.search_groups()
        except LDAPException as exc:
            if result.error:
                result.error += f"; group search failed: {type(exc).__name__}"
            else:
                result.error = f"group search failed: {type(exc).__name__}"
            result.complete = False

        return result

    def summarize(self) -> str:
        """Return a safe, human-readable summary of the directory.

        Intended for operator review. Never includes passwords or bind
        secrets.
        """
        lines = [
            f"LDAP server: {self.uri}",
            f"Bind DN: {self.bind_dn or '(anonymous)'}",
            f"Base DN: {self.base_dn}",
            f"User filter: {self.user_filter}",
            f"Group filter: {self.group_filter}",
        ]
        return "\n".join(lines)

    def __enter__(self) -> "LdapClient":
        self.open()
        self.bind()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def _first_value(value: object) -> Optional[str]:
    """Extract the first string value from an ldap3 attribute value."""
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        return str(value[0])
    return str(value)
