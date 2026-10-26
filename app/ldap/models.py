"""Normalized LDAP directory structures.

These are plain Python dataclasses that represent directory records in a
technology-neutral form. The LDAP client (client.py) populates them; the
synchronization service (sync.py) compares them against IdentityGuard's
local records.

No passwords or bind secrets are ever stored in these structures.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DirectoryUser:
    """A normalized directory user record.

    Attributes:
        uid: The directory login attribute (e.g. "jane.doe").
        entry_uuid: Immutable directory entry UUID. Used for identity matching.
        dn: Full distinguished name of the directory entry.
        cn: Common name / display name.
        mail: Email address, if present.
        account_status: "active" or "disabled" if the directory exposes this;
            None when the directory does not expose account status.
        member_of: DNs of groups this user is a member of (from memberOf or
            computed from group membership).
        raw_attributes: The raw LDAP attribute map for debugging/audit.
    """

    uid: str
    entry_uuid: str
    dn: str
    cn: Optional[str] = None
    mail: Optional[str] = None
    account_status: Optional[str] = None
    member_of: list[str] = field(default_factory=list)
    raw_attributes: dict = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        """True when the directory account is known to be active.

        Returns False only when account_status is explicitly "disabled".
        Returns True when status is None (unknown) — callers must treat
        unknown status as "not enough information to disable access."
        """
        return self.account_status != "disabled"


@dataclass
class DirectoryGroup:
    """A normalized directory group record."""

    cn: str
    entry_uuid: str
    dn: str
    member_uids: list[str] = field(default_factory=list)
    raw_attributes: dict = field(default_factory=dict)


@dataclass
class DirectorySearchResult:
    """Result of a directory search operation.

    Attributes:
        users: DirectoryUser records returned by the search.
        groups: DirectoryGroup records returned by the search.
        complete: True when the search returned all expected results.
            False when the search was partial or timed out.
        error: Error message if the search failed; None on success.
    """

    users: list[DirectoryUser] = field(default_factory=list)
    groups: list[DirectoryGroup] = field(default_factory=list)
    complete: bool = True
    error: Optional[str] = None

    @property
    def failed(self) -> bool:
        return self.error is not None
