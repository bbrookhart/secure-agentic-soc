"""Who is allowed to answer the approval gate.

The approval gate is the most security-critical control in the system, and
until now the analyst's name was a free-text form field.  That meant two
things, both bad: anyone who could reach the console could approve anything,
and the audit log recorded an unverified claim as though it were a fact.  An
approval trail whose "who" is self-asserted cannot answer the one question an
auditor will ask.

Streamlit has no authentication of its own, and building one here would be
worse than useless -- a hand-rolled login in an analyst console is exactly the
sort of thing that looks like security without being it.  The right shape is
the standard one: front the console with an authenticating reverse proxy
(oauth2-proxy, an identity-aware proxy, an SSO gateway) and have the
application trust only the identity that proxy asserts.

This module is the boundary where that assertion is read, and where the system
fails closed if it is absent.

**Deployment requirement.** The proxy must *strip* the identity header from
inbound client requests before setting its own, and the app must be reachable
only through it. A header this code trusts is a header a client must not be
able to set. The compose file binds the console to loopback for exactly this
reason.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict


class AnalystIdentity(BaseModel):
    """A proxy-verified approver."""

    model_config = ConfigDict(frozen=True)

    username: str
    source: str = "proxy_header"
    email: str = ""

    @property
    def display(self) -> str:
        return f"{self.username} ({self.email})" if self.email else self.username


class UnauthenticatedApproval(PermissionError):
    """Raised when an approval is attempted without a verified identity."""


def resolve_identity(headers: Mapping[str, str] | None) -> AnalystIdentity | None:
    """Read the proxy-asserted identity, or ``None`` if there is not one.

    Header lookup is case-insensitive because proxies and servers disagree
    about casing, and a control that silently fails on a capitalisation
    mismatch is a control that silently does not run.
    """
    from src.config import get_settings

    if not headers:
        return None

    settings = get_settings()
    wanted = settings.approval_identity_header.lower()
    lookup = {str(key).lower(): value for key, value in headers.items()}

    username = (lookup.get(wanted) or "").strip()
    if not username:
        return None

    email = (lookup.get("x-forwarded-email") or "").strip()
    return AnalystIdentity(username=username[:128], email=email[:254])


def require_identity(headers: Mapping[str, str] | None) -> AnalystIdentity:
    """Return the verified approver, or fail closed.

    When ``require_authenticated_approval`` is disabled -- local development,
    the offline demo -- an explicitly-labelled unverified identity is returned
    instead of a silent fallback.  The label then travels into the audit log,
    so a run approved without authentication is visibly marked as such rather
    than looking identical to a properly authenticated one.
    """
    from src.config import get_settings

    identity = resolve_identity(headers)
    if identity is not None:
        return identity

    settings = get_settings()
    if settings.require_authenticated_approval:
        raise UnauthenticatedApproval(
            f"no verified analyst identity in header '{settings.approval_identity_header}'. "
            "The approval console must sit behind an authenticating proxy that sets it; "
            "set SOC_REQUIRE_AUTHENTICATED_APPROVAL=false only for local, single-user runs."
        )

    return AnalystIdentity(username="unverified-local-analyst", source="unauthenticated")
