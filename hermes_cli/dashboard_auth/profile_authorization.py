"""Fail-closed profile authorization for verified dashboard sessions."""
from __future__ import annotations

from typing import Optional

from hermes_cli.dashboard_auth.base import Session


# The deployment owns this mapping.  A browser/native client may choose only a
# profile; it never supplies or selects the corresponding Honcho identity.
HONCHO_PROFILE_PEERS = {
    "dev": "owner",
    "marketing": "owner-marketing",
    "business": "owner-business",
    "bjoern-privat": "owner-privat",
}


def _canonical_profile(value: str) -> str:
    """Return Hermes' canonical profile spelling without accepting invalid input."""
    from hermes_cli import profiles

    canonical = profiles.normalize_profile_name(value.strip())
    profiles.validate_profile_name(canonical)
    return canonical


def profile_is_allowed(session: Session, requested: Optional[str]) -> bool:
    """Check a client-requested profile against a verified session assertion.

    Legacy providers return ``None`` and retain their pre-existing routing.
    A self-hosted OIDC session carries a tuple reconstructed from a verified
    ID token; missing or malformed claims become ``()`` and therefore deny all
    explicit profile routing.
    """
    if not requested or requested.strip().lower() == "current":
        return True
    if session.allowed_profiles is None:
        return True
    try:
        return _canonical_profile(requested) in session.allowed_profiles
    except ValueError:
        return False


def honcho_peer_for_profile(profile: str) -> str:
    """Return the deployment-owned peer for a canonical Hermes profile.

    Unknown profiles intentionally have no fallback.  Callers must reject
    them instead of inheriting a root/default Honcho peer.
    """
    return HONCHO_PROFILE_PEERS.get(_canonical_profile(profile), "")


def oidc_identity_mapping_is_mutable(session: Optional[Session]) -> bool:
    """Whether this request may modify a client-independent Honcho identity.

    ``allowed_profiles is None`` identifies legacy providers, whose existing
    operator workflows stay unchanged.  Every self-hosted OIDC session has a
    tuple (including an explicit empty deny-all tuple) and may not overwrite
    workspace, user-peer, AI-peer, or bearer mapping through a dashboard API.
    """
    return session is None or session.allowed_profiles is None
