"""Fail-closed profile authorization for verified dashboard sessions."""
from __future__ import annotations

from typing import Optional

from hermes_cli.dashboard_auth.base import Session


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
