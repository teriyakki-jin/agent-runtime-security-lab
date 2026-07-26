from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable


class DelegationError(ValueError):
    """Raised when a delegated identity chain cannot be trusted."""


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    root_subject: str
    token_jti: str
    delegation_depth: int
    scopes: frozenset[str]
    chain_jtis: tuple[str, ...]


@dataclass(frozen=True)
class DelegationLink:
    jti: str
    parent_jti: str | None
    issuer: str
    subject: str
    audience: str
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise DelegationError(f"{field} must be a bounded ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DelegationError(f"{field} is not valid ISO-8601") from exc
    if parsed.tzinfo is None:
        raise DelegationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _bounded_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise DelegationError(f"{field} is required and must be at most 256 characters")
    return value.strip()


def _parse_link(raw: dict[str, object]) -> DelegationLink:
    raw_scopes = raw.get("scopes")
    if not isinstance(raw_scopes, (list, tuple, set)):
        raise DelegationError("scopes must be a list")
    scopes = frozenset(_bounded_text(item, "scope") for item in raw_scopes)
    if not scopes:
        raise DelegationError("delegation scopes cannot be empty")
    parent = raw.get("parent_jti")
    if parent is not None:
        parent = _bounded_text(parent, "parent_jti")
    return DelegationLink(
        jti=_bounded_text(raw.get("jti"), "jti"),
        parent_jti=parent,
        issuer=_bounded_text(raw.get("issuer"), "issuer"),
        subject=_bounded_text(raw.get("subject"), "subject"),
        audience=_bounded_text(raw.get("audience"), "audience"),
        scopes=scopes,
        issued_at=_timestamp(raw.get("issued_at"), "issued_at"),
        expires_at=_timestamp(raw.get("expires_at"), "expires_at"),
    )


class DelegationVerifier:
    """Validate an explicitly linked, scope-narrowing delegated-token chain."""

    def __init__(self, *, trusted_issuer: str, audience: str, max_depth: int = 3) -> None:
        if max_depth < 0 or max_depth > 8:
            raise ValueError("max_depth must be between 0 and 8")
        self.trusted_issuer = trusted_issuer.rstrip("/")
        self.audience = audience
        self.max_depth = max_depth

    def verify(
        self,
        chain: Iterable[dict[str, object]],
        *,
        required_scopes: set[str],
        now: datetime | None = None,
    ) -> AgentIdentity:
        links = [_parse_link(item) for item in chain]
        if not links:
            raise DelegationError("delegation chain cannot be empty")
        if len(links) - 1 > self.max_depth:
            raise DelegationError("delegation depth exceeds policy")
        if len({item.jti for item in links}) != len(links):
            raise DelegationError("delegation jti values must be unique")

        current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        for index, item in enumerate(links):
            if item.issuer.rstrip("/") != self.trusted_issuer:
                raise DelegationError("delegation issuer is not trusted")
            if item.audience != self.audience:
                raise DelegationError("delegation audience does not match the MCP resource")
            if item.issued_at > current_time:
                raise DelegationError("delegation link is not active yet")
            if item.expires_at <= current_time:
                raise DelegationError("delegation link is expired")
            if item.expires_at <= item.issued_at:
                raise DelegationError("delegation expiry must follow issuance")
            if index == 0:
                if item.parent_jti is not None:
                    raise DelegationError("root delegation link cannot have a parent")
                continue

            parent = links[index - 1]
            if item.parent_jti != parent.jti:
                raise DelegationError("delegation parent is not contiguous")
            if item.issued_at < parent.issued_at:
                raise DelegationError("child delegation predates its parent")
            if item.expires_at > parent.expires_at:
                raise DelegationError("child delegation outlives its parent")
            if not item.scopes.issubset(parent.scopes):
                raise DelegationError("delegation scope escalation is not allowed")

        leaf = links[-1]
        if not required_scopes.issubset(leaf.scopes):
            raise DelegationError("leaf token is missing a required scope")
        return AgentIdentity(
            agent_id=leaf.subject,
            root_subject=links[0].subject,
            token_jti=leaf.jti,
            delegation_depth=len(links) - 1,
            scopes=leaf.scopes,
            chain_jtis=tuple(item.jti for item in links),
        )
