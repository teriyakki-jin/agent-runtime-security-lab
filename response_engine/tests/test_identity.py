from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from response_engine.identity import DelegationError, DelegationVerifier


NOW = datetime(2026, 7, 26, 6, 0, tzinfo=timezone.utc)


def link(
    jti: str,
    subject: str,
    scopes: list[str],
    *,
    parent_jti: str | None = None,
    issued_offset: int = 0,
    expires_offset: int = 300,
    issuer: str = "https://auth.arsl.local",
    audience: str = "http://mcp-server:8000/mcp",
) -> dict[str, object]:
    return {
        "jti": jti,
        "parent_jti": parent_jti,
        "issuer": issuer,
        "subject": subject,
        "audience": audience,
        "scopes": scopes,
        "issued_at": (NOW + timedelta(seconds=issued_offset)).isoformat(),
        "expires_at": (NOW + timedelta(seconds=expires_offset)).isoformat(),
    }


class DelegationVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = DelegationVerifier(
            trusted_issuer="https://auth.arsl.local",
            audience="http://mcp-server:8000/mcp",
            max_depth=3,
        )

    def test_valid_chain_binds_leaf_agent_and_root_identity(self) -> None:
        identity = self.verifier.verify(
            [
                link("root-jti", "human:analyst", ["mcp:access", "mcp:read_document"]),
                link(
                    "child-jti",
                    "agent:researcher",
                    ["mcp:access", "mcp:read_document"],
                    parent_jti="root-jti",
                    issued_offset=1,
                ),
            ],
            required_scopes={"mcp:read_document"},
            now=NOW + timedelta(seconds=2),
        )

        self.assertEqual(identity.agent_id, "agent:researcher")
        self.assertEqual(identity.root_subject, "human:analyst")
        self.assertEqual(identity.token_jti, "child-jti")
        self.assertEqual(identity.delegation_depth, 1)

    def test_child_cannot_expand_parent_scope(self) -> None:
        chain = [
            link("root-jti", "human:analyst", ["mcp:access"]),
            link(
                "child-jti",
                "agent:researcher",
                ["mcp:access", "mcp:run_command"],
                parent_jti="root-jti",
            ),
        ]
        with self.assertRaisesRegex(DelegationError, "scope escalation"):
            self.verifier.verify(chain, required_scopes=set(), now=NOW)

    def test_parent_link_must_be_contiguous(self) -> None:
        chain = [
            link("root-jti", "human:analyst", ["mcp:access"]),
            link("child-jti", "agent:a", ["mcp:access"], parent_jti="unknown"),
        ]
        with self.assertRaisesRegex(DelegationError, "parent"):
            self.verifier.verify(chain, required_scopes=set(), now=NOW)

    def test_duplicate_jti_is_rejected(self) -> None:
        chain = [
            link("same-jti", "human:analyst", ["mcp:access"]),
            link("same-jti", "agent:a", ["mcp:access"], parent_jti="same-jti"),
        ]
        with self.assertRaisesRegex(DelegationError, "unique"):
            self.verifier.verify(chain, required_scopes=set(), now=NOW)

    def test_expired_link_fails_closed(self) -> None:
        with self.assertRaisesRegex(DelegationError, "expired"):
            self.verifier.verify(
                [link("root-jti", "agent:a", ["mcp:access"], expires_offset=-1)],
                required_scopes={"mcp:access"},
                now=NOW,
            )

    def test_wrong_issuer_or_audience_is_rejected(self) -> None:
        for chain in (
            [link("root-jti", "agent:a", ["mcp:access"], issuer="https://evil.example")],
            [link("root-jti", "agent:a", ["mcp:access"], audience="https://evil.example")],
        ):
            with self.subTest(chain=chain):
                with self.assertRaises(DelegationError):
                    self.verifier.verify(chain, required_scopes=set(), now=NOW)

    def test_depth_and_required_scope_are_enforced(self) -> None:
        too_deep = [link("0", "human:a", ["mcp:access"])]
        for index in range(1, 5):
            too_deep.append(
                link(str(index), f"agent:{index}", ["mcp:access"], parent_jti=str(index - 1))
            )
        with self.assertRaisesRegex(DelegationError, "depth"):
            self.verifier.verify(too_deep, required_scopes=set(), now=NOW)

        with self.assertRaisesRegex(DelegationError, "required scope"):
            self.verifier.verify(
                [link("root-jti", "agent:a", ["mcp:access"])],
                required_scopes={"mcp:read_document"},
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
