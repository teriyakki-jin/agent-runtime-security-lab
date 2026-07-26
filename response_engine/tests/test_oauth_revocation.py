from __future__ import annotations

import io
import json
import unittest
from urllib.error import URLError

from response_engine.oauth_revocation import OAuthRevocationError, OAuthTokenRevoker


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


class OAuthTokenRevokerTests(unittest.TestCase):
    def test_registered_token_is_revoked_without_exporting_it(self) -> None:
        requests: list[object] = []

        def opener(request: object, timeout: float) -> FakeResponse:
            requests.append(request)
            self.assertEqual(timeout, 5.0)
            return FakeResponse({"revoked": True})

        revoker = OAuthTokenRevoker(
            endpoint="http://127.0.0.1:19000/revoke",
            client_secret="r" * 32,
            opener=opener,
        )
        revoker.register("jti-001", "signed-secret-token")
        revoker.revoke("jti-001")

        self.assertEqual(revoker.revoked_jtis, {"jti-001"})
        self.assertFalse(revoker.has_token("jti-001"))
        self.assertNotIn("signed-secret-token", repr(revoker))
        self.assertEqual(len(requests), 1)

    def test_unknown_jti_and_short_secret_fail_closed(self) -> None:
        with self.assertRaises(OAuthRevocationError):
            OAuthTokenRevoker(
                endpoint="http://127.0.0.1:19000/revoke",
                client_secret="short",
            )

        revoker = OAuthTokenRevoker(
            endpoint="http://127.0.0.1:19000/revoke",
            client_secret="r" * 32,
        )
        with self.assertRaisesRegex(OAuthRevocationError, "not registered"):
            revoker.revoke("unknown")

    def test_failed_revocation_keeps_token_for_retry(self) -> None:
        def opener(request: object, timeout: float) -> io.BytesIO:
            del request, timeout
            raise URLError("unavailable")

        revoker = OAuthTokenRevoker(
            endpoint="http://127.0.0.1:19000/revoke",
            client_secret="r" * 32,
            opener=opener,
        )
        revoker.register("jti-001", "signed-secret-token")

        with self.assertRaises(OAuthRevocationError):
            revoker.revoke("jti-001")
        self.assertTrue(revoker.has_token("jti-001"))


if __name__ == "__main__":
    unittest.main()
