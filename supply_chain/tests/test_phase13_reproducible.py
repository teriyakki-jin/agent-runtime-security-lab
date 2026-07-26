import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]


class Phase13ReproducibleBuildTests(unittest.TestCase):
    def test_base_image_and_python_dependencies_are_immutable(self) -> None:
        dockerfile = (ROOT / "mcp-server/Dockerfile").read_text()
        self.assertRegex(
            dockerfile.splitlines()[0],
            r"^FROM python:3\.12-slim@sha256:[a-f0-9]{64}$",
        )
        self.assertIn("--require-hashes", dockerfile)
        self.assertIn("requirements.lock", dockerfile)

        lock = (ROOT / "mcp-server/requirements.lock").read_text()
        requirement_lines = [
            line for line in lock.splitlines()
            if line and not line.startswith(("#", " ", "--"))
        ]
        self.assertGreater(len(requirement_lines), 20)
        self.assertTrue(all("==" in line for line in requirement_lines))
        self.assertGreaterEqual(lock.count("--hash=sha256:"), len(requirement_lines))

    def test_every_github_action_is_pinned_to_a_commit_sha(self) -> None:
        workflows = list((ROOT / ".github/workflows").glob("*.yml"))
        uses = []
        for workflow in workflows:
            uses.extend(
                line.strip().split("uses:", 1)[1].strip()
                for line in workflow.read_text().splitlines()
                if line.strip().startswith("uses:")
            )
        self.assertTrue(uses)
        for reference in uses:
            self.assertRegex(reference, r"^[^@]+@[a-f0-9]{40}(?:\s+#.*)?$")

    def test_keyless_workflow_has_narrow_identity_and_rekor_verification(self) -> None:
        workflow = (ROOT / ".github/workflows/supply-chain.yml").read_text()
        self.assertIn("id-token: write", workflow)
        self.assertIn("packages: write", workflow)
        self.assertIn("--certificate-identity=", workflow)
        self.assertIn("--certificate-oidc-issuer=", workflow)
        self.assertNotIn("--insecure-ignore-tlog", workflow)
        self.assertNotIn("@v", "\n".join(
            line for line in workflow.splitlines() if "uses:" in line
        ))


if __name__ == "__main__":
    unittest.main()
