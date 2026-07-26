import unittest

from supply_chain.probe import build_probe_parameters


class Phase13ProbeTests(unittest.TestCase):
    def test_probe_uses_actual_stdio_mcp_in_a_hardened_container(self) -> None:
        image = "ghcr.io/example/mcp-server@sha256:" + "f" * 64
        parameters = build_probe_parameters(
            image,
            docker="docker",
            environment={
                "PATH": "safe-path",
                "DOCKER_HOST": "tcp://127.0.0.1:2375",
                "GITHUB_TOKEN": "must-not-propagate",
            },
        )
        self.assertEqual(parameters.command, "docker")
        self.assertIn("--network=none", parameters.args)
        self.assertIn("--read-only", parameters.args)
        self.assertIn("--cap-drop=ALL", parameters.args)
        self.assertIn("no-new-privileges", parameters.args)
        self.assertIn("--pids-limit=128", parameters.args)
        self.assertIn("--memory=256m", parameters.args)
        self.assertEqual(
            parameters.args[-4:], [image, "python", "-m", "app.pre_admission"]
        )
        self.assertEqual(parameters.env["DOCKER_HOST"], "tcp://127.0.0.1:2375")
        self.assertNotIn("GITHUB_TOKEN", parameters.env)

    def test_probe_rejects_mutable_image_reference(self) -> None:
        with self.assertRaises(ValueError):
            build_probe_parameters("ghcr.io/example/mcp-server:latest")


if __name__ == "__main__":
    unittest.main()
