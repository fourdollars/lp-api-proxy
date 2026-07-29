from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class CharmLayoutTest(unittest.TestCase):
    def test_charm_files_exist(self):
        required = [
            "metadata.yaml",
            "config.yaml",
            ".jujuignore",
            "hooks/install",
            "hooks/start",
            "hooks/stop",
            "hooks/config-changed",
            "hooks/upgrade-charm",
            "hooks/common.sh",
        ]
        for rel in required:
            self.assertTrue((REPO_ROOT / rel).exists(), f"Missing {rel}")

    def test_metadata_has_expected_name(self):
        metadata = (REPO_ROOT / "metadata.yaml").read_text()
        self.assertIn("name: lp-api-proxy", metadata)

    def test_config_has_required_oauth_keys(self):
        config = (REPO_ROOT / "config.yaml").read_text()
        self.assertIn("proxy-base-url:", config)
        self.assertIn("proxy-oidc-client-id:", config)
        self.assertIn("proxy-oidc-client-secret:", config)
        self.assertIn("proxy-jwt-secret:", config)
        self.assertIn("proxy-jwt-encryption-key:", config)
        self.assertIn("http-proxy:", config)
        self.assertIn("https-proxy:", config)
        self.assertIn("no-proxy:", config)
        self.assertIn("allowed-origins:", config)

    def test_common_hook_supports_proxy_envs(self):
        common = (REPO_ROOT / "hooks/common.sh").read_text()
        self.assertIn("HTTP_PROXY", common)
        self.assertIn("HTTPS_PROXY", common)
        self.assertIn("NO_PROXY", common)
        self.assertIn("PROXY_ALLOWED_ORIGINS", common)


if __name__ == "__main__":
    unittest.main()
