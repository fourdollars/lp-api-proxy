import unittest

import main


class OidcSurfaceTest(unittest.TestCase):
    def test_removed_endpoints_are_not_exposed(self):
        paths = {r.path for r in main.app.routes if hasattr(r, "path")}
        self.assertNotIn("/oauth2/authorize", paths)
        self.assertNotIn("/oauth2/.well-known/configuration", paths)
        self.assertNotIn("/oauth2/launchpad/login", paths)
        self.assertNotIn("/oauth2/launchpad/callback", paths)
        self.assertNotIn("/oauth2/launchpad/token", paths)
        self.assertNotIn("/oauth2/launchpad/userinfo", paths)
        self.assertNotIn("/oauth2/launchpad/jwks", paths)

    def test_launchpad_oidc_provider_endpoints_use_oauth2_prefix(self):
        paths = {r.path for r in main.app.routes if hasattr(r, "path")}
        self.assertIn("/.well-known/openid-configuration", paths)
        self.assertIn("/oauth2/login", paths)
        self.assertIn("/oauth2/callback", paths)
        self.assertIn("/oauth2/token", paths)
        self.assertIn("/oauth2/userinfo", paths)
        self.assertIn("/oauth2/jwks", paths)


if __name__ == "__main__":
    unittest.main()
