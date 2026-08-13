import importlib
import os
import unittest


class EmailClaimTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["PROXY_JWT_SECRET"] = "0123456789abcdef0123456789abcdef"
        os.environ["PROXY_JWT_ENCRYPTION_KEY"] = "uqrbQQAj_ErcRA_DJ0JQcNoeFI-NSBU1MCk9cLI0BZM="
        import main as main_module

        cls.main = importlib.reload(main_module)

    def test_extract_preferred_email_from_me_payload(self):
        email = self.main._lp_extract_preferred_email(
            {
                "preferred_email_address_link": (
                    "https://api.launchpad.net/devel/~alice/+email/"
                    "alice%40example.com"
                )
            }
        )
        self.assertEqual("alice@example.com", email)

    def test_extract_preferred_email_missing_link_returns_none(self):
        self.assertIsNone(self.main._lp_extract_preferred_email({}))

    def test_extract_preferred_email_rejects_malformed_value(self):
        # No "@" in the trailing segment -> not a real email, ignore it.
        email = self.main._lp_extract_preferred_email(
            {
                "preferred_email_address_link": (
                    "https://api.launchpad.net/devel/~alice/+email/not-an-email"
                )
            }
        )
        self.assertIsNone(email)

    def test_userinfo_returns_email_claim_when_present(self):
        token = self.main._sign_jwt(
            {
                "typ": "lp-access",
                "aud": self.main.PROXY_JWT_AUDIENCE,
                "sub": "alice",
                "username": "alice",
                "user_id": "alice",
                "name": "Alice",
                "profile": "https://launchpad.net/~alice",
                "groups": [],
                "groups_full": [],
                "email": "alice@example.test",
                "email_verified": True,
                "lp_cred": "dummy",
            },
            600,
        )
        userinfo = self.main.oauth2_launchpad_userinfo(f"Bearer {token}")
        self.assertEqual("alice@example.test", userinfo["email"])
        self.assertTrue(userinfo["email_verified"])

    def test_userinfo_omits_email_claim_when_absent(self):
        token = self.main._sign_jwt(
            {
                "typ": "lp-access",
                "aud": self.main.PROXY_JWT_AUDIENCE,
                "sub": "bob",
                "username": "bob",
                "user_id": "bob",
                "name": "Bob",
                "profile": "https://launchpad.net/~bob",
                "groups": [],
                "groups_full": [],
                "lp_cred": "dummy",
            },
            600,
        )
        userinfo = self.main.oauth2_launchpad_userinfo(f"Bearer {token}")
        self.assertNotIn("email", userinfo)
        self.assertNotIn("email_verified", userinfo)

    def test_discovery_advertises_email_claim_and_scope(self):
        discovery = self.main.oidc_provider_discovery()
        self.assertIn("email", discovery["claims_supported"])
        self.assertIn("email_verified", discovery["claims_supported"])
        self.assertIn("email", discovery["scopes_supported"])


if __name__ == "__main__":
    unittest.main()
