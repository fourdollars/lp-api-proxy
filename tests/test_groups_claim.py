import importlib
import os
import unittest


class GroupsClaimTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["PROXY_JWT_SECRET"] = "0123456789abcdef0123456789abcdef"
        os.environ["PROXY_JWT_ENCRYPTION_KEY"] = "uqrbQQAj_ErcRA_DJ0JQcNoeFI-NSBU1MCk9cLI0BZM="
        import main as main_module

        cls.main = importlib.reload(main_module)

    def test_userinfo_returns_groups_claim(self):
        token = self.main._sign_jwt(
            {
                "typ": "lp-access",
                "aud": self.main.PROXY_JWT_AUDIENCE,
                "sub": "alice",
                "username": "alice",
                "user_id": "alice",
                "name": "Alice",
                "profile": "https://launchpad.net/~alice",
                "groups": ["my-group"],
                "groups_full": ["https://launchpad.net/~my-group"],
                "lp_cred": "dummy",
            },
            600,
        )
        userinfo = self.main.oauth2_launchpad_userinfo(f"Bearer {token}")
        self.assertEqual("alice", userinfo["username"])
        self.assertEqual("alice", userinfo["user_id"])
        self.assertEqual(["my-group"], userinfo["groups"])
        self.assertEqual(
            ["https://launchpad.net/~my-group"], userinfo["groups_full"]
        )

    def test_discovery_advertises_groups_claim(self):
        discovery = self.main.oidc_provider_discovery()
        self.assertIn("username", discovery["claims_supported"])
        self.assertIn("user_id", discovery["claims_supported"])
        self.assertIn("groups", discovery["claims_supported"])
        self.assertIn("groups_full", discovery["claims_supported"])

    def test_groups_full_uses_single_launchpad_url_spec(self):
        names, urls = self.main._extract_groups_from_membership_entry(
            {
                "name": "my-group",
                "self_link": "https://api.launchpad.net/devel/~my-group",
                "web_link": "https://launchpad.net/~my-group",
                "team_link": "https://api.launchpad.net/devel/~my-group",
            }
        )
        self.assertIn("my-group", names)
        self.assertEqual({"https://launchpad.net/~my-group"}, urls)


if __name__ == "__main__":
    unittest.main()
