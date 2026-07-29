from pathlib import Path
import importlib
import os
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class LpOauthConsumerKeyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["PROXY_JWT_SECRET"] = "0123456789abcdef0123456789abcdef"
        os.environ["PROXY_JWT_ENCRYPTION_KEY"] = "uqrbQQAj_ErcRA_DJ0JQcNoeFI-NSBU1MCk9cLI0BZM="
        import main as main_module

        cls.main = importlib.reload(main_module)

    def test_userinfo_exposes_lp_oauth_consumer_key(self):
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
                "lp_cred": "dummy",
                "lp_oauth_consumer_key": "concourse-ci (http://localhost:8080)",
            },
            600,
        )
        userinfo = self.main.oauth2_launchpad_userinfo(f"Bearer {token}")
        self.assertEqual(
            "concourse-ci (http://localhost:8080)",
            userinfo["lp_oauth_consumer_key"],
        )

    def test_id_token_does_not_expose_lp_oauth_consumer_key(self):
        code = self.main._sign_jwt(
            {
                "typ": "lp-code",
                "aud": self.main.PROXY_JWT_AUDIENCE,
                "sub": "alice",
                "username": "alice",
                "user_id": "alice",
                "name": "Alice",
                "profile": "https://launchpad.net/~alice",
                "groups": [],
                "groups_full": [],
                "lp_oauth_consumer_key": "concourse-ci (http://localhost:8080)",
                "client_id": "concourse-ci",
                "redirect_uri": "http://localhost:8080/example.html",
                "lp_cred": "dummy",
                "user": {
                    "sub": "alice",
                    "username": "alice",
                    "user_id": "alice",
                    "name": "Alice",
                    "profile": "https://launchpad.net/~alice",
                    "groups": [],
                    "groups_full": [],
                },
            },
            600,
        )
        result = self.main.oauth2_launchpad_token(
            grant_type="authorization_code",
            code=code,
            redirect_uri="http://localhost:8080/example.html",
            client_id="concourse-ci",
            client_secret=None,
            code_verifier="verifier",
        )
        id_claims = self.main.jwt.decode(
            result["id_token"],
            self.main._get_rsa_private_key()[0].public_key(),
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        self.assertNotIn("lp_oauth_consumer_key", id_claims)

    def test_example_html_fetches_userinfo(self):
        html = (REPO_ROOT / "static" / "example.html").read_text()
        self.assertIn('/oauth2/userinfo', html)
        self.assertIn('lp-userinfo', html)


if __name__ == "__main__":
    unittest.main()
