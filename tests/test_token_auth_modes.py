import base64
import hashlib
import importlib
import os
import unittest


class TokenAuthModesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["PROXY_JWT_SECRET"] = "0123456789abcdef0123456789abcdef"
        os.environ["PROXY_JWT_ENCRYPTION_KEY"] = "uqrbQQAj_ErcRA_DJ0JQcNoeFI-NSBU1MCk9cLI0BZM="
        os.environ["PROXY_OIDC_CLIENT_ID"] = "concourse-ci"
        os.environ["PROXY_OIDC_CLIENT_SECRET"] = "myclientsecret"
        import main as main_module

        cls.main = importlib.reload(main_module)

    def test_token_endpoint_accepts_pkce_without_client_secret(self):
        verifier = "test-verifier-value"
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        code = self.main._sign_jwt(
            {
                "typ": "lp-code",
                "client_id": "concourse-ci",
                "redirect_uri": "http://localhost:3456/example.html",
                "code_challenge": challenge,
                "user": {
                    "sub": "alice",
                    "username": "alice",
                    "user_id": "alice",
                    "name": "Alice",
                    "profile": "https://launchpad.net/~alice",
                    "groups": [],
                    "groups_full": [],
                },
                "lp_cred": "dummy",
            },
            120,
        )

        result = self.main.oauth2_launchpad_token(
            grant_type="authorization_code",
            code=code,
            redirect_uri="http://localhost:3456/example.html",
            client_id="concourse-ci",
            client_secret=None,
            code_verifier=verifier,
        )
        self.assertIn("access_token", result)
        self.assertIn("id_token", result)


if __name__ == "__main__":
    unittest.main()
