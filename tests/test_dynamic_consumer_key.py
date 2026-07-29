import importlib
import os
import unittest


class DynamicConsumerKeyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["PROXY_JWT_SECRET"] = "0123456789abcdef0123456789abcdef"
        os.environ["PROXY_JWT_ENCRYPTION_KEY"] = "uqrbQQAj_ErcRA_DJ0JQcNoeFI-NSBU1MCk9cLI0BZM="
        os.environ["PROXY_ALLOWED_ORIGINS"] = "http://ci.internal:8080,https://ci.example.com"
        os.environ["LP_CONSUMER_KEY"] = "lp-api-proxy"
        import main as main_module

        cls.main = importlib.reload(main_module)

    def test_dynamic_consumer_key_uses_client_id_and_origin(self):
        key = self.main._dynamic_consumer_key(
            "concourse-ci", "http://ci.internal:8080/cb?x=1"
        )
        self.assertEqual("concourse-ci (http://ci.internal:8080)", key)

    def test_dynamic_consumer_key_falls_back_when_origin_not_allowed(self):
        key = self.main._dynamic_consumer_key(
            "concourse-ci", "http://unknown.example/callback"
        )
        self.assertEqual("lp-api-proxy", key)

    def test_dynamic_consumer_key_defaults_to_lp_consumer_key_base(self):
        key = self.main._dynamic_consumer_key(None, "https://ci.example.com/oauth2/cb")
        self.assertEqual("lp-api-proxy (https://ci.example.com)", key)

    def test_allowed_origins_are_applied_to_cors(self):
        self.assertEqual(
            ["http://ci.internal:8080", "https://ci.example.com"], self.main.origins
        )


if __name__ == "__main__":
    unittest.main()
