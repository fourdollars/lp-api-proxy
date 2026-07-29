from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class ExampleHtmlBrowserCompatTest(unittest.TestCase):
    def test_example_has_sha256_fallback_for_non_secure_context(self):
        html = (REPO_ROOT / "static" / "example.html").read_text()
        self.assertIn("sha256Fallback", html)
        self.assertIn("crypto.subtle", html)
        self.assertIn("const bitLenHi = Math.floor(bitLen / 0x100000000);", html)
        self.assertIn("const bitLenLo = bitLen >>> 0;", html)
        self.assertNotIn(
            "for (let i = 7; i >= 0; i--) msg.push((bitLen >>> (i * 8)) & 0xff);",
            html,
        )

    def test_example_handles_non_json_token_errors(self):
        html = (REPO_ROOT / "static" / "example.html").read_text()
        self.assertIn("await r.text()", html)
        self.assertIn("JSON.parse(raw)", html)


if __name__ == "__main__":
    unittest.main()
