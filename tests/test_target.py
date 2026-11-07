import unittest
from backend.app.analyzers.target import ensure_public_host, normalize_url, resolve_public_host


class TargetValidationTests(unittest.TestCase):
    def test_normalizes_scheme_host_and_path(self):
        self.assertEqual(normalize_url("Example.COM"), "https://example.com/")

    def test_rejects_private_addresses(self):
        for host in ("127.0.0.1", "10.1.2.3", "169.254.1.1", "::1"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                ensure_public_host(host)

    def test_public_ip_is_returned_for_pinning(self):
        self.assertEqual(resolve_public_host("1.1.1.1"), ["1.1.1.1"])

    def test_rejects_credentials_in_urls(self):
        with self.assertRaises(ValueError):
            normalize_url("https://user:secret@example.com")


if __name__ == "__main__":
    unittest.main()
