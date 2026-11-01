import ssl
import unittest

from testutil import C  # noqa: F401  (добавляет путь к модулям проекта)
import netutil


class Context(unittest.TestCase):
    def test_verification_is_always_on(self):
        ctx = netutil.make_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)


if __name__ == "__main__":
    unittest.main()
