import secrets
import unittest

from testutil import C  # noqa: F401  (добавляет путь к модулям проекта)
import wallet

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class RecoveryCode(unittest.TestCase):
    def test_roundtrip_and_formatting(self):
        seed = secrets.token_bytes(32)
        code = wallet.recovery_code(seed)
        self.assertEqual(wallet.parse_recovery_code(code), seed)
        self.assertEqual(wallet.parse_recovery_code(code.lower()), seed)
        self.assertEqual(wallet.parse_recovery_code(code.replace("-", " ") + "\n"), seed)

    def test_every_single_character_typo_is_detected(self):
        seed = secrets.token_bytes(32)
        chars = [c for c in wallet.recovery_code(seed) if c != "-"]
        for i, original in enumerate(chars):
            for ch in ALPHA:
                if ch == original:
                    continue
                mutated = chars[:]
                mutated[i] = ch
                with self.assertRaises(ValueError, msg="позиция %d: %s -> %s" % (i, original, ch)):
                    wallet.parse_recovery_code("".join(mutated))

    def test_truncated_and_extended_rejected(self):
        code = wallet.recovery_code(secrets.token_bytes(32))
        for bad in (code[:-1], code + "A", code[2:], "", "ABCD", "0189-0189"):
            with self.assertRaises(ValueError):
                wallet.parse_recovery_code(bad)

    def test_wallet_matches_seed(self):
        seed = (12345).to_bytes(32, "big")
        w = wallet.wallet_from_seed(seed)
        self.assertEqual(w["address"], C.address_from_pub(C.pubkey_from_priv(12345)))
        self.assertTrue(C.is_valid_address(w["address"]))


class Encryption(unittest.TestCase):
    def test_roundtrip_wrong_password_and_tamper(self):
        seed = secrets.token_bytes(32)
        enc = wallet.encrypt_seed(seed, "correct horse battery", n=2 ** 10)
        self.assertEqual(wallet.decrypt_seed(enc, "correct horse battery"), seed)
        with self.assertRaises(ValueError):
            wallet.decrypt_seed(enc, "wrong password!!")
        bad = dict(enc, ct=("00" if enc["ct"][:2] != "00" else "01") + enc["ct"][2:])
        with self.assertRaises(ValueError):
            wallet.decrypt_seed(bad, "correct horse battery")
        self.assertNotIn(seed.hex(), str(enc))


if __name__ == "__main__":
    unittest.main(verbosity=2)
