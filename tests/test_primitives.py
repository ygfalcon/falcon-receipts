import os, sys, hashlib, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
import receipt_verify as rv
class T(unittest.TestCase):
    def test_rfc8032(self):
        for pk, m, s in [("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
                         ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")]:
            self.assertTrue(rv.ed25519_verify(bytes.fromhex(pk), bytes.fromhex(m), bytes.fromhex(s)))
            self.assertFalse(rv.ed25519_verify(bytes.fromhex(pk), bytes.fromhex(m) + b"x", bytes.fromhex(s)))
    def test_vs_openssl(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization as S
        except ImportError: self.skipTest("cryptography missing")
        for _ in range(30):
            k = Ed25519PrivateKey.generate(); pub = k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw); m = os.urandom(32); sig = k.sign(m)
            self.assertTrue(rv.ed25519_verify(pub, m, sig))
            b = bytearray(sig); b[os.urandom(1)[0] % 64] ^= 1; self.assertFalse(rv.ed25519_verify(pub, m, bytes(b)))
    def test_vs_solders(self):  # the library the real signer uses
        try: from solders.keypair import Keypair
        except ImportError: self.skipTest("solders missing (run with killer-app .venv python)")
        for _ in range(30):
            kp = Keypair(); m = os.urandom(32); sig = kp.sign_message(m)
            self.assertTrue(rv.ed25519_verify(bytes(kp.pubkey()), m, bytes(sig)))
            self.assertEqual(rv.b58decode(str(kp.pubkey())), bytes(kp.pubkey())); self.assertEqual(rv.b58decode(str(sig)), bytes(sig))
    def test_fuzz_canon_matches_json_dumps(self):
        import json; self.assertEqual(rv.canon({"b": [1, 2.5, "é"], "a": None}), '{"a":null,"b":[1,2.5,"\\u00e9"]}')
if __name__ == "__main__": unittest.main()
