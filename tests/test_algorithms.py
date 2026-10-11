import unittest

from cbom_scan.algorithms import BROKEN, SAFE, VULNERABLE, WEAKENED, aes, ec, from_name, rsa
from cbom_scan.scanner import parse_cipher_suite, parse_group


def names(s, ctx="algorithm"):
    return [(a.name, a.status) for a in from_name(s, ctx)]


class NameParsing(unittest.TestCase):
    def test_java_transformations(self):
        self.assertEqual(names("AES/GCM/NoPadding"), [("AES-GCM", SAFE)])
        self.assertEqual(names("DESede/CBC/PKCS5Padding"), [("3DES", BROKEN)])
        self.assertEqual(names("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"), [("RSA", VULNERABLE)])  # ECB is meaningless for RSA
        self.assertEqual(names("SHA256withECDSA"), [("ECDSA", VULNERABLE), ("SHA-256", SAFE)])
        self.assertEqual(names("SHA"), [("SHA-1", BROKEN)])

    def test_openssl_and_node_names(self):
        self.assertEqual(names("aes-128-ecb"), [("AES-128-ECB", BROKEN)])
        self.assertEqual(names("aes-256-gcm"), [("AES-256-GCM", SAFE)])
        self.assertEqual(names("aes-128-gcm"), [("AES-128-GCM", WEAKENED)])
        self.assertEqual(names("RSA-SHA1"), [("RSA", VULNERABLE), ("SHA-1", BROKEN)])
        self.assertEqual(names("chacha20-poly1305"), [("ChaCha20-Poly1305", SAFE)])

    def test_jwt(self):
        self.assertEqual(names("RS256", "jwt.encode(x, algorithm='RS256')")[0], ("RSA", VULNERABLE))
        self.assertEqual(names("ES384", "alg")[0], ("ECDSA-P-384", VULNERABLE))
        self.assertEqual(names("none", "alg: none")[0][1], BROKEN)

    def test_pqc(self):
        self.assertEqual(names("ML-KEM-768"), [("ML-KEM-768", SAFE)])
        self.assertEqual(names("Kyber1024"), [("ML-KEM-1024", SAFE)])
        self.assertEqual(names("ML-DSA-65"), [("ML-DSA-65", SAFE)])
        self.assertEqual(names("Dilithium2"), [("ML-DSA-44", SAFE)])
        hybrid = from_name("X25519MLKEM768")[0]
        self.assertTrue(hybrid.hybrid)
        self.assertEqual(hybrid.nist_level, 3)

    def test_strength_rules(self):
        self.assertEqual(rsa(1024).status, BROKEN)
        self.assertEqual(rsa(2048).status, VULNERABLE)
        self.assertEqual(rsa(3072).classical_bits, 128)
        self.assertEqual(ec("ECDSA", "prime192v1").status, BROKEN)
        self.assertEqual(ec("ECDSA", "NID_X9_62_prime256v1").curve, "P-256")
        self.assertEqual(aes(256, "gcm").nist_level, 5)
        self.assertIsNone(aes(None, "gcm").nist_level)

    def test_unknown_is_ignored(self):
        self.assertEqual(from_name("hello"), [])
        self.assertEqual(from_name("RS256", "print('RS256')"), [])  # needs a JWT-ish context


class SuitesAndGroups(unittest.TestCase):
    def test_cipher_suites(self):
        got = [a.name for a in parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")]
        self.assertEqual(got, ["ECDH", "RSA", "AES-128-GCM"])
        self.assertIn("3DES", [a.name for a in parse_cipher_suite("DES-CBC3-SHA")])
        self.assertIn("AES-256-GCM", [a.name for a in parse_cipher_suite("TLS_AES_256_GCM_SHA384")])
        self.assertEqual(parse_cipher_suite("ECDHE-RSA-NULL-SHA")[0].status, BROKEN)

    def test_groups(self):
        self.assertTrue(parse_group("X25519MLKEM768")[0].hybrid)
        self.assertTrue(parse_group("mlkem768x25519-sha256")[0].hybrid)
        self.assertTrue(parse_group("sntrup761x25519-sha512@openssh.com")[0].hybrid)
        self.assertEqual(parse_group("prime256v1")[0].name, "ECDH-P-256")
        self.assertEqual(parse_group("diffie-hellman-group14-sha1")[0].status, BROKEN)
        self.assertEqual(parse_group("!aNULL"), [])


if __name__ == "__main__":
    unittest.main()
