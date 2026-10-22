"""Tests for cryptographic primitives (Ed25519, X25519, HKDF, AEAD)."""

import os
import unittest

from usmd.security.crypto import AeadCipher, Ed25519Pair, HkdfDeriver, X25519Pair


class TestEd25519Pair(unittest.TestCase):

    def test_generate_key_lengths(self):
        priv, pub = Ed25519Pair.generate()
        self.assertEqual(len(priv), 32)
        self.assertEqual(len(pub), 32)

    def test_sign_returns_64_bytes(self):
        priv, _ = Ed25519Pair.generate()
        sig = Ed25519Pair.sign(priv, b"hello")
        self.assertEqual(len(sig), 64)

    def test_verify_valid_signature(self):
        priv, pub = Ed25519Pair.generate()
        sig = Ed25519Pair.sign(priv, b"test data")
        result = Ed25519Pair.verify(pub, b"test data", sig)
        self.assertTrue(result.is_ok())

    def test_verify_tampered_data_fails(self):
        priv, pub = Ed25519Pair.generate()
        sig = Ed25519Pair.sign(priv, b"original")
        result = Ed25519Pair.verify(pub, b"tampered", sig)
        self.assertTrue(result.is_err())

    def test_verify_wrong_key_fails(self):
        priv, _ = Ed25519Pair.generate()
        _, other_pub = Ed25519Pair.generate()
        sig = Ed25519Pair.sign(priv, b"data")
        result = Ed25519Pair.verify(other_pub, b"data", sig)
        self.assertTrue(result.is_err())

    def test_different_keys_generated_each_time(self):
        _, pub1 = Ed25519Pair.generate()
        _, pub2 = Ed25519Pair.generate()
        self.assertNotEqual(pub1, pub2)


class TestX25519Pair(unittest.TestCase):

    def test_generate_key_lengths(self):
        priv, pub = X25519Pair.generate()
        self.assertEqual(len(priv), 32)
        self.assertEqual(len(pub), 32)

    def test_shared_secret_is_symmetric(self):
        a_priv, a_pub = X25519Pair.generate()
        b_priv, b_pub = X25519Pair.generate()
        shared_a = X25519Pair.exchange(a_priv, b_pub)
        shared_b = X25519Pair.exchange(b_priv, a_pub)
        self.assertEqual(shared_a, shared_b)

    def test_shared_secret_is_32_bytes(self):
        a_priv, a_pub = X25519Pair.generate()
        b_priv, b_pub = X25519Pair.generate()
        shared = X25519Pair.exchange(a_priv, b_pub)
        self.assertEqual(len(shared), 32)

    def test_different_pairs_different_secrets(self):
        a_priv, a_pub = X25519Pair.generate()
        b_priv, b_pub = X25519Pair.generate()
        c_priv, c_pub = X25519Pair.generate()
        shared_ab = X25519Pair.exchange(a_priv, b_pub)
        shared_ac = X25519Pair.exchange(a_priv, c_pub)
        self.assertNotEqual(shared_ab, shared_ac)


class TestHkdfDeriver(unittest.TestCase):

    def test_derive_returns_correct_length(self):
        secret = os.urandom(32)
        key = HkdfDeriver.derive(secret, length=32)
        self.assertEqual(len(key), 32)

    def test_derive_16_bytes(self):
        secret = os.urandom(32)
        key = HkdfDeriver.derive(secret, length=16)
        self.assertEqual(len(key), 16)

    def test_derive_deterministic_with_same_input(self):
        secret = b"\x42" * 32
        key1 = HkdfDeriver.derive(secret, length=32, info=b"test")
        key2 = HkdfDeriver.derive(secret, length=32, info=b"test")
        self.assertEqual(key1, key2)

    def test_derive_different_info_different_output(self):
        secret = b"\x42" * 32
        key1 = HkdfDeriver.derive(secret, length=32, info=b"context-a")
        key2 = HkdfDeriver.derive(secret, length=32, info=b"context-b")
        self.assertNotEqual(key1, key2)

    def test_derive_from_x25519_shared_secret(self):
        a_priv, a_pub = X25519Pair.generate()
        b_priv, b_pub = X25519Pair.generate()
        shared = X25519Pair.exchange(a_priv, b_pub)
        key = HkdfDeriver.derive(shared)
        self.assertEqual(len(key), 32)


class TestAeadCipher(unittest.TestCase):

    def setUp(self):
        self.key = os.urandom(32)
        self.cipher = AeadCipher(self.key)

    def test_invalid_key_length_raises(self):
        with self.assertRaises(ValueError):
            AeadCipher(b"short")

    def test_generate_nonce_length(self):
        nonce = AeadCipher.generate_nonce()
        self.assertEqual(len(nonce), 12)

    def test_generate_nonce_random(self):
        n1 = AeadCipher.generate_nonce()
        n2 = AeadCipher.generate_nonce()
        self.assertNotEqual(n1, n2)

    def test_encrypt_decrypt_roundtrip(self):
        nonce = AeadCipher.generate_nonce()
        plaintext = b"secret message"
        ciphertext = self.cipher.encrypt(nonce, plaintext)
        result = self.cipher.decrypt(nonce, ciphertext)
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), plaintext)

    def test_encrypt_with_aad(self):
        nonce = AeadCipher.generate_nonce()
        ct = self.cipher.encrypt(nonce, b"data", b"extra auth data")
        result = self.cipher.decrypt(nonce, ct, b"extra auth data")
        self.assertTrue(result.is_ok())

    def test_decrypt_wrong_aad_fails(self):
        nonce = AeadCipher.generate_nonce()
        ct = self.cipher.encrypt(nonce, b"data", b"aad-original")
        result = self.cipher.decrypt(nonce, ct, b"aad-wrong")
        self.assertTrue(result.is_err())

    def test_decrypt_tampered_ciphertext_fails(self):
        nonce = AeadCipher.generate_nonce()
        ct = bytearray(self.cipher.encrypt(nonce, b"hello"))
        ct[0] ^= 0xFF  # flip a bit
        result = self.cipher.decrypt(nonce, bytes(ct))
        self.assertTrue(result.is_err())

    def test_ciphertext_longer_than_plaintext(self):
        nonce = AeadCipher.generate_nonce()
        pt = b"hello world"
        ct = self.cipher.encrypt(nonce, pt)
        # ChaCha20-Poly1305 adds a 16-byte tag
        self.assertEqual(len(ct), len(pt) + 16)


if __name__ == "__main__":
    unittest.main()
