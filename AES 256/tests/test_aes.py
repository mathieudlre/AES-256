"""
tests/test_aes.py
Suite de tests unitaires pour le projet AES-256.

Structure attendue :
    src/
        aes.py
        key_expansion.py
        sbox.py
        utils.py
    tests/
        test_aes.py   <- ce fichier

Lancer depuis la racine du projet (le dossier qui contient src/ et tests/) :
    python3 -m unittest tests/test_aes.py -v
ou, depuis le dossier tests/ :
    python3 test_aes.py
"""

import os
import sys
import unittest

# Ajoute le dossier src/ au chemin de recherche des imports Python,
# puisque test_aes.py est dans tests/ et non a cote de aes.py.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from utils import bytes_to_matrix, matrix_to_bytes, xor_bytes, xtime, galois_multiply, pad, unpad
from sbox import sub_byte, inv_sub_byte, sub_bytes, inv_sub_bytes
from key_expansion import key_expansion
from aes import (
    shift_rows, inv_shift_rows,
    mix_columns, inv_mix_columns,
    add_round_key,
    encrypt_block, decrypt_block,
    encrypt, decrypt,
)


# ============================================================
# utils.py
# ============================================================

class TestUtils(unittest.TestCase):

    def test_bytes_to_matrix_roundtrip(self):
        """matrix_to_bytes(bytes_to_matrix(x)) doit redonner x."""
        data = bytes(range(16))
        self.assertEqual(matrix_to_bytes(bytes_to_matrix(data)), data)

    def test_bytes_to_matrix_remplissage_colonnes(self):
        """Vérifie que le remplissage se fait bien par colonnes, pas par lignes."""
        data = bytes(range(16))
        matrix = bytes_to_matrix(data)
        self.assertEqual([matrix[r][0] for r in range(4)], [0, 1, 2, 3])

    def test_xor_bytes(self):
        a = bytes([0x01, 0xFF, 0x10])
        b = bytes([0x0F, 0x0F, 0x10])
        self.assertEqual(xor_bytes(a, b), bytes([0x0E, 0xF0, 0x00]))

    def test_xor_bytes_est_sa_propre_inverse(self):
        a = bytes([0x12, 0x34, 0x56])
        b = bytes([0x78, 0x9A, 0xBC])
        c = xor_bytes(a, b)
        self.assertEqual(xor_bytes(c, b), a)

    def test_xtime_valeurs_connues(self):
        self.assertEqual(xtime(0x00), 0x00)
        self.assertEqual(xtime(0x02), 0x04)
        self.assertEqual(xtime(0x80), 0x1B)   # cas avec débordement
        self.assertEqual(xtime(0x57), 0xAE)   # valeur de référence FIPS-197

    def test_galois_multiply_valeur_officielle(self):
        """Exemple officiel FIPS-197 : 0x57 * 0x83 = 0xC1 dans GF(2^8)."""
        self.assertEqual(galois_multiply(0x57, 0x83), 0xC1)

    def test_galois_multiply_par_un(self):
        for v in [0x00, 0x01, 0x57, 0xFF]:
            self.assertEqual(galois_multiply(v, 1), v)

    def test_pad_ajoute_bien_un_multiple_de_16(self):
        for taille in [0, 1, 15, 16, 17, 33]:
            data = bytes(taille)
            padded = pad(data)
            self.assertEqual(len(padded) % 16, 0)

    def test_pad_unpad_roundtrip(self):
        for taille in [0, 1, 15, 16, 17, 100]:
            data = bytes(range(256))[:taille]
            self.assertEqual(unpad(pad(data)), data)

    def test_unpad_rejette_padding_invalide(self):
        data_corrompue = b"1234567890123456"  # dernier octet = 0x36, > 16 -> invalide
        with self.assertRaises(ValueError):
            unpad(data_corrompue)


# ============================================================
# sbox.py
# ============================================================

class TestSbox(unittest.TestCase):

    def test_sub_byte_valeurs_connues(self):
        self.assertEqual(sub_byte(0x00), 0x63)
        self.assertEqual(sub_byte(0x01), 0x7C)

    def test_sub_byte_inv_sub_byte_reversible(self):
        for b in range(256):
            self.assertEqual(inv_sub_byte(sub_byte(b)), b)

    def test_sub_bytes_inv_sub_bytes_reversible(self):
        state = bytes_to_matrix(bytes(range(16)))
        original = [row[:] for row in state]
        state = sub_bytes(state)
        state = inv_sub_bytes(state)
        self.assertEqual(state, original)


# ============================================================
# aes.py — transformations de tour
# ============================================================

class TestTransformations(unittest.TestCase):

    def test_shift_rows_inv_shift_rows_reversible(self):
        state = bytes_to_matrix(bytes(range(16)))
        original = [row[:] for row in state]
        state = shift_rows(state)
        state = inv_shift_rows(state)
        self.assertEqual(state, original)

    def test_mix_columns_inv_mix_columns_reversible(self):
        state = bytes_to_matrix(bytes(range(16)))
        original = [row[:] for row in state]
        state = mix_columns(state)
        state = inv_mix_columns(state)
        self.assertEqual(state, original)

    def test_add_round_key_est_sa_propre_inverse(self):
        state = bytes_to_matrix(bytes(range(16)))
        original = [row[:] for row in state]
        cle = bytes_to_matrix(bytes(range(16, 32)))
        state = add_round_key(state, cle)
        state = add_round_key(state, cle)
        self.assertEqual(state, original)


# ============================================================
# key_expansion.py
# ============================================================

class TestKeyExpansion(unittest.TestCase):

    def test_nombre_de_round_keys(self):
        """AES-256 doit produire 15 sous-cles (round 0 a 14)."""
        key = bytes(range(32))
        round_keys = key_expansion(key)
        self.assertEqual(len(round_keys), 15)

    def test_round_key_0_egale_la_cle_initiale(self):
        key = bytes(range(32))
        round_keys = key_expansion(key)
        cle_reconstituee = matrix_to_bytes(round_keys[0]) + matrix_to_bytes(round_keys[1])
        self.assertEqual(cle_reconstituee, key)


# ============================================================
# aes.py — chiffrement bloc unique (vecteurs officiels FIPS-197)
# ============================================================

class TestBlocUnique(unittest.TestCase):

    def setUp(self):
        self.key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        self.plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.ciphertext_attendu = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

    def test_encrypt_block_vecteur_officiel(self):
        self.assertEqual(encrypt_block(self.plaintext, self.key), self.ciphertext_attendu)

    def test_decrypt_block_vecteur_officiel(self):
        self.assertEqual(decrypt_block(self.ciphertext_attendu, self.key), self.plaintext)

    def test_encrypt_decrypt_block_roundtrip(self):
        chiffre = encrypt_block(self.plaintext, self.key)
        self.assertEqual(decrypt_block(chiffre, self.key), self.plaintext)


# ============================================================
# aes.py — encrypt / decrypt (mode CBC, message complet)
# ============================================================

class TestChiffrementComplet(unittest.TestCase):

    def setUp(self):
        self.key = bytes(range(32))

    def test_roundtrip_message_court(self):
        message = b"Salut"
        chiffre = encrypt(message, self.key)
        self.assertEqual(decrypt(chiffre, self.key), message)

    def test_roundtrip_message_multiple_de_16(self):
        message = b"A" * 32
        chiffre = encrypt(message, self.key)
        self.assertEqual(decrypt(chiffre, self.key), message)

    def test_roundtrip_message_vide(self):
        message = b""
        chiffre = encrypt(message, self.key)
        self.assertEqual(decrypt(chiffre, self.key), message)

    def test_roundtrip_message_long_multi_blocs(self):
        message = b"Ceci est un message de test assez long pour couvrir plusieurs blocs AES !"
        chiffre = encrypt(message, self.key)
        dechiffre = decrypt(chiffre, self.key)
        self.assertEqual(dechiffre, message)

    def test_deux_chiffrements_du_meme_message_sont_differents(self):
        message = b"Meme message, deux chiffrements"
        chiffre1 = encrypt(message, self.key)
        chiffre2 = encrypt(message, self.key)
        self.assertNotEqual(chiffre1, chiffre2)
        self.assertEqual(decrypt(chiffre1, self.key), message)
        self.assertEqual(decrypt(chiffre2, self.key), message)

    def test_taille_ciphertext_iv_plus_blocs(self):
        message = b"test"
        chiffre = encrypt(message, self.key)
        self.assertEqual((len(chiffre) - 16) % 16, 0)


if __name__ == "__main__":
    unittest.main()
