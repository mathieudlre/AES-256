"""
aes.py
Transformations de tour (ShiftRows, MixColumns, AddRoundKey), assemblage
des tours complets, et fonctions publiques encrypt/decrypt (mode CBC).
"""

import os

from utils import bytes_to_matrix, matrix_to_bytes, xor_bytes, xtime, galois_multiply, pad, unpad
from sbox import sub_bytes, inv_sub_bytes
from key_expansion import key_expansion


def shift_rows(state):
    """Décale cycliquement chaque ligne r de r positions vers la gauche."""
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]
    return state


def inv_shift_rows(state):
    """Inverse de shift_rows : décale chaque ligne r de r positions vers la droite."""
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]
    return state


def mix_single_column(column):
    """Mélange une colonne de 4 octets selon la matrice de mélange AES."""
    a = column[:]
    r = [0, 0, 0, 0]
    r[0] = xtime(a[0]) ^ (xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
    r[1] = a[0] ^ xtime(a[1]) ^ (xtime(a[2]) ^ a[2]) ^ a[3]
    r[2] = a[0] ^ a[1] ^ xtime(a[2]) ^ (xtime(a[3]) ^ a[3])
    r[3] = (xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ xtime(a[3])
    return r


def mix_columns(state):
    """Applique mix_single_column à chacune des 4 colonnes de l'état."""
    for c in range(4):
        column = [state[r][c] for r in range(4)]
        column = mix_single_column(column)
        for r in range(4):
            state[r][c] = column[r]
    return state


def inv_mix_single_column(column):
    """Inverse de mix_single_column (coefficients 9, 11, 13, 14)."""
    a = column[:]
    r = [0, 0, 0, 0]
    r[0] = (galois_multiply(a[0], 14) ^ galois_multiply(a[1], 11) ^
            galois_multiply(a[2], 13) ^ galois_multiply(a[3], 9))
    r[1] = (galois_multiply(a[0], 9) ^ galois_multiply(a[1], 14) ^
            galois_multiply(a[2], 11) ^ galois_multiply(a[3], 13))
    r[2] = (galois_multiply(a[0], 13) ^ galois_multiply(a[1], 9) ^
            galois_multiply(a[2], 14) ^ galois_multiply(a[3], 11))
    r[3] = (galois_multiply(a[0], 11) ^ galois_multiply(a[1], 13) ^
            galois_multiply(a[2], 9) ^ galois_multiply(a[3], 14))
    return r


def inv_mix_columns(state):
    """Applique inv_mix_single_column à chacune des 4 colonnes de l'état."""
    for c in range(4):
        column = [state[r][c] for r in range(4)]
        column = inv_mix_single_column(column)
        for r in range(4):
            state[r][c] = column[r]
    return state


def add_round_key(state, round_key):
    """XOR de l'état avec la sous-clé de tour, case par case."""
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]
    return state


def aes_round(state, round_key):
    """Un tour normal de chiffrement : SubBytes -> ShiftRows -> MixColumns -> AddRoundKey."""
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, round_key)
    return state


def aes_final_round(state, round_key):
    """Le tour final de chiffrement (sans MixColumns)."""
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key)
    return state


def encrypt_block(block, key):
    """block : 16 octets. key : 32 octets (AES-256). Renvoie 16 octets chiffrés."""
    round_keys = key_expansion(key)
    state = bytes_to_matrix(block)

    state = add_round_key(state, round_keys[0])

    for round_num in range(1, 14):          # tours 1 à 13
        state = aes_round(state, round_keys[round_num])

    state = aes_final_round(state, round_keys[14])  # tour 14 (final)

    return matrix_to_bytes(state)


def inv_aes_round(state, round_key):
    """Un tour normal de déchiffrement : InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns."""
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_key)
    state = inv_mix_columns(state)
    return state


def inv_aes_final_round(state, round_key):
    """Le tour final de déchiffrement (sans InvMixColumns)."""
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_key)
    return state


def decrypt_block(block, key):
    """block : 16 octets chiffrés. key : 32 octets. Renvoie 16 octets en clair."""
    round_keys = key_expansion(key)
    state = bytes_to_matrix(block)

    state = add_round_key(state, round_keys[14])

    for round_num in range(13, 0, -1):       # tours 13 à 1, à l'envers
        state = inv_aes_round(state, round_keys[round_num])

    state = inv_aes_final_round(state, round_keys[0])

    return matrix_to_bytes(state)


def encrypt(data, key):
    """
    data : bytes en clair, de longueur quelconque.
    key  : 32 octets (256 bits).
    Renvoie IV (16 octets) + texte chiffré, en mode CBC.
    """
    iv = os.urandom(16)
    data = pad(data)

    ciphertext = b""
    previous_block = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        block = xor_bytes(block, previous_block)   # chaînage CBC
        encrypted_block = encrypt_block(block, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return iv + ciphertext


def decrypt(data, key):
    """
    data : IV (16 octets) + texte chiffré (produit par encrypt()).
    key  : 32 octets (256 bits).
    Renvoie les données en clair (padding retiré).
    """
    iv = data[:16]
    ciphertext = data[16:]

    plaintext = b""
    previous_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted_block = decrypt_block(block, key)
        plaintext += xor_bytes(decrypted_block, previous_block)
        previous_block = block

    return unpad(plaintext)
