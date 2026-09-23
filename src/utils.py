"""
utils.py
Fonctions génériques utilisées dans tout le projet AES-256 :
- conversions octets <-> matrice d'état
- arithmétique du corps de Galois GF(2^8)
- padding PKCS#7
"""


def bytes_to_matrix(data):
    """Transforme 16 octets en matrice d'état 4x4 (remplissage par colonnes)."""
    matrix = [[0] * 4 for _ in range(4)]
    for i in range(16):
        matrix[i % 4][i // 4] = data[i]
    return matrix


def matrix_to_bytes(matrix):
    """Reconstitue les 16 octets à partir de la matrice d'état 4x4."""
    data = bytearray(16)
    for i in range(16):
        data[i] = matrix[i % 4][i // 4]
    return bytes(data)  # bytes plutôt que bytearray : plus facile à comparer/concaténer


def xor_bytes(a, b):
    """XOR octet par octet entre deux séquences d'octets de même taille."""
    return bytes(x ^ y for x, y in zip(a, b))


def xtime(byte):
    """Multiplication par 2 (x) dans GF(2^8)."""
    byte <<= 1
    if byte & 0x100:          # débordement au-delà de 8 bits
        byte ^= 0x11B
    return byte & 0xFF


def galois_multiply(a, b):
    """Multiplication générale a * b dans GF(2^8), construite à partir de xtime."""
    result = 0
    a &= 0xFF
    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result & 0xFF


def pad(data):
    """Ajoute un padding PKCS#7 pour que len(data) soit un multiple de 16."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    """Retire le padding PKCS#7 et valide sa cohérence."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding invalide")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding invalide")
    return data[:-pad_len]
