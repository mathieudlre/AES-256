"""
key_expansion.py
Cadencement de clé (key schedule) : étend la clé maître de 256 bits
en 15 sous-clés de tour (round keys), utilisées par add_round_key.
"""

from utils import xtime
from sbox import sub_byte


def rot_word(word):
    """Décale cycliquement un mot de 4 octets d'une position vers la gauche."""
    return word[1:] + word[:1]


def sub_word(word):
    """Applique la S-Box à chacun des 4 octets du mot."""
    return [sub_byte(b) for b in word]


def rcon(index):
    """Renvoie la constante de tour RCON pour l'itération donnée (index >= 1)."""
    rc = 1
    for _ in range(index - 1):
        rc = xtime(rc)
    return [rc, 0x00, 0x00, 0x00]


def key_expansion(key):
    """key : bytes de 32 octets (256 bits). Renvoie 15 round keys (matrices 4x4)."""
    Nk = 8   # mots de 32 bits dans la clé (256/32)
    Nr = 14  # nombre de tours pour AES-256
    Nb = 4   # colonnes de l'état

    # Découpe la clé en Nk mots de 4 octets
    w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            rc = rcon(i // Nk)
            temp = [t ^ r for t, r in zip(temp, rc)]
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)
        w.append([a ^ b for a, b in zip(w[i - Nk], temp)])

    # Regroupe les mots en 15 round keys (matrices 4x4, remplies par colonnes)
    round_keys = []
    for r in range(Nr + 1):
        words = w[r * Nb:(r + 1) * Nb]
        matrix = [[0] * 4 for _ in range(4)]
        for c, word in enumerate(words):
            for row in range(4):
                matrix[row][c] = word[row]
        round_keys.append(matrix)

    return round_keys
