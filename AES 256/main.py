"""
main.py
Exemples d'utilisation du projet AES-256 (src/aes.py) :
1. Chiffrer/déchiffrer un texte
2. Chiffrer/déchiffrer un fichier
3. Bonnes pratiques de gestion de la clé

Structure attendue :
    src/
        aes.py, key_expansion.py, sbox.py, utils.py
    main.py   <- ce fichier, à la racine du projet
"""

import os
import sys

# Permet d'importer les modules situés dans src/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from aes import encrypt, decrypt


# ============================================================
# 1. Générer une clé AES-256
# ============================================================
def generer_cle():
    """
    Une clé AES-256 fait EXACTEMENT 32 octets (256 bits).
    os.urandom() est la bonne source : aléatoire cryptographiquement sûr,
    fournie par le système d'exploitation.

    Ne JAMAIS utiliser une clé prévisible : ni un mot de passe tapé
    directement ("motdepasse123"), ni une valeur fixe codée en dur.
    """
    return os.urandom(32)


# ============================================================
# 2. Chiffrer / déchiffrer un texte
# ============================================================
def exemple_texte():
    print("=" * 60)
    print("Exemple 1 : chiffrer un texte")
    print("=" * 60)

    cle = generer_cle()
    print(f"Clé (hex)   : {cle.hex()}")

    message = "Ceci est un message secret !"
    print(f"Message     : {message}")

    # encrypt() attend des bytes, pas une str -> il faut encoder en UTF-8
    message_bytes = message.encode("utf-8")
    chiffre = encrypt(message_bytes, cle)
    print(f"Chiffré (hex): {chiffre.hex()}")

    # decrypt() renvoie des bytes -> il faut redécoder en str pour l'afficher
    dechiffre_bytes = decrypt(chiffre, cle)
    dechiffre = dechiffre_bytes.decode("utf-8")
    print(f"Déchiffré   : {dechiffre}")

    assert dechiffre == message
    print("-> Chiffrement/déchiffrement réussi\n")


# ============================================================
# 3. Chiffrer / déchiffrer un fichier
# ============================================================
def chiffrer_fichier(chemin_source, chemin_destination, cle):
    """Lit un fichier, le chiffre, écrit le résultat dans un nouveau fichier."""
    with open(chemin_source, "rb") as f:
        contenu = f.read()

    contenu_chiffre = encrypt(contenu, cle)

    with open(chemin_destination, "wb") as f:
        f.write(contenu_chiffre)


def dechiffrer_fichier(chemin_source, chemin_destination, cle):
    """Lit un fichier chiffré, le déchiffre, écrit le résultat en clair."""
    with open(chemin_source, "rb") as f:
        contenu_chiffre = f.read()

    contenu = decrypt(contenu_chiffre, cle)

    with open(chemin_destination, "wb") as f:
        f.write(contenu)


def exemple_fichier():
    print("=" * 60)
    print("Exemple 2 : chiffrer un fichier")
    print("=" * 60)

    cle = generer_cle()

    # Crée un fichier de test
    with open("secret.txt", "w", encoding="utf-8") as f:
        f.write("Contenu confidentiel du fichier.\nDeuxième ligne.")

    chiffrer_fichier("secret.txt", "secret.txt.enc", cle)
    print("Fichier chiffré -> secret.txt.enc")

    dechiffrer_fichier("secret.txt.enc", "secret_dechiffre.txt", cle)
    print("Fichier déchiffré -> secret_dechiffre.txt")

    with open("secret.txt", "rb") as f1, open("secret_dechiffre.txt", "rb") as f2:
        assert f1.read() == f2.read()
    print("-> Chiffrement/déchiffrement de fichier réussi\n")

    # Nettoyage des fichiers de démonstration
    for fichier in ["secret.txt", "secret.txt.enc", "secret_dechiffre.txt"]:
        os.remove(fichier)


# ============================================================
# 4. Point d'entrée
# ============================================================
if __name__ == "__main__":
    exemple_texte()
    exemple_fichier()
