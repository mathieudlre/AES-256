# AES-256 from Scratch

**Une implémentation complète d'AES-256 en Python pur, écrite ligne par ligne pour comprendre chaque étape de l'algorithme — sans bibliothèque cryptographique externe.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-27%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Status](https://img.shields.io/badge/status-educational-orange)

---

## Pourquoi ce projet

AES (Advanced Encryption Standard) protège la quasi-totalité du trafic chiffré sur Internet, mais reste souvent une boîte noire même pour des développeurs expérimentés. Ce projet reconstruit l'algorithme AES-256 complet — S-Box, cadencement de clé, mode CBC — directement depuis la spécification officielle [FIPS-197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf), pour comprendre concrètement ce qui se passe entre un texte en clair et son équivalent chiffré.

Chaque fonction correspond à une étape précise de l'algorithme (`sub_bytes`, `shift_rows`, `mix_columns`, `key_expansion`…), testée individuellement contre les vecteurs de test officiels du NIST.

## Démo interactive

Une interface web permet de tester le chiffrement/déchiffrement directement dans le navigateur, sans rien installer :

- **[`web/index.html`](web/index.html)** — interface autonome, à ouvrir directement ou à héberger via GitHub Pages (voir [Héberger la démo](#héberger-la-démo-en-ligne))

> **Note de transparence** : l'algorithme AES-256 (`src/`) et les tests (`tests/`) ont été écrits et compris entièrement par moi. L'interface web (`web/index.html`) a en revanche été générée avec l'aide d'une IA (Claude, Anthropic) : je n'ai pas écrit le HTML/CSS/JavaScript moi-même, l'objectif étant de rendre le projet plus simple à démontrer, pas de m'attribuer ce travail. Le cœur cryptographique du projet reste le résultat de mon propre travail.

## Fonctionnalités

- Chiffrement et déchiffrement AES-256 complet (14 tours, clé de 256 bits)
- Mode opératoire CBC avec vecteur d'initialisation aléatoire
- Padding PKCS#7
- Chaque étape de l'algorithme isolée dans sa propre fonction, testée indépendamment
- 27 tests unitaires, incluant les vecteurs de test officiels FIPS-197
- Interface web autonome (HTML/CSS/JS), sans dépendance serveur
- Intégration continue : les tests tournent automatiquement à chaque push

## Architecture du projet

```
AES-256/
├── src/
│   ├── utils.py           # Conversions octets/matrice, arithmétique GF(2^8), padding
│   ├── sbox.py             # Table de substitution S-Box et son inverse
│   ├── key_expansion.py    # Cadencement de clé (256 bits -> 15 sous-clés)
│   └── aes.py               # Transformations de tour, chiffrement/déchiffrement, mode CBC
├── tests/
│   └── test_aes.py          # 27 tests unitaires (unittest), vecteurs FIPS-197 inclus
├── web/
│   └── index.html           # Interface de démonstration, 100% client-side
├── main.py                   # Exemples d'utilisation (texte et fichiers)
└── .github/workflows/
    └── tests.yml              # CI : tests exécutés automatiquement à chaque push
```

## Comment fonctionne AES-256 (résumé)

AES chiffre des blocs fixes de 16 octets, organisés en une matrice 4×4 appelée **état**. Pour une clé de 256 bits, l'algorithme applique **14 tours** de quatre transformations :

| Étape | Rôle |
|---|---|
| `SubBytes` | Substitution non linéaire de chaque octet via la S-Box |
| `ShiftRows` | Décalage cyclique des lignes de la matrice |
| `MixColumns` | Mélange linéaire des colonnes (absent au dernier tour) |
| `AddRoundKey` | XOR avec la sous-clé du tour, dérivée de la clé maître |

Les sous-clés de chaque tour sont générées une fois pour toutes par `key_expansion`, à partir de la clé de 256 bits fournie.

## Installation

Aucune dépendance externe — seul Python 3.9+ est nécessaire.

```bash
git clone https://github.com/mathieudlre/AES-256.git
cd AES-256
```

## Utilisation

```python
import os
import sys
sys.path.insert(0, "src")

from aes import encrypt, decrypt

cle = os.urandom(32)  # 256 bits
message = "Message confidentiel".encode("utf-8")

chiffre = encrypt(message, cle)
dechiffre = decrypt(chiffre, cle).decode("utf-8")

assert dechiffre == "Message confidentiel"
```

Un exemple complet (texte et fichiers) est disponible dans [`main.py`](main.py) :

```bash
python3 main.py
```

## Tests

```bash
python3 -m unittest tests/test_aes.py -v
```

Les tests couvrent :
- Le vecteur de test officiel FIPS-197 (Appendix C.3)
- La réversibilité de chaque transformation (`SubBytes`/`InvSubBytes`, `ShiftRows`/`InvShiftRows`…)
- Le cadencement de clé (nombre de sous-clés, cohérence avec la clé d'origine)
- Le chiffrement de bout en bout sur des messages courts, vides, longs et multi-blocs
- La validation du padding PKCS#7

## Héberger la démo en ligne

Pour rendre `web/index.html` accessible par un lien public (via GitHub Pages) :

1. Dans les paramètres du dépôt GitHub → **Pages**
2. Source : *Deploy from a branch* → branche `main`, dossier `/web` (ou `/root` selon l'organisation choisie)
3. GitHub fournit une URL du type `https://mathieudlre.github.io/AES-256/`

## Sécurité — Important

Ce projet est **strictement pédagogique**. Une implémentation Python pure n'est pas protégée contre les attaques par canal auxiliaire (temps d'exécution non constant, notamment) et ne doit **jamais** être utilisée pour chiffrer des données réellement sensibles.

Pour un usage en production, utiliser une bibliothèque auditée :
- [pycryptodome](https://pycryptodome.readthedocs.io/) (Python)
- [Web Crypto API](https://developer.mozilla.org/fr/docs/Web/API/Web_Crypto_API) (navigateur)

## Références

- [FIPS-197 — Advanced Encryption Standard (NIST)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

## Licence

Ce projet est sous licence MIT — voir [LICENSE](LICENSE).

---

*Projet réalisé dans un but d'apprentissage de la cryptographie appliquée.*
