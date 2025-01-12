from rfc7448 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

# Paramètres de la courbe
p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

# Fonction de hachage
def H(message):
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)

# Génération du nounce
def ECDSA_generate_nonce():
    return randint(1, ORDER - 1)

# Générer une paire de clés (privée et publique)
def ECDSA_generate_keys():
    private_key = randint(1, ORDER - 1)  # Clé privée aléatoire
    public_key = mult(private_key, BaseU, BaseV, p)  # Clé publique correspondante
    return private_key, public_key

# Signer un message
def ECDSA_sign(message, private_key):
    z = H(message) % ORDER  # Hachage du message
    k = ECDSA_generate_nonce()  # Générer un nonce
    R = mult(k, BaseU, BaseV, p)  # Calculer le point R
    r = R[0] % ORDER  # Coordonnée x de R (mod l'ordre)
    if r == 0:
        raise ValueError("Le nonce a produit une signature invalide.")
    k_inv = mod_inv(k, ORDER)  # Inverse modulaire de k
    s = (k_inv * (z + r * private_key)) % ORDER  # Calculer s
    if s == 0:
        raise ValueError("Le calcul de s a échoué.")
    return (r, s)

# Vérifier une signature
def ECDSA_verify(message, signature, public_key):
    r, s = signature
    if not (1 <= r < ORDER and 1 <= s < ORDER):
        return False  # Signature invalide
    z = H(message) % ORDER
    s_inv = mod_inv(s, ORDER)  # Inverse modulaire de s
    u1 = (z * s_inv) % ORDER
    u2 = (r * s_inv) % ORDER #Calcul des multiplicateurs pour les points

    # Multiplier les scalaires
    P1 = mult(u1, BaseU, BaseV, p)
    P2 = mult(u2, public_key[0], public_key[1], p) #Points obtenus par multiplication scalaire.

    # Ajouter les points
    P = add(P1[0], P1[1], P2[0], P2[1], p)

    # Vérifier si v == r
    v = P[0] % ORDER
    return v == r
