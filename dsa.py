from algebra import mod_inv
from Crypto.Hash import SHA256
from random import randint
from sympy import sqrt, Integer, log, ceiling

# Parameters from MODP Group 24 -- Extracted from RFC 5114
# These are standardized domain parameters for DSA

# Large prime modulus p
PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

# Prime divisor q of p-1
PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

# Generator g of the q-order subgroup of Z_p*
PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659


def DSA_generate_nonce():
    """Generate a random nonce between 1 and q-2 for DSA signing"""
    return randint(1, PARAM_Q - 2)


def H(message):
    """Hash a message using SHA256 and return the integer representation"""
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)


def DSA_generate_keys(key_length, p, q, g):
    """
    Generate DSA key pair
    Args:
        key_length: Desired key length in bits
        p: Prime modulus
        q: Prime divisor of p-1
        g: Generator
    Returns:
        tuple: (private_key, public_key)
    """
    x = randint(1, q-1)  # Private key
    y = pow(g, x, p)     # Public key = g^x mod p
    return (x, y)


def DSA_sign(message, privatekey, p, q, g):
    """
    Generate DSA signature for a message
    Args:
        message: Message to sign
        privatekey: Signer's private key
        p, q, g: Domain parameters
    Returns:
        tuple: Signature (r, s)
    """
    while True:
        k = DSA_generate_nonce()  # Generate random nonce
        r = pow(g, k, p) % q      # r = (g^k mod p) mod q
        if r == 0:
            continue
        s = (mod_inv(k, q) * (H(message) + privatekey * r)) % q  # s = k^-1(H(m) + xr) mod q
        if s != 0:
            break
    return (r, s)


def DSA_verify(message, r, s, publickey, p, q, g):
    """
    Verify a DSA signature
    Args:
        message: Original message
        r, s: Signature components
        publickey: Signer's public key
        p, q, g: Domain parameters
    Returns:
        bool: True if signature is valid
    """
    if not (0 < r < q) or not (0 < s < q):
        return False
    w = mod_inv(s, q)           # w = s^-1 mod q
    u1 = (H(message) * w) % q   # u1 = H(m)w mod q
    u2 = (r * w) % q            # u2 = rw mod q
    t1 = pow(g, u1, p)          # t1 = g^u1 mod p
    t2 = pow(publickey, u2, p)  # t2 = y^u2 mod p
    v = ((t1 * t2) % p) % q     # v = ((g^u1 * y^u2) mod p) mod q
    return v == r


def is_square(n):
    """Check if a number is a perfect square"""
    return type(sqrt(n)) == Integer


def fermat_factor(n):
    """
    Factor a number using Fermat's factorization method
    Args:
        n: Number to factor
    Returns:
        tuple: (p+q, p-q, iterations)
    """
    num_digits = int(log(n, 10).evalf() + 1)
    a = ceiling( sqrt(n).evalf(num_digits) )
    counter = 0
    while not is_square(a*a - n):
        a += 1
        counter += 1
    b = sqrt(a*a - n)
    return(a+b, a-b, counter)


def get_privatekey_from_nonce(nonce, r, s, hash_of_message, q):
    """
    Recover private key if nonce is known
    Args:
        nonce: Known nonce k used in signing
        r, s: Signature components
        hash_of_message: Hash of the signed message
        q: Domain parameter
    Returns:
        int: Recovered private key
    """
    return (((s * nonce) - hash_of_message) * mod_inv(r, q)) % q
