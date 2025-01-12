from algebra import mod_inv, int_to_bytes
from random import randint

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659


### call bruteLog with p = PARAM_P and g = PARAM_G

def bruteLog(g, c, p):
    """
    Brute force the discrete logarithm of c base g
    parameters:
    g: generator element
    c: target element
    p: prime modulus
    return: integer x such that g^x = c mod p, or -1 if not found
    """
    s = 1
    for i in range(p):
        if s == c:
            return i
        s = (s * g) % p
        if s == c:
            return i + 1
    return -1

def EG_generate_keys(key_length, p, g):
    """
    Generate private and public key pair for ElGamal
    Args:
        key_length: desired key length in bits
        p: prime modulus
        g: generator element
    Returns:
        tuple: (private_key, public_key)
    """
    x = randint(1, p-1)
    y = pow(g, x, p)
    return (x,y)

## multiplicative version
def EGM_encrypt(message, publickey, p, g):
    """
    Encrypt a message using multiplicative ElGamal with the given public key.
    Args:
        message: Integer message to encrypt
        publickey: Public key y = g^x mod p
        p: Prime modulus
        g: Generator element
    Returns:
        tuple: (c1, c2) encrypted message where:
            c1 = g^k mod p
            c2 = message * y^k mod p
    """
    k = randint(0, p-1)
    c1 = pow(g, k, p)
    c2 = (message * pow(publickey, k, p)) % p
    return(c1, c2)

## additive version
def EGA_encrypt(message, publickey, p, g):
    """
    Encrypt a message using additive ElGamal with the given public key.
    Args:
        message: Integer message to encrypt
        publickey: Public key y = g^x mod p
        p: Prime modulus
        g: Generator element
    Returns:
        tuple: (c1, c2) encrypted message where:
            c1 = g^k mod p
            c2 = g^message * y^k mod p
    """
    k = randint(0, p-1)
    c1 = pow(g, k, p)
    c2 = (pow(g, message, p) * pow(publickey, k, p)) % p
    return(c1, c2)

def EG_decrypt(c1, c2, privatekey, p, g):
    """
    Decrypt a message using ElGamal with the given private key.
    Args:
        c1: First component of ciphertext (g^k mod p)
        c2: Second component of ciphertext
        privatekey: Private key x
        p: Prime modulus
        g: Generator element
    Returns:
        int: Decrypted message
    """
    s = pow(c1, privatekey, p)
    s_inv = mod_inv(s,p)
    m = (c2 * s_inv) % p
    return(m)


(privatekey, publickey) = EG_generate_keys(2048, PARAM_P, PARAM_G)

#g^(0+1+1+0)

mesa = 0
mesb = 1
mesc = 1
mesd = 0

a1, a2 = EGA_encrypt(mesa, publickey, PARAM_P, PARAM_G)
b1, b2 = EGA_encrypt(mesb, publickey, PARAM_P, PARAM_G)
c1, c2 = EGA_encrypt(mesc, publickey, PARAM_P, PARAM_G)
d1, d2 = EGA_encrypt(mesd, publickey, PARAM_P, PARAM_G)


s1, s2 = a1*b1*c1*d1%PARAM_P, a2*b2*c2*d2%PARAM_P

decrypted = EG_decrypt(s1, s2, privatekey, PARAM_P, PARAM_G)

res = bruteLog(PARAM_G, decrypted, PARAM_P)
print(res)
