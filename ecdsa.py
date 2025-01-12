from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

# Curve parameters
p = 2**255 - 19  # Prime field characteristic
ORDER = (2**252 + 27742317777372353535851937790883648493)  # Curve order

# Base point coordinates
BaseU = 9  # x-coordinate
BaseV = computeVcoordinate(BaseU)  # y-coordinate computed from x


def H(message):
    """
    Compute SHA256 hash of a message.
    
    Args:
        message: Bytes or string to hash
        
    Returns:
        int: Integer representation of the hash
    """
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))


def ECDSA_generate_nonce():
    """
    Generate a random nonce k for ECDSA signing.
    The nonce must be between 1 and ORDER-1.
    
    Returns:
        int: Random nonce k
    """
    return randint(1, ORDER - 1)


def ECDSA_generate_keys():
    """
    Generate a new ECDSA key pair.
    
    Returns:
        tuple: (private_key, public_key)
            - private_key: Random integer d between 1 and ORDER-1
            - public_key: Point Q = d*G where G is the base point
    """
    private_key = randint(1, ORDER - 1)  # Random private key
    public_key = mult(private_key, BaseU, BaseV, p)  # Q = d*G
    return private_key, public_key


def ECDSA_sign(message, private_key):
    """
    Sign a message using ECDSA.
    
    Args:
        message: Message to sign (bytes or int)
        private_key: Signer's private key d
        
    Returns:
        tuple: Signature (r, s) where:
            - r is the x-coordinate of k*G mod ORDER
            - s = k^(-1)(z + r*d) mod ORDER
            where z is the message hash and k is a random nonce
            
    Raises:
        ValueError: If signature generation fails (invalid r or s)
    """
    z = H(message) % ORDER  # Hash the message
    k = ECDSA_generate_nonce()  # Generate random nonce
    R = mult(k, BaseU, BaseV, p)  # Compute R = k*G
    r = R[0] % ORDER  # r = x-coordinate of R mod ORDER
    
    if r == 0:
        raise ValueError("Invalid signature: r = 0")
        
    k_inv = mod_inv(k, ORDER)  # Compute k^(-1) mod ORDER
    s = (k_inv * (z + r * private_key)) % ORDER  # s = k^(-1)(z + r*d) mod ORDER
    
    if s == 0:
        raise ValueError("Invalid signature: s = 0")
        
    return (r, s)


def ECDSA_verify(message, r, s, public_key):
    """
    Verify an ECDSA signature.
    
    Args:
        message: Original message that was signed
        r: First part of signature (x-coordinate of R)
        s: Second part of signature
        public_key: Signer's public key Q
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Check signature components are in valid range
    if not (1 <= r < ORDER and 1 <= s < ORDER):
        return False
        
    z = H(message) % ORDER  # Hash the message
    s_inv = mod_inv(s, ORDER)  # Compute s^(-1) mod ORDER
    u1 = (z * s_inv) % ORDER
    u2 = (r * s_inv) % ORDER

    # Compute u1*G + u2*Q
    P1 = mult(u1, BaseU, BaseV, p)
    P2 = mult(u2, public_key[0], public_key[1], p)
    P = add(P1[0], P1[1], P2[0], P2[1], p)

    # Verify if x-coordinate of P mod ORDER equals r
    v = P[0] % ORDER
    return v == r


def test_ecdsa():
    """
    Test ECDSA implementation with signing and verification.
    
    Process:
    1. Generate key pair
    2. Sign a test message
    3. Verify the signature
    4. Test with modified message
    """
    print("-----Testing ECDSA Implementation-----")
    
    # Generate keys
    private_key, public_key = ECDSA_generate_keys()
    print("Keys generated successfully")
    
    # Test message
    message = b"Test message for ECDSA"
    print(f"Original message: {message}")
    
    # Sign message
    signature = ECDSA_sign(message, private_key)
    r, s = signature
    print(f"Signature generated: (r={r}, s={s})")
    
    # Verify valid signature
    is_valid = ECDSA_verify(message, r, s, public_key)
    print(f"Signature verification (original message): {is_valid}")
    assert is_valid, "Signature verification failed for valid message"
    
    # Test with modified message
    modified_message = b"Modified test message"
    is_valid_modified = ECDSA_verify(modified_message, r, s, public_key)
    print(f"Signature verification (modified message): {is_valid_modified}")
    assert not is_valid_modified, "Signature incorrectly verified for modified message"
    
    print("All tests passed successfully!")
    return True


if __name__ == "__main__":
    test_ecdsa()
