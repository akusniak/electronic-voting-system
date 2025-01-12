from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint

# Function sub implements point subtraction
# Function ECencode maps 0 and 1 to the correct points on the elliptic curve

p = 2**255 - 19  # Prime number
ORDER = (2**252 + 27742317777372353535851937790883648493)  # Order of the curve

BaseU = 9  # Base point of the elliptic curve
BaseV = computeVcoordinate(BaseU)  # Compute the V coordinate of the base point


# Functions provided by the instructions

def bruteECLog(C1, C2, p):
    """
    Brute force the EC logarithm of C1 and C2
    parameters:
    C1: point on the curve
    C2: point on the curve 
    p: prime number
    return: integer representing the message
    """
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1


def EGencode(message):
    """
    Encode the message into a point on the elliptic curve
    parameters:
    message: integer representing the message
    return: point on the curve
    """
    if message == 0:
        return (1, 0)
    if message == 1:
        return (BaseU, BaseV)


def ECEG_generate_keys():
    """
    Generate private and public key pair for EC ElGamal
    Returns:
        tuple: (private_key, public_key)
    """
    priv = randint(1, ORDER - 1)
    pub = mult(priv, BaseU, BaseV, p)
    return (priv, pub)


def ECEG_encrypt(message: int, pub: tuple) -> tuple:
    """
    Encrypt a message using EC ElGamal with the given public key.

    Args:
        message: Integer message to encrypt (must be 0 or 1)
        pub: Public key tuple (x, y) representing a point on the curve

    Returns:
        tuple: (C1, C2) encrypted message points on the curve

    Raises:
        ValueError: If message is not 0 or 1
    """
    if message not in (0, 1):
        raise ValueError("Message must be 0 or 1")

    message_point = EGencode(message)
    r = randint(1, ORDER - 1)

    # C1 = r * G (base point)
    # C2 = M + r * Q (public key)
    C1 = mult(r, BaseU, BaseV, p)
    r_Q = mult(r, pub[0], pub[1], p)
    C2 = add(message_point[0], message_point[1], r_Q[0], r_Q[1], p)
    
    return (C1, C2)


def ECEG_decrypt(message: tuple, priv: int) -> tuple:
    """
    Decrypt a message using EC ElGamal with the given private key.

    Args:
        message: Encrypted message tuple ((x1,y1), (x2,y2)) containing two curve points
        priv: Private key integer k where Q = k*G

    Returns:
        tuple: (x,y) Decrypted message point M = C2 - k*C1
    """
    if not 1 <= priv <= ORDER - 1:
        raise ValueError("Private key is not valid")

    if not isinstance(message, tuple) or len(message) != 2:
        raise ValueError("Invalid encrypted message format")

    C1, C2 = message

    # Compute k*C1 = k*(r*G) = r*Q 
    k_C1 = mult(priv, C1[0], C1[1], p)

    # Recover message point M = C2 - k*C1 = (M + r*Q) - r*Q
    M = sub(C2[0], C2[1], k_C1[0], k_C1[1], p)

    return M


def test_homomorphic_property():
    """
    Test the homomorphic property of EC ElGamal encryption.
    Process:
    1. Encrypt five messages [1,0,1,1,0]
    2. Add their encrypted forms
    3. Decrypt the sum
    4. Verify the result equals 3
    """
    messages = [1, 0, 1, 1, 0]
    print("Testing messages:", messages)

    # Generate keys
    private_key, public_key = ECEG_generate_keys()
    print("Keys generated successfully")

    # Step 1: Encrypt each message
    encrypted_messages = []
    for i, m in enumerate(messages, 1):
        cipher = ECEG_encrypt(m, public_key)
        encrypted_messages.append(cipher)
        print(f"Message {i} encrypted: (r{i}, c{i})")

    # Step 2: Add encrypted messages
    # Start with point at infinity (1,0)
    r_sum = (1, 0)  # Sum of all r values
    c_sum = (1, 0)  # Sum of all c values

    # Add all encrypted parts
    for r, c in encrypted_messages:
        r_sum = add(r_sum[0], r_sum[1], r[0], r[1], p)
        c_sum = add(c_sum[0], c_sum[1], c[0], c[1], p)
    print("Sum of encrypted messages computed")

    # Step 3: Decrypt the sum
    decrypted_point = ECEG_decrypt((r_sum, c_sum), private_key)
    print("Sum decrypted to point:", decrypted_point)

    # Step 4: Convert point to actual sum using bruteforce
    message_sum = bruteECLog(decrypted_point[0], decrypted_point[1], p)
    print("Final sum:", message_sum)

    # Verify the result
    expected_sum = sum(messages)
    if message_sum == expected_sum:
        print("Test SUCCESSFUL: Homomorphic property verified")
        print(f"Sum of original messages: {expected_sum}")
        print(f"Decrypted sum: {message_sum}")
    else:
        print("Test FAILED")
        print(f"Expected {expected_sum}, got {message_sum}")

    return message_sum == expected_sum


if __name__ == "__main__":
    test_homomorphic_property()
