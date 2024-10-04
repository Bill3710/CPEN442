from typing import Callable
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from utils import extended_gcd, evaluate_forge_signature1, evaluate_forge_signature2, AliceAndBob, Alice
import random
import a3

def textbook_rsa_encrypt(M: int, e: int, n: int) -> int:
    """
    RSA textbook encryption: Encrypts the integer message M using the public key (e, n).
    C = M^e mod n
    """
    # print("M is ",M)
    # print("e is ",e)
    # print("n is ",n)

    return a3.mod_pow(M, e, n)

def evaluate_forge_signature():
    alice = Alice()  # Instantiate Alice
    e, n = alice.get_public_key()  # Get her public parameters

    # Test forge_signature1
    print("\nTesting forge_signature1:")
    evaluate_forge_signature1(a3.forge_signature1)
    print("forge_signature1 passed!")

    # Test forge_signature2
    print("\nTesting forge_signature2:")
    evaluate_forge_signature2(a3.forge_signature2)
    print("forge_signature2 passed!")

    # Test forge_signature3
    print("\nTesting forge_signature3:")
    M, T = a3.forge_signature3(e, n, alice.sign)  # Forge signature
    alice.check_q24_correctness(M, T)  # Verify you forged the right signature
    print("forge_signature3 passed!")


def testing_alice_and_bob():
    aliceandbob = AliceAndBob()  # initialize Alice and Bob

    eve = a3.Eve()  # initialize Eve
    M_eve = eve.craft_message("I hate you, Bob!!!")  # Eve crafts a message
    C, IV = aliceandbob.send_message_from_eve(M_eve)  # Alice warns Bob about the message
    C, IV = eve.modify_ciphertext_and_iv(C, IV)  # Eve modifies ciphertext and IV
    aliceandbob.receive_message(C, IV)  # Bob receives the modified message

def mod_pow(x: int, y: int, n: int) -> int:
    """Computes x**y % n using the binary modular exponentiation algorithm."""
    result = 1
    x = x % n
    while y > 0:
        if y % 2 == 1:
            result = (result * x) % n
        x = (x * x) % n
        y //= 2
    return result


# Test
if __name__ == "__main__":

    # # # Bob creates message for Alice
    # M_str = "Hello, world!"

    # # Encrypt message with random AES key (IV is all-zero bytes)
    # aes_key = random.randbytes(AES.block_size)
    # cipher = AES.new(aes_key, AES.MODE_CBC, iv=bytes(AES.block_size))
    # C_aes = cipher.encrypt(pad(M_str.encode('ascii'), AES.block_size))

    # # Encrypt AES key with Textbook RSA (params: M, e, n)
    # aes_key_as_int = int.from_bytes(aes_key, byteorder='big')
    # print("true int key:", aes_key_as_int)
    # p = getPrime(1024)
    # q = getPrime(1024)
    # e = 65537 
    # phi_n = (p - 1) * (q - 1)
    # d = a3.mod_inv(e, phi_n)
    # n = p * q

    # C_rsa = textbook_rsa_encrypt(aes_key_as_int, e, n)

    # # Here, Bob would send Alice (C_aes || C_rsa)

    # # Your attack: Eve intercepts the ciphertext and knows public parameters (e, n), plus p:
    # recovered_text = a3.attack_q21(C_aes, C_rsa, e, n, p)

    # # Checking the attack correctly recovered the plaintext:
    # assert recovered_text == M_str
    
    # evaluate_forge_signature()
    testing_alice_and_bob()
