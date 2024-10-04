from typing import Callable
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from utils import extended_gcd
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

# Test
if __name__ == "__main__":

    # Bob creates message for Alice
    M_str = "Hello, world!"

    # Encrypt message with random AES key (IV is all-zero bytes)
    aes_key = random.randbytes(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=bytes(AES.block_size))
    C_aes = cipher.encrypt(pad(M_str.encode('ascii'), AES.block_size))

    # Encrypt AES key with Textbook RSA (params: M, e, n)
    aes_key_as_int = int.from_bytes(aes_key, byteorder='big')
    print("true int key:", aes_key_as_int)
    p = getPrime(1024)
    q = getPrime(1024)
    e = 65537 
    phi_n = (p - 1) * (q - 1)
    d = a3.mod_inv(e, phi_n)
    n = p * q

    C_rsa = textbook_rsa_encrypt(aes_key_as_int, e, n)

    # Here, Bob would send Alice (C_aes || C_rsa)

    # Your attack: Eve intercepts the ciphertext and knows public parameters (e, n), plus p:
    recovered_text = a3.attack_q21(C_aes, C_rsa, e, n, p)

    # Checking the attack correctly recovered the plaintext:
    assert recovered_text == M_str
