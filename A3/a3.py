"""You must submit this file, after filling the functions defined here.
The function headers specify the format for inputs and outputs.
Do NOT change the function headers.
You can implement other functions and import other packages"""
from typing import Callable
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime
from utils import extended_gcd
import random


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

def mod_inv(x: int, n: int) -> int:
    """Computes the modular multiplicative inverse of x modulo n. It raises an error if the inverse does not exist."""
    gcd, inverse, _ = extended_gcd(x, n)
    
    if gcd != 1:
        raise ValueError(f"No modular inverse exists for {x} mod {n}")

    return inverse % n
    
def attack_q21(C_aes: bytes, C_rsa: int, e: int, n: int, p: int) -> str:
    """Implements a trivial attack against RSA as explained in question 2.1"""
    q  = n // p
    # print(p,q)
    fi = (q - 1) * (p - 1)

    d = mod_inv(e, fi)

    # print("aes input", C_aes)
    # print("rsa input", C_rsa)
    
    aes_key = mod_pow(C_rsa, d, n)

    aes_key_byte = aes_key.to_bytes(AES.block_size, byteorder='big')
    # print("key is ", aes_key)
    cipher = AES.new(aes_key_byte, AES.MODE_CBC, iv = bytes(AES.block_size))
    plaintext = unpad(cipher.decrypt(C_aes), AES.block_size)
    plaintext_str = plaintext.decode('ascii')

    return plaintext_str

def forge_signature1(e: int, n: int) -> tuple[int, int]:
    """Creates valid message-signature pairs (M, T) to be verified with the decryption key"""
    T = random.randint(1, n - 1)
    M = mod_pow(T, e, n)
    return M, T

def forge_signature2(M1: int, T1: int, M2: int, T2: int, e: int, n: int) -> int:
    """Creates a valid message-signature pair (M3, T3) for message M3 = M1 * M2 (mod n)"""
    M3 = (M1 * M2) % n
    T3 = (T1 * T2) % n
    
    return T3

def forge_signature3(e: int, n: int, sign: Callable) -> tuple[int, int]:
    """Forges a signature for the message ``Transfer all of Alice's money to Eve'' that can be verified with Alice's private key (d)"""
    M_str = "Transfer all of Alice's money to Eve"
    M = int.from_bytes(M_str.encode('ascii'), byteorder='big')

    e_inv = mod_inv(e,n)
    T = mod_pow(M, e_inv, n)

    return M, T


def find_collision(hash: Callable) -> tuple[bytes, bytes]:
    """Finds a collision for the callable hash function received as input. Returns the two inputs that have the same digest."""
    dict = []
    key1 = b''
    key2 = b''
    while True:
        cur_size = random.randint(1, 16)
        cur_key = random.randbytes(cur_size)
        cur_hash = hash(cur_key)
        for i in range(0, len(dict)):
            if dict[i][1] == cur_hash and dict[i][0] != cur_key:
                key1 = dict[i][0]
                key2 = cur_key
                break
        else:
            dict.append((cur_key,cur_hash))

    return key1, key2
        
def find_preimage(hash: Callable, digest: bytes) -> bytes:
    "Finds a pre-image for the given digest using the given callable hash function"
    preimage = b''
    while True:
        cur_size = random.randint(1, 16)
        cur_key = random.randbytes(cur_size)
        cur_hash = hash(cur_key)
        if cur_hash == digest:
            preimage = cur_key
            break

    return preimage
        

class Eve():
    """Implements the attacker for Q34"""

    def __init__(self):
        return
    
    def craft_message(self, M_evil: str) -> bytes:
        M_evil_bytes = M_evil.encode('ascii')
        message_length = len(M_evil_bytes)
        remainder = message_length % AES.block_size

        result_message = M_evil_bytes[:message_length-remainder]

        if remainder != 0:
            last_block = pad(M_evil_bytes[:-remainder], AES.block_size)
            result_message += last_block

        hash_digest = SHA256.new(data=result_message).digest()    

        return result_message + hash_digest
    
    def modify_ciphertext_and_iv(self, C: bytes, IV: bytes) -> tuple[bytes, bytes]:
        # c2 will always be the iv for our message
        new_IV = C[AES.block_size: 2*AES.block_size]

        # remove the starting two blocks and the last 3 blocks 
        new_cipher = C[2*AES.block_size: len(C) - 3*AES.block_size]

        return new_cipher, new_IV
    
