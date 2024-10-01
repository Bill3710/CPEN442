"""You must submit this file, after filling the functions defined here.
The function headers specify the format for inputs and outputs.
Do NOT change the function headers.
You can implement other functions and import other packages"""
from typing import Callable
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from utils import extended_gcd
import random


def mod_pow(x: int, y: int, n: int) -> int:
    """Computes x**y % n using the binary modular exponentiation algorithm."""
    return 0

def mod_inv(x: int, n: int) -> int:
    """Computes the modular multiplicative inverse of x modulo n. It raises an error if the inverse does not exist."""
    return 0
    
def attack_q21(C_aes: bytes, C_rsa: int, e: int, n: int, p: int) -> str:
    """Implements a trivial attack against RSA as explained in question 2.1"""
    return ''

def forge_signature1(e: int, n: int) -> tuple[int, int]:
    """Creates valid message-signature pairs (M, T) to be verified with the decryption key"""
    return 0, 0

def forge_signature2(M1: int, T1: int, M2: int, T2: int, e: int, n: int) -> int:
    """Creates a valid message-signature pair (M3, T3) for message M3 = M1 * M2 (mod n)"""
    return 0

def forge_signature3(e: int, n: int, sign: Callable) -> tuple[int, int]:
    """Forges a signature for the message ``Transfer all of Alice's money to Eve'' that can be verified with Alice's private key (d)"""
    return 0, 0


def find_collision(hash: Callable) -> tuple[bytes, bytes]:
    """Finds a collision for the callable hash function received as input. Returns the two inputs that have the same digest."""
    return bytes(1), bytes(1)
        
def find_preimage(hash: Callable, digest: bytes) -> bytes:
    "Finds a pre-image for the given digest using the given callable hash function"
    return bytes(1)
        

class Eve():
    """Implements the attacker for Q34"""

    def __init__(self):
        return
    
    def craft_message(self, M_evil: str) -> bytes:
        return bytes(1)
    
    def modify_ciphertext_and_iv(self, C: bytes, IV: bytes) -> tuple[bytes, bytes]:
        return bytes(1), bytes(1)