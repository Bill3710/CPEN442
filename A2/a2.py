"""You must submit this file, after filling the functions defined here.
The function headers specify the format for inputs and outputs.
Do NOT change the function headers.
You can implement other functions and import other packages"""
from typing import Callable
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def xor_bytes(input1: bytes, input2: bytes) -> bytes:
    """Returns the bit-by-bit XOR of two bytes inputs"""
    return bytes(1)

def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    """Encrypts the plaintext with the given key using AES in ECB mode. Returns the cyphertext as a bytes object"""
    return bytes(1)


def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts the ciphertext with the given key using AES in ECB mode. Returns the plaintext as a bytes object"""
    return bytes(1)

def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts the plaintext with the given key and IV using AES in CBC mode. Returns the cyphertext as a bytes object"""
    return bytes(1)

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypts the ciphertext with the given key and iv using AES in CBC mode. Returns the plaintext as a bytes object"""
    return bytes(1)


def encrypt_aes_ctr(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts the plaintext with the given key and IV using AES in CTR mode. Returns the cyphertext as a bytes object"""
    return bytes(1)


def decrypt_aes_ctr(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypts the ciphertext with the given key and IV using AES in CTR mode. Returns the plaintext as a bytes object"""
    return bytes(1)


class AttackCTR:

    def __init__(self):
        pass

    def generate_name_and_pwd(self) -> tuple[str, str]:
        return '', ''
    
    def modify_token_and_pwd(self, token: bytes) -> tuple[bytes, str]:
        return bytes(1), ''


def attack_ecb(generate_token: Callable) -> str:
    return ''
