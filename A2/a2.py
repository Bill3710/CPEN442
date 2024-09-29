"""You must submit this file, after filling the functions defined here.
The function headers specify the format for inputs and outputs.
Do NOT change the function headers.
You can implement other functions and import other packages"""
from typing import Callable
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from utils import ServerCTR


def xor_bytes(input1: bytes, input2: bytes) -> bytes:
    """Returns the bit-by-bit XOR of two bytes inputs"""
     # truncate the bytes that are longer
    if len(input1) > len(input2):
        input1 = input1[-len(input2):]
    elif len(input2) > len(input1):
        input2 = input2[-len(input1):]

    return bytes(a ^ b for a, b in zip(input1, input2))

def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    """Encrypts the plaintext with the given key using AES in ECB mode. Returns the cyphertext as a bytes object"""

    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    return ciphertext


def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts the ciphertext with the given key using AES in ECB mode. Returns the plaintext as a bytes object"""

    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)

    return plaintext

def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypts the ciphertext with the given key and iv using AES in CBC mode. Returns the plaintext as a bytes object"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext


def encrypt_aes_ctr(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts the plaintext with the given key and IV using AES in CTR mode. Returns the cyphertext as a bytes object"""
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def decrypt_aes_ctr(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypts the ciphertext with the given key and IV using AES in CTR mode. Returns the plaintext as a bytes object"""
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

class AttackCTR:

    def __init__(self, server: ServerCTR):
        self.server = server

    def generate_name_and_pwd(self) -> tuple[str, str]:
        return "guest_user", "guest_pwd"
    
    def modify_token_and_pwd(self, token: bytes) -> tuple[bytes, str]:

        cipher = AES.new(self.server.key, AES.MODE_CTR, nonce=self.server.iv)
        plaintext = cipher.decrypt(token)

        g_plaintext = b"guest"
        target = b"superuser"

        idx = plaintext.find(g_plaintext)
        if idx == -1:
            print("Guest role not found, returning original token")
            return token, "guest_pwd"
        
        xor_diff = xor_bytes(g_plaintext, target)
        modified_ciphertext = bytearray(token)

        for i in range(len(xor_diff)):
            modified_ciphertext[idx + i] ^= xor_diff[i]

        new_pwd = "superpwd"
        return bytes(modified_ciphertext), new_pwd


def attack_ecb(generate_token: Callable) -> str:
    base64_dictionary = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '+', '/']
    attack_name = '12345123456' # fill first block "name=12345123456"
    pre = 'ole=guest&code=' # 1 more char to complete this block

    for i in range (0, 64):
        filling = pre + base64_dictionary[i]
        attack_name += filling

    attack_pwd = 123456789 # allowing the next block ending with the first char in code



    return ''
