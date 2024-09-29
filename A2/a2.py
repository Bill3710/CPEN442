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
        self.name = "nameInit"   # 8 bytes + name= (5 bytes) =  13 bytes
        self.password = "pwd_init" # &pwd= (5 bytes) + 8 bytes + &role=(6 bytes) = 19 bytes 

    def helper_2nd_3rd_block(token:bytes) -> tuple[bytes, bytes]:
        
        block_size = 16,
        block2 = token[block_size: 2 * block_size - 1]
        block3 = token[2 * block_size: 3 * block_size - 1]

        return block2, block3
    def generate_name_and_pwd(self) -> tuple[str, str]:
        return self.name, self.password
    
    def modify_token_and_pwd(self, token: bytes) -> tuple[bytes, str]:
        guest_role = b"guest" # 5 bytes
        superuser_role = b"superuser" # 9 bytes

        guest_pwd = b"pwd_init" # 8 bytes
        superuser_pwd = b"pwdN" # 4 bytes
        
        second_block, third_block = self.helper_2nd_3rd_block(token)
        #second_block = d=pwd_init&role=
        #third_block = guest&code=*****

        target_second = b"d=pwdN&role=supe"
        target_third = b"ruser&code="

        padded_target_third = pad(target_third, AES.block_size)

        xor_diff_second =  xor_bytes(target_second, second_block)
        xor_diff_third = xor_bytes(padded_target_third, third_block)
        
        modified_second_block = xor_bytes(second_block, xor_diff_second)
        modified_third_block = xor_bytes(third_block, xor_diff_third)

        first_part = token[0 :AES.block_size - 1]
        remainder = token[3 * AES.block_size:]

        new_token = first_part + modified_second_block + modified_third_block + remainder

        return new_token, "pwdN"



def attack_ecb(generate_token: Callable) -> str:
    return ''
