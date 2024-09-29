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

    def helper_2nd_3rd_block(self, token:bytes) -> tuple[bytes, bytes]:
        block_size = AES.block_size
        block2 = token[block_size: 2 * block_size]
        block3 = token[2 * block_size: 3 * block_size]

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

        first_part = token[0: AES.block_size]
        remainder = token[3 * AES.block_size:]

        new_token = first_part + modified_second_block + modified_third_block + remainder

        return new_token, "pwdN"


def attack_ecb(generate_token: Callable) -> str:

    base64_dictionary = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '+', '/']
    # Step 1 get the first letter in server code
    attack_name = '12345123456' # fill first block "name=12345123456"
    pre = 'ole=guest&code=' # 1 more char to complete this block

    # Structure: 0-64 blocks contain name info, 65 is pwd, 66 is the block to crack, 1-64 is the dictionary
    for i in range (0, 64):
        filling = pre + base64_dictionary[i]
        attack_name += filling

    attack_pwd = '123456789' # this block "&pwd=123456789&r", allowing the next block ending with the first char of server code

    token = generate_token(attack_name, attack_pwd)

    block_num = 0
    cipher64_dictionary = []
    target_block = b''
    for i in range(0, len(token), AES.block_size):
        cur_block = token[i: i+AES.block_size]
        
        # build cipher dictionary, 64 entries in total
        if block_num >= 1 and block_num <=64:
            cipher64_dictionary.append(cur_block)

        if block_num == 66:
            target_block = cur_block
            break

        block_num += 1
    first_letter = ''

    for j in range(0,64):
        if target_block == cipher64_dictionary[j]:
            first_letter = base64_dictionary[j]
            
    if first_letter == '':
        print('failed to find first letter')        
    
    server_code = first_letter + '' # length 24, 23 remains to crack

    # Step 2: get the next 15 letters in server code
    attack_name = '12345123456' # fill first block "name=12345123456"
    attack_pwd = '1234567890123456789123456' # construct blocks "&pwd=12345678901" "23456789123456&r" to allow shift positions in next step

    # Structure: 0-64 blocks contain name info, 65/66 is pwd, 67 is the block to crack, 1-64 is the dictionary

    for k in range(1, 16):  # get the first 16 chars first
        cur_name = attack_name # fill first block "name=12345123456"
        
        cur_pre = pre[k: ] + server_code[0: k]

        for i in range (0, 64):
            filling = cur_pre + base64_dictionary[i]
            cur_name += filling

        cur_passpwd = attack_pwd[: -k] # reduce the length of pwd one by one to get the code one by one

        token = generate_token(cur_name, cur_passpwd)

        block_num = 0
        cur_cipher64_dictionary = []
        target_block = b''
        for i in range(0, len(token), AES.block_size):
            cur_block = token[i: i+AES.block_size]
            
            # build cipher dictionary, 64 entries in total
            if block_num >= 1 and block_num <=64:
                cur_cipher64_dictionary.append(cur_block)

            if block_num == 67:
                target_block = cur_block
                break

            block_num += 1

        cur_letter = ''

        for j in range(0,64):
            if target_block == cur_cipher64_dictionary[j]:
                cur_letter = base64_dictionary[j]

        if cur_letter == '':
            print(f'failed to find {k}th letter')

        server_code += cur_letter

    # Step3: get the remaining 16 letters in the server code
    attack_name = '12345123456' # name remain unchanged
    attack_pwd = '1234567890123456789123456' # password remain unchanged

    # Structure: 0-64 blocks contain name info, 65/66 is pwd, 68 is the block to crack, 1-64 is the dictionary

    for k in range(0, 16): 
        cur_name = attack_name # fill first block "name=12345123456"
        
        cur_pre = server_code[1+k: ] # first 15 chars in block 68

        for i in range (0, 64):
            filling = cur_pre + base64_dictionary[i]
            cur_name += filling

        cur_passpwd = attack_pwd[: len(attack_pwd)-k] # reduce the length of pwd one by one to get the code one by one

        token = generate_token(cur_name, cur_passpwd)

        block_num = 0
        cur_cipher64_dictionary = []
        target_block = b''
        for i in range(0, len(token), AES.block_size):
            cur_block = token[i: i+AES.block_size]
            
            # build cipher dictionary, 64 entries in total
            if block_num >= 1 and block_num <=64:
                cur_cipher64_dictionary.append(cur_block)

            if block_num == 68:
                target_block = cur_block
                break

            block_num += 1

        cur_letter = ''

        for j in range(0,64):
            if target_block == cur_cipher64_dictionary[j]:
                cur_letter = base64_dictionary[j]

        if cur_letter == '':
            print(f'failed to find {k}th letter')

        server_code += cur_letter

    return server_code
