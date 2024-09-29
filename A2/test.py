import numpy as np
import base64
import a2

'''

# 1.1 String <-> Bytes

text = 'hello world!'
text_bytes = text.encode('ascii')

text_string = text_bytes.decode('ascii')

print(text)
print(text_bytes)
print(text_string)

# 1.2 String <-> Bytes <-> base64

text_base64 = base64.b64encode(text_bytes)
print(text_base64)

text_binary = base64.b64decode(text_base64)
text = text_binary.decode('ascii')

print(text_binary)
print(text)

# 1.3 Testing

text_base64 = 'WW91ciBkZWNvZGluZyBzZWVtcyB0byBiZSB3b3JraW5nIGNvcnJlY3RseSEh'

text_bytes_base64 = text_base64.encode('ascii')
text_binary = base64.b64decode(text_bytes_base64)
text = text_binary.decode('ascii')

print(text_bytes_base64)
print(text_binary)
print(text)

'''

# 2.1 Using AES library PyCryptodome
from Crypto.Cipher import AES
from random import randbytes
from Crypto.Util.Padding import pad, unpad

'''
plaintext = b'hello, world!!!!!'

# Pad
padded_plaintext = pad(plaintext, AES.block_size)
print(padded_plaintext)

# Encrypt
key = randbytes(AES.block_size)
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(padded_plaintext)

print(ciphertext)

padded_plaintext = cipher.decrypt(ciphertext)
print(padded_plaintext)

plaintext = unpad(padded_plaintext, AES.block_size)
print(plaintext)

key = 'zQcs2L5vn2KsTAnCggbn4w=='
key_binary = base64.b64decode(key)

ciphertext = '2466mVLtcnf1FuvQiryyVHA3v2mJ8pUEEI0X7kaQHUzVOjkApO6E1mSsleGPa7ywM7P4rUaKYISQsT4LnUbVVQ=='
ciphertext_binary = base64.b64decode(ciphertext)

plaintext = a2.decrypt_aes_ecb(ciphertext_binary, key_binary)
print(plaintext)
'''

# 2.4 
'''
f = open('q24_plaintext.txt', 'r')
plaintexts = f.readlines()
text = ''.join(plaintexts)

for i in range(0, len(text), AES.block_size):
    substring = text[i: i+AES.block_size]

    print(substring.encode('unicode_escape').decode("utf-8"))

    
f = open('q24_ciphertext1.txt', 'r')
ciphertexts = f.readlines()
text = ''.join(ciphertexts)
ciphertext_binary = base64.b64decode(text)

for i in range(0, len(ciphertext_binary), AES.block_size):
    substring = ciphertext_binary[i: i+AES.block_size]
    print(substring)


f = open('q24_ciphertext2.txt', 'r')
ciphertexts = f.readlines()
text = ''.join(ciphertexts)
ciphertext_binary = base64.b64decode(text)

for i in range(0, len(ciphertext_binary), AES.block_size):
    substring = ciphertext_binary[i: i+AES.block_size]
    print(substring)


f = open('q24_ciphertext3.txt', 'r')
ciphertexts = f.readlines()
text = ''.join(ciphertexts)
ciphertext_binary = base64.b64decode(text)

for i in range(0, len(ciphertext_binary), AES.block_size):
    substring = ciphertext_binary[i: i+AES.block_size]
    print(substring)

'''

'''
# test from piazza
import random

random.seed(0)
print("  Testing AES-ECB")
key = randbytes(AES.block_size)
plaintext = b'This is a test message'
ciphertext = a2.encrypt_aes_ecb(plaintext, key)
print(f"ciphertext = '{base64.b64encode(ciphertext).decode('ascii')}'")
recovered_plaintext = a2.decrypt_aes_ecb(ciphertext, key)
print(f"recovered plaintext = '{recovered_plaintext.decode('ascii')}'")

print("\n  Testing AES-CBC")
key = randbytes(AES.block_size)
iv = randbytes(AES.block_size)
plaintext = b'This is another test message'
ciphertext = a2.encrypt_aes_cbc(plaintext, key, iv)
print(f"ciphertext = '{base64.b64encode(ciphertext).decode('ascii')}'")
recovered_plaintext = a2.decrypt_aes_cbc(ciphertext, key, iv)
print(f"recovered plaintext = '{recovered_plaintext.decode('ascii')}'")

print("\n  Testing AES-CTR")
key = randbytes(AES.block_size)
iv = randbytes(AES.block_size // 2)
plaintext = b'This is yet another test message!'
ciphertext = a2.encrypt_aes_ctr(plaintext, key, iv)
print(f"ciphertext = '{base64.b64encode(ciphertext).decode('ascii')}'")
recovered_plaintext = a2.decrypt_aes_ctr(ciphertext, key, iv)
print(f"recovered plaintext = '{recovered_plaintext.decode('ascii')}'")
'''
import utils

'''
# 3
my_server_CTR = utils.ServerCTR(seed=0)
my_attack_CTR = a2.AttackCTR(my_server_CTR)
name, pwd = my_attack_CTR.generate_name_and_pwd()

token = my_attack_CTR.server.generate_guest_token(name, pwd)
modified_token, modified_pwd = my_attack_CTR.modify_token_and_pwd(token)

result = my_attack_CTR.server.read_token(modified_token, modified_pwd)
print(result)
'''

# 4
my_server = utils.ServerECB(seed=0) # Initialize server
my_cracked_code = a2.attack_ecb(my_server.generate_guest_token) # Run attack
if my_cracked_code[0] == my_server.server_code[0]:
    print("You got the first character! (25 pts)")
if my_cracked_code == my_server.server_code:
    print("You got the full code! (30 pts)")

print(my_cracked_code)
print(my_server.server_code)
