import numpy as np


def index_of_coincidence(text: str) -> float:
    """Returns the index of coincidence of a text, assuming the alphabet is of size 26"""
    # Write your function here
    c = 26
    
    result = 0.0
    textLength = len(text)

    if textLength < 1 :
        print('empty string input');
        return -1
    
    for num in range(ord('A'), ord('Z')+1):
        count = 0
        for char in text:
            if ord(char) == num :
                count += 1

        if count > 0:
            result += (count / textLength) * ((count - 1)/(textLength - 1))

    result *= c

    return result


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Encrypts a plaintext with the given key using the Vigenere cipher, returning the ciphertext. You may assume the plaintext and key are strings that only contain ascii uppercase characters."""
    if plaintext == "" or key == "":
        return ""
    
    offsetASCII = 65 # ASCII for 'A'
    ciphertext = ''
    key_length = len(key)

    for i, char in enumerate(plaintext):
        key_char = key[i % key_length]
        encrypted_char = (ord(char) + ord(key_char) - 2 * offsetASCII) % 26 + offsetASCII
        ciphertext += chr(encrypted_char)

    return ciphertext

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypts a ciphertext with the given key using the Vigenere cipher, returning the plaintext. You may assume the ciphertext and key are strings that only contain ascii uppercase characters."""
    if ciphertext == "" or key == "":
        return ""
    
    offsetASCII = 65 # ASCII for 'A'
    plaintext = ''
    key_length = len(key)

    for i, char in enumerate(ciphertext):
        key_char = key[i % key_length] 
        decrypted_char = (ord(char) - ord(key_char) + 26) % 26 + offsetASCII
        plaintext += chr(decrypted_char)

    return plaintext


def crack_key_length_vigenere(ciphertext: str) -> int:
    """Returns the length of the key that was used to generate the given ciphertext with a Vigenere cipher"""
    keyLengths = range(2, 21)
    best_length = 0
    best_ic = 0.0

    for key_length in keyLengths:
            subsequences = []
            for _ in range(key_length):
                subsequences.append('')

            for i, char in enumerate(ciphertext):
                subsequences[i % key_length] += char

            total_ic = 0.0
            for sub in subsequences:
                total_ic += index_of_coincidence(sub)
            average_ic = total_ic / key_length

            if average_ic > best_ic:
                best_ic = average_ic
                best_length = key_length

    return best_length

def crack_vigenere(ciphertext: str) -> tuple[str, str]:
    """Given a ciphertext generated with the Vigenere cipher, this function cracks the secret key and returns both the key and the plaintext."""
    key = ''
    plaintext = ''

    key_length = crack_key_length_vigenere(ciphertext)
    subsequences = []

    for _ in range(key_length):
        subsequences.append('')

    for i, char in enumerate(ciphertext):
        subsequences[i % key_length] += char

    for i, sub in enumerate(subsequences):
        freqs = {}
        for char in sub:
            if char in freqs:
                freqs[char] += 1
            else:
                freqs[char] = 1

        most_freq_char = max(freqs, key=freqs.get)
        shift = (ord(most_freq_char) - ord('E')) % 26
        key += chr((ord('A') + shift) % 26 + ord('A'))

    plaintext = vigenere_decrypt(ciphertext, key)

    return key, plaintext
    
# vigenere_encrypt test #

plain1 = open("plaintext1.txt", "r").read()
cipher1 = open("ciphertext1.txt", "r").read()
key1 = open("key1.txt", "r").read()

print('## vigenere_encrypt test ##')
print('-------------------')
my_cipher1 = vigenere_encrypt(plain1, key1)

print(plain1)
print('-------------------')

print(cipher1)
print('-------------------')

print(my_cipher1)
print(cipher1 == my_cipher1)
print('-------------------')

# vigenere_decrypt test #

print('## vigenere_decrypt test ##')
my_plain1 = vigenere_decrypt(cipher1, key1)

print(cipher1)
print('-------------------')

print(plain1)
print('-------------------')

print(my_plain1)
print(plain1 == my_plain1)
print('-------------------')

#  Question 2.2  #
cipher2 = open("ciphertext2.txt", "r").read()
cipher3 = open("ciphertext3.txt", "r").read()

englishIC = 1.73

IC2 = index_of_coincidence(cipher2)
IC3 = index_of_coincidence(cipher3)

if abs(IC2 - englishIC) < abs(IC3 - englishIC) :
    print('cipher2text: substitution')
    print('cipher3text: vigenere')
else :
    print('cipher2text: vigenere')
    print('cipher3text: substitution')

# IC3 is much closer to the IC of typical English than IC2. Then cipher3text must be substitution #


# Question 5.1 #
