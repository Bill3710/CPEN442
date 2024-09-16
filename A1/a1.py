


def index_of_coincidence(text: str) -> float:
    """Returns the index of coincidence of a text, assuming the alphabet is of size 26"""
    # Write your function here
    return 1.


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Encrypts a plaintext with the given key using the Vigenere cipher, returning the ciphertext. You may assume the plaintext and key are strings that only contain ascii uppercase characters."""
    if plaintext == "" or key == "":
        return -1
    offsetASCII = 65 # ASCII for 'A'
    ciphertext = ''
    for charK in key:
        for charP in plaintext:
            ciphertext += chr(ord(charK) + ord(charP) - offsetASCII)
    return ciphertext

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypts a ciphertext with the given key using the Vigenere cipher, returning the plaintext. You may assume the ciphertext and key are strings that only contain ascii uppercase characters."""
    if ciphertext == "" or key == "":
        return -1
    offsetASCII = 65 # ASCII for 'A'
    plaintext = ''
    for charK in key:
        for charC in ciphertext:
            if ord(charC) < ord(charK):
                plaintext += chr(ord(charC) + 26 - ord(charK) + offsetASCII)
            else :
                plaintext += chr(ord(charC) - ord(charK) + offsetASCII)
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
    return key, plaintext