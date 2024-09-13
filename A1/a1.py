


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
    return 0


def crack_vigenere(ciphertext: str) -> tuple[str, str]:
    """Given a ciphertext generated with the Vigenere cipher, this function cracks the secret key and returns both the key and the plaintext."""
    key = ''
    plaintext = ''
    return key, plaintext