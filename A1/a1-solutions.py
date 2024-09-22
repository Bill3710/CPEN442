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

        if count > 0 :
            if textLength == 1:
                return 0
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
    englishIC = 1.73
    maxKeyLength = 100  # Assume maximum key length to check
    minIC_Diff = float('inf')
    bestKeyLength = 0

    for keylength in range(1, min(maxKeyLength, len(ciphertext) + 1)):
        totalIC = 0
        for i in range(keylength):
            curCharGroup = ciphertext[i::keylength]
            totalIC += index_of_coincidence(curCharGroup)
        averageIC = totalIC / keylength

        if abs(englishIC - averageIC) < minIC_Diff:
            minIC_Diff = abs(englishIC - averageIC)
            bestKeyLength = keylength

    return bestKeyLength


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