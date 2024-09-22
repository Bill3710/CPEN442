import string
from collections import Counter
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
    minIC_Diff = 100 # just a really high number for default
    minIC_DiffKeylength = 0
    for keylength in range (1, 21):
        curTotalIC = 0
        for i in range (0, keylength):
            curCharGroup = ciphertext[i::keylength]
            curTotalIC += index_of_coincidence(curCharGroup)
        averageIC = curTotalIC / keylength
        
        # print(f"keylength: {keylength}, IC: {averageIC}")
        
        if minIC_Diff > abs(englishIC - averageIC):
            minIC_Diff = abs(englishIC - averageIC)
            
            if minIC_Diff <= 0.15:
                return keylength
            
            minIC_DiffKeylength = keylength
            
    return minIC_DiffKeylength


def crack_vigenere(ciphertext: str) -> tuple[str, str]:
    """Given a ciphertext generated with the Vigenere cipher, this function cracks the secret key and returns both the key and the plaintext."""
    key_length = crack_key_length_vigenere(ciphertext)
    subsequences = ['' for _ in range(key_length)]
    for i, char in enumerate(ciphertext):
        subsequences[i % key_length] += char

    english_freqs = {
        'E': 12.0, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 7.31, 'N': 6.95,
        'S': 6.28, 'R': 6.02, 'H': 5.92, 'D': 4.32, 'L': 3.98, 'U': 2.88,
        'C': 2.71, 'M': 2.61, 'F': 2.30, 'Y': 2.11, 'W': 2.09, 'G': 2.03,
        'P': 1.82, 'B': 1.49, 'V': 1.11, 'K': 0.69, 'X': 0.17, 'Q': 0.11,
        'J': 0.10, 'Z': 0.07
    }

    key = ''
    for sub in subsequences:
        freqs = Counter(sub)
        n = sum(freqs.values())
        score = {}
        for shift in range(26):
            shifted_score = 0 
            for char in english_freqs: 
                shifted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                if shifted_char in freqs:
                    char_freq = freqs[shifted_char] / n
                else:
                    char_freq = 0
                char_score = char_freq * english_freqs[char]
                shifted_score += char_score
            score[shift] = shifted_score

        best_shift = max(score, key=score.get)
        key += chr(ord('A') + best_shift)

    plaintext = vigenere_decrypt(ciphertext, key)
    return key, plaintext
