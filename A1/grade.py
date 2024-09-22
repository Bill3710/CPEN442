"""Grades the programming questions of A1."""
import os
import numpy as np
import importlib
import string
sol = importlib.import_module("a1-solutions") # the true solution; we compare with this to grade
stu = importlib.import_module("a1-solutions") # replace this with the student's solution

PATH = os.path.join('assignments', 'a1', 'code') # replace with the path where you have the plaintexts
PATH_TO_PLAINTEXTS = 'plaintexts-for-grading-long.txt'

def reformat_text_to_ascii_uppercase(text: str) -> str:
    """Converts the input 'text' into a string with characters in upper-case characters only"""
    text = text.upper()
    final_text = ''.join(c for c in text if c in string.ascii_uppercase)
    return final_text

def grade_q21(path_to_plaintexts):
    with open(path_to_plaintexts, 'r') as f:
        plaintexts = f.readlines()
    plaintexts = [reformat_text_to_ascii_uppercase(text) for text in plaintexts]    

    fails = 0
    for plaintext in plaintexts:
        if abs(sol.index_of_coincidence(plaintext) - stu.index_of_coincidence(plaintext)) > 1e-4:
            fails += 1
    return fails/len(plaintexts) * 100

def grade_q31(path_to_plaintexts, seed = 0):
    with open(path_to_plaintexts, 'r') as f:
        plaintexts = f.readlines()
    plaintexts = [reformat_text_to_ascii_uppercase(text) for text in plaintexts]  

    key_alphabet = list(string.ascii_uppercase)
    fails = 0
    for plaintext in plaintexts:
        for key_length in [3, 10, 20]:
            # Generate a random key of length key_length
            key = ''.join([key_alphabet[i] for i in np.random.permutation(len(key_alphabet))[:key_length]])
            # Encrypt with the true solution
            ciphertext = sol.vigenere_encrypt(plaintext, key)

            if ciphertext != stu.vigenere_encrypt(plaintext, key):
                fails += 1

            if plaintext != stu.vigenere_decrypt(ciphertext, key):
                fails += 1
    return fails/6/len(plaintexts) * 100

def grade_q41(path_to_plaintexts, seed = 0, nreps = 10):
    with open(path_to_plaintexts, 'r') as f:
        plaintexts = f.readlines()
    plaintexts = [reformat_text_to_ascii_uppercase(text) for text in plaintexts]

    np.random.seed(seed)
    fails = 0
    key_alphabet = list(string.ascii_uppercase)
    for plaintext in plaintexts:
        for key_length in range(3, 20):
            for _ in range(nreps):
                # Generate a random key of length key_length
                key = ''.join([key_alphabet[i] for i in np.random.permutation(len(key_alphabet))[:key_length]])
                # Encrypt with the true solution
                ciphertext = sol.vigenere_encrypt(plaintext, key)
                
                # Crack it
                cracked_length = stu.crack_key_length_vigenere(ciphertext)
                if cracked_length != len(key):
                    fails += 1
    return fails/len(range(3,20))/len(plaintexts)/nreps * 100

def grade_q51(path_to_plaintexts, seed = 0, nreps = 10):
    with open(path_to_plaintexts, 'r') as f:
        plaintexts = f.readlines()
    plaintexts = [reformat_text_to_ascii_uppercase(text) for text in plaintexts]

    np.random.seed(seed)
    fails = 0
    key_alphabet = list(string.ascii_uppercase)
    for plaintext in plaintexts:
        for key_length in range(3, 20):
            for _ in range(nreps):
                # Generate a random key of length key_length
                key = ''.join([key_alphabet[i] for i in np.random.permutation(len(key_alphabet))[:key_length]])
                # Encrypt with the true solution
                ciphertext = sol.vigenere_encrypt(plaintext, key)
                
                # Crack it
                cracked_key, cracked_plaintext = stu.crack_vigenere(ciphertext)
                if cracked_plaintext != plaintext:
                    fails += 1
    return fails/len(range(3,20))/len(plaintexts)/nreps * 100


if __name__ == "__main__":

    seed = 0
    print(f"Q21 (IoC) failure rate: {grade_q21(PATH_TO_PLAINTEXTS):.2f}%")
    print(f"Q31 (implement Vigenere) failure rate: {grade_q31(PATH_TO_PLAINTEXTS, seed):.2f}%")
    print(f"Q41 (crack key length) failure rate: {grade_q41(PATH_TO_PLAINTEXTS, seed):.2f}%")
    print(f"Q51 (crack Vigenere) failure rate: {grade_q51(PATH_TO_PLAINTEXTS, seed):.2f}%")
    