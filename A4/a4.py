from typing import Callable
import time
import numpy as np

def online_attack(check_password: Callable) -> str:
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    length = find_length(check_password)
    
    guessed_password = ['A'] * length
    
    for i in range(length):
        maxTime = -0.001
        times = np.zeros(len(charset))

        for j in range(len(charset)):
            guessed_password[i] = charset[j]
            start = time.perf_counter()
            check_password(''.join(guessed_password))
            times[j] = time.perf_counter() - start


        for k in range(len(times)):
            if times[k] > maxTime:
                maxTime = times[k]
                guessed_password[i] = charset[k]
        
        if check_password(guessed_password):
            print("password find!!!\n")
            return guessed_password
    
    return ''.join(guessed_password)

def find_length(check_password: Callable) -> int:

    maxTime = -0.001
    true_length = 0

    for len in range(5, 11):
        guess = '/' * len 
        start = time.perf_counter()
        check_password(guess)
        time_taken = time.perf_counter() - start

        if time_taken > maxTime:
            maxTime = time_taken
            true_length = len

    return true_length