from typing import Callable
import time
import numpy as np

def online_attack(check_password: Callable) -> str:
    # TODO Implement attack here by calling check_password
    # Return the password
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    guessed_password = ""

    length = find_length(check_password)

    while len(guessed_password) <= length:
        maxTime = -0.001
        times = np.zeros(len(charset))

        for i, char in enumerate(charset):
            
            temp = guessed_password + char
            start = time.perf_counter()
            check_password(temp)
            times[i] = time.perf_counter() - start

        index = 0
        for i in range(0,len(times)):
            if times[i] >= maxTime:
                maxTime = times[i]
                index = i

        guessed_password += charset[index]
        
        if check_password(guessed_password):
            print("password find!!!\n")
            return guessed_password
        
    return guessed_password

def find_length(check_password: Callable) -> int:

    maxLength  = 10
    maxTime = -0.001

    length = np.zeros(maxLength + 1)
    for len in range(5, 11):
        guess = '/' * len 
        start = time.perf_counter()
        check_password(guess)
        time_taken = time.perf_counter() - start

        if time_taken > maxTime:
            length[len] = time_taken
    
    for i, time_taken in enumerate(length):
        if time_taken > maxTime:
            maxTime = time_taken
            true_length  = i

    return true_length