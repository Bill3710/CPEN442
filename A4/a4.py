from typing import Callable
import time
import numpy as np

def online_attack(check_password: Callable) -> str:
    # TODO Implement attack here by calling check_password
    # Return the password
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    guessed_password = ""

    maxlength = 10

    while len(guessed_password) <= maxlength:
        maxTime = -1
        # current_char = None
        times = np.zeros(len(charset))

        for i, char in enumerate(charset):
            
            temp = guessed_password + char
            start = time.perf_counter()
            check_password(temp)
            times[i] = time.perf_counter() - start
            # print(times[i] > (maxTime + 0.0001), maxTime, char, "result \n")

            # if times[i] >= maxTime + 0.0001:
            #     maxTime = times[i]
            #     current_char = char
        index = 0
        for i in range(0,len(times)):
            if times[i] >= maxTime:
                maxTime = times[i]
                index = i

        guessed_password += charset[index]
        
        # guessed_password += current_char
        # print("more char \n", guessed_password)
        if check_password(guessed_password):
            print("password find!!!\n")
            return guessed_password
        
    return guessed_password
