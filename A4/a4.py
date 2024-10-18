from typing import Callable
import time
import numpy as np

def online_attack(check_password: Callable) -> str:
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    default_char = '@'
    sleep_time = 0.001
    confidence_threshold = sleep_time * 0.8

    password_length = find_length(check_password)
    guessed_password = [default_char] * password_length
    avg_time = np.zeros(password_length)
    
    i = 0
    while i < password_length:

        times = np.zeros(len(charset))
        # find digits one by one using timing trick
        
        for j in range(len(charset)):
            guessed_password[i] = charset[j]
            curr_pwd = ''.join(guessed_password)
            start = time.perf_counter()
            check_password(curr_pwd)
            end = time.perf_counter()
            times[j] = end - start

        # use this round result determine whether the previous turn's guess correct
        cur_avr_time = np.average(times)
        #print(cur_avr_time)
        
        time_diff = 0
        if i == 0:
            time_diff = cur_avr_time
        else:
            time_diff = cur_avr_time - avg_time[i - 1]

        if time_diff >= confidence_threshold:
            # previous digit correct
            max_index = np.argmax(times)
            guessed_password[i] = charset[max_index]
            avg_time[i] = cur_avr_time
            i += 1
        else:
            # previous digit wrong, roll back to get it right
            guessed_password[i] = default_char
            #print("Revert, current index is", i, "Avg Time Difference:", cur_avr_time - avg_time[i - 1], "current password:", ''.join(guessed_password))
            i = max(0, i - 1)
        
        #print(guessed_password)

        # brutforce last digit, timing technique not working for this digit
        if i == password_length - 1:
            for char in charset:
                guessed_password[i] = char
                curr_pwd = ''.join(guessed_password)
                if check_password(curr_pwd):
                    # found password, fast return
                    return curr_pwd
                if char == charset[-1]:
                    # all last digit failed revert two steps
                    #print("cracked failed, try again.")
                    i -= 2
                    guessed_password[-1] = default_char
                    guessed_password[-2] = default_char
            
        

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
