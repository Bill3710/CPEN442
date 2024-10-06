'''This file contains the function to crack.
An unmodified version of this file will be used to check your code.'''
import time
import random
import base64


class Server():

    def __init__(self):
        """This simulates the user's registration in the server with a certain password, stored in self.password"""
        L = random.randint(5, 10) # random length
        random_bytes = random.getrandbits(80).to_bytes(10, 'little') # random bytes
        self.password = base64.b64encode(random_bytes).decode('ascii')[:L]

    def check_password(self, password):
        """This simulates the server checking if the provided password matches the one stored in self.password"""
        if len(password) != len(self.password):
            return False
        for i, char in enumerate(password):
            time.sleep(0.001) # protect against brute force
            if char != self.password[i]:
                return False
        return True
