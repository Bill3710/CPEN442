import base64
import random
from random import randbytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad



class ServerCTR():

    def __init__(self, seed: int = 0):
        random.seed(seed)
        self.key = randbytes(AES.block_size)
        self.iv = randbytes(AES.block_size // 2)
        self.server_code = base64.b64encode(randbytes(24)).decode('ascii')

    def generate_guest_token(self, name: str, pwd: str) -> bytes:
        """Receives name and password strings, and returns an encrypted user token. It does not accept & nor = characters for the name or password"""
        name = name.replace('&','').replace('=','') # remove '&' and '=' characters
        pwd = pwd.replace('&','').replace('=','') # remove '&' and '=' characters
        token = f'name={name}&pwd={pwd}&role=guest&code={self.server_code}' # generate token
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.iv)
        return cipher.encrypt(token.encode('ascii'))
    
    def read_token(self, enc_token: bytes, pwd: str):
        """Receives an encrypted token and a password. It checks that the received password is the same as the password in the token and, if so, it prints out the role stored in the token."""
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.iv)
        token = cipher.decrypt(enc_token).decode('ascii')
        data = {kv.split('=')[0]: kv.split('=')[1] for kv in token.split('&')}
        assert 'pwd' in data
        assert 'role' in data
        assert 'code' in data
        if data['pwd'] != pwd:
            print("Incorrect password")
        elif data['code'] != self.server_code:
            print("Incorrect server code")
        else:
            print(f"Your role is {data['role']}")
        



class ServerECB():

    def __init__(self, seed: int = 0):
        random.seed(seed)
        self.key = randbytes(AES.block_size)
        self.server_code = base64.b64encode(randbytes(24)).decode('ascii')

    def generate_guest_token(self, name: str, pwd: str) -> bytes:
        """Receives name and password strings, and returns an encrypted user token."""
        token = f'name={name}&pwd={pwd}&role=guest&code={self.server_code}' # generate token
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(pad(token.encode('ascii'), AES.block_size))
    