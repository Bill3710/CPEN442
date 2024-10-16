"""Grades the programming question of A4."""
from a4 import online_attack
from authentication_server import Server
from time import time

def test_q41():
    server = Server()
    print(server.password)
    pwd = online_attack(server.check_password)
    print(f"Guessed pwd: {pwd}")
    print(f"True pwd length: {len(server.password)}")
    print(f"True pwd: {server.password}")
    return len(pwd) == len(server.password)

if __name__ == "__main__":

    nreps = 1
    n_success = 0
    t0 = time()
    for i in range(nreps):
        if test_q41():
            n_success += 1
        print(f" **** Done rep {i} ({time()-t0:.1f} secs)")
    print(f"Success rate is {n_success/nreps*100:.2f}%, avg time per password is {(time()-t0)/nreps:.1f} secs")
