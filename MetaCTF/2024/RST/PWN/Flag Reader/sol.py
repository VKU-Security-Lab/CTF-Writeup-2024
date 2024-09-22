#!/usr/bin/python3

from pwn import *

# Set up pwntools for the correct architecture
context.binary = exe = ELF("./reader", checksec=False)

p = process(exe.path)



p.interactive()