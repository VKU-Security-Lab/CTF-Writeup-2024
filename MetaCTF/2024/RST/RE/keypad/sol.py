

def xor_encrypt(a1, a2):
    v5 = len(a1)
    for i in range(v5):
        a1[i] = a1[i] ^ a2[i % len(a2)]
    return a1

def xor_decrypt(a1, a2):
    return xor_encrypt(a1, a2)

a2 = [ord(i) for i in "power"]
a1 = [0x4,0x13,0x1D,0x09,0x13,0x0E,0x00]

s = xor_decrypt(a1, a2)
s = "".join([chr(i) for i in s])

s1 = [ord(i) for i in s]

enc = xor_encrypt(s1, a2)

for i in enc:
    print(hex(i), end=",")