encrypted_flag = "\xD9\xD6\xD2\xD0\xCB\x87\x8C\xD5" +"\x8F\x83\x8E\xDB\x8B\x86\xD1\xDA"+"\x8D\xD5\x8E\xD3\x87\xD9\x8B"+"\x84\xD2\xD9\x88\x8A\xD4\x86\xDA\xD9"+"\xD0\xD2\x89\x8D\xDC\xCE"
f = "admin"
ff = ""
for i in range(0, len(f)):
    ff += chr(ord(f[i]) ^ 0xDE)
print(ff)
flag = ""
for i in range(0, len(encrypted_flag)):
    v16 = ord(encrypted_flag[i])
    flag += chr(ord(ff[i % 5]) ^ v16)

print(flag)