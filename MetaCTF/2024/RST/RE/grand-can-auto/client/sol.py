from Cryptodome.Cipher import ARC4


def decode_s5():
    encrypted_s5 = [0x5A, 0x5B, 0x0B, 0x0A, 0x5E, 0x5F]
    s5 = ''.join([chr(c ^ 0x69) for c in encrypted_s5])
    return s5


def find_s4(s5):
    encrypted_values = [0x05, 0x01, 0x06, 0x5B, 0x05, 0x02]
    s4 = ''.join([chr(ord(s5[i]) ^ encrypted_values[i])
                 for i in range(len(s5))])
    return s4


def decrypt_rc4(key, ciphertext):
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def find_s1(s2, encrypted_values):
    s1_bytes = []
    for i in range(len(s2)):
        s2_char = ord(s2[i])
        encrypted_value = encrypted_values[i]
        s1_byte = (encrypted_value - s2_char) % 256
        s1_bytes.append(s1_byte)
    return bytes(s1_bytes)


def find_s0(s3, encrypted_values):
    s0_bytes = []
    for i in range(len(s3)):
        s3_char = ord(s3[i])
        encrypted_value = encrypted_values[i]
        s0_byte = (encrypted_value + s3_char) % 256
        s0_bytes.append(s0_byte)
    return bytes(s0_bytes)


def main():
    s5 = decode_s5()
    print("S[5] =", s5)
    encrypted_values_s4 = [0x05, 0x01, 0x06, 0x5B, 0x05, 0x02]
    s4 = find_s4(s5)
    print("S[4] =", s4)
    key = (s4 + s5).encode()
    ciphertext = bytes([0x60, 0xE0, 0xE4, 0x2D, 0xFF, 0x97,
                       0xDD, 0x13, 0xEE, 0xA0, 0x55, 0xF4])
    plaintext = decrypt_rc4(key, ciphertext)
    print("Plaintext:", plaintext)
    s2s3 = plaintext.decode()
    s2 = s2s3[:6]
    s3 = s2s3[6:]
    print("S[2] =", s2)
    print("S[3] =", s3)
    encrypted_values_s1 = [0x95, 0xC8, 0x95, 0x9D, 0x69, 0x68]
    s1_bytes = find_s1(s2, encrypted_values_s1)
    try:
        s1 = s1_bytes.decode('utf-8')
    except UnicodeDecodeError:
        s1 = s1_bytes.hex()
    print("S[1] =", s1)
    encrypted_values_s0 = [0x01, 0xFA, 0x06, 0xD2, 0xFF, 0xCE]
    s0_bytes = find_s0(s3, encrypted_values_s0)
    try:
        s0 = s0_bytes.decode('utf-8')
    except UnicodeDecodeError:
        s0 = s0_bytes.hex()
    print("S[0] =", s0)
    flag = f"ASCIS{{{s0}-{s1}-{s2}-{s3}-{s4}-{s5}}}"
    print(flag)


if __name__ == '__main__':
    main()
