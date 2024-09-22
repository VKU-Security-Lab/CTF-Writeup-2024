from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes

# Hàm mã hóa
def rc4_encrypt(key, plaintext):
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# Hàm giải mã
def rc4_decrypt(key, ciphertext):
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Ví dụ sử dụng
encrypt = (b"\xE1\x9F\xF1\x64\xCC\x36\x35\x19\xd7\x26\x3e\xf5\x52\xae\x0f\x08"
           b"\x94\xa2\x87\xfd\x7d\x8f\xb9\x53"
           b"\x12\xf7\x6a\x51\xa0\x91\x7f\x3c"
           b"\x3f\x1c\xf0\x8f\x4f\xc8")

# Chạy thử với các khóa từ 0 đến 255 để kiểm tra
for i in range(0, 100000000000000):
    key = bytes([i])  # Tạo khóa đơn byte
    d = rc4_decrypt(key, encrypt)
    if b"flag" in d:
        print(d.decode())  # In ra chuỗi khi tìm thấy "flag"
        break
