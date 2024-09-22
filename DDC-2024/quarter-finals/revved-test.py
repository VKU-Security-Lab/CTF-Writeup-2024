import math

def rc4(key, data):
    # Định nghĩa hàm RC4 cho mã hóa/giải mã
    # Tham khảo: https://en.wikipedia.org/wiki/RC4
    key = bytearray(key)
    data = bytearray(data)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    out = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[k] = data[k] ^ S[(S[i] + S[j]) % 256]
    return bytes(out)

username_entry = "Hacker"
serial_entry = "123"

username = username_entry
entered_serial = serial_entry

# Tạo mảng len tương tự như trong mã C
len_arr = [0] * 12
len_arr[8] = 0
len_arr[0] = len(username)

# Tính toán giá trị cho len_arr[4]
for i in range(len(username)):
    v16 = math.pow(ord(username[i]), i + 2)
    v17 = len_arr[4] if len_arr[4] >= 0 else (len_arr[4] & 1) + (len_arr[4] >> 1) * 2
    v18 = v17 + v16
    if v18 >= 9.223372036854776e18:
        len_arr[4] = int(v18 - 9.223372036854776e18) ^ 0x8000000000000000
    else:
        len_arr[4] = int(v18)

user_serial = int(entered_serial) if entered_serial.isdigit() else 0
print("data", len_arr[4])
# Kiểm tra điều kiện và thiết lập text của result_label
if len_arr[4] == user_serial and username == "Hacker":
    encrypted_string = (
        b"\x19\x35\x36\xCC\x64\xF1\x9F\xE1"
        b"\x80\xFA\xE5\x2F\x53\xE2\x6D\x7F"
        b"\x53\xB9\x8F\x7D\xFD\x87\xA2\x94"
        b"\x3C\x7F\x91\xA0\x51\x6A\xF7\x12"
        b"\xC8\x4F\x8F\xF0\x1C\x3F\x7F"
    )
    decrypted_string = rc4(entered_serial.encode(), encrypted_string).decode()
    print(decrypted_string)
elif len_arr[4] != user_serial or username != "Hacker":
    print("Incorrect!")
else:
    print("Correct! But not a 'Hacker'")

