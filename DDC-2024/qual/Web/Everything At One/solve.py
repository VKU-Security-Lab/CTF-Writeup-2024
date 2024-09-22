import requests
import base64

# Fuzz thì thấy có 169 trang từ 1 đến 168 với format là https://digitaldragonsctf-everything-at-once.chals.io/{i}.html
# Mỗi trang sẽ có title chứa một ký tự trong flag được encode bằng base32 -> base64 -> hex
# Để lấy flag thì ta cần lấy hết các ký tự trong title của các trang từ 1 đến 168

enc_flag = ""

for i in range(1, 169):
    response = requests.get(f"https://digitaldragonsctf-everything-at-once.chals.io/{i}.html")
    title = response.text.split("<title>")[1].split("</title>")[0]
    enc_flag += title
    print(f"Page {i}: {title}, Encoded flag: {enc_flag}")
    
print("Encrypted flag:", enc_flag)

# Decode base32 
enc_flag = base64.b32decode(enc_flag)
print("Decoded base32:", enc_flag)

# Decode base64
enc_flag = base64.b64decode(enc_flag)
print("Decoded base64:", enc_flag)

# Decode hex
flag = bytes.fromhex(enc_flag.decode())
print("Flag:", flag)
