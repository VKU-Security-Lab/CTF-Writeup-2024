from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import long_to_bytes

def decrypt(ciphertext, private_key):
    # Tạo một đối tượng để giải mã RSA sử dụng OAEP padding
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted_message = decryptor.decrypt(ciphertext)
    return decrypted_message

if __name__ == "__main__":
    # Đọc khóa bí mật từ file
    private_key = RSA.import_key(open("pub.pem").read())
    
    # Đọc ciphertext từ file
    ciphertext = open("flag.txt.enc", "rb").read()
    
    # Giải mã ciphertext
    decrypted_message = decrypt(ciphertext, private_key)
    
    # In ra thông điệp đã giải mã
    print(decrypted_message.decode())
