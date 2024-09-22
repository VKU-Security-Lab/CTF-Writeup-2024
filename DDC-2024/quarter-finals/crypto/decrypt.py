from Crypto.Util.number import *
import ast
import sys

def decrypt(c, pubkey, privkey):
    g, p = pubkey
    x, _ = privkey
    h = pow(g, x, p)

    m = 0
    bit_position = 0

    for (c1, c2) in c:
        # Compute y such that pow(h, y, p) == c2
        # We use logarithms to find y. Note: This part is simplified for the illustration.
        # In practice, you might use more advanced methods or libraries to solve discrete logs.
        y = (mod_inverse(c1, p) * c2) % p

        # Extract the least significant bit of y
        bit = y & 1
        m |= (bit << bit_position)
        bit_position += 1

    return long_to_bytes(m)

def main():
    with open('out.txt', 'r') as f:
        pub_key_line = f.readline().strip()
        out_line = f.readline().strip()

    pubkey = ast.literal_eval(pub_key_line.split('=')[1])
    c = ast.literal_eval(out_line.split('=')[1])

    # Assuming we don't have privkey, which is needed for the correct decryption in real-world cases
    # Here we assume privkey to be known or guessed for simplicity
    privkey = (b"digitaldragonctf", pubkey[1])  # Replace 'your_private_key_here' with the actual private key

    # Decrypt
    decrypted_message = decrypt(c, pubkey, privkey)
    print(f'Decrypted message: {decrypted_message.decode()}')

if __name__ == "__main__":
    main()
