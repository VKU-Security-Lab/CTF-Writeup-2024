def invert(bits):
    return bits ^ 0xFFFFFFFF

def sm0_simulation(data):
    y = 0
    x = 0
    output = []

    for byte in data:
        y = byte
        y = invert(y)
        while True:
            if y != 0:
                y -= 1 
            else:
                break
            if x != 0:
                x -= 1 
            else:
                break
        y = invert(y)
        x = y
        output.append(chr(x & 0x7F))
    
    return ''.join(output)

flag = b"rstcon{"
KEY = b'sg\\@0\x1f\x1b]W7|fVJ*{E\x15\x13'

wordlist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}"
while True:
    for i in wordlist:
        data = flag + i.encode()
        encrypted_data = sm0_simulation(data)
        if encrypted_data in KEY.decode():
            flag += i.encode()
            print(flag.decode())
            if flag[-1] == b'}':
                print(flag.decode())
                exit()
            break

        