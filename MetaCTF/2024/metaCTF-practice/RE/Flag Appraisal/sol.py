data = [0x9c, 0x85, 0xb5, 0x8d, 0x12, 0xa0, 0x9b, 0x10, 0xe8, 0x1f, 0x2b, 0xb3, 0xdb, 0x4a, 0x87, 0x1e, 0x39, 0xbd, 0x03, 0x32, 0xc6, 0xd0, 0x82, 0xdb, 0xcd, 0x46, 0x82, 0xa1, 0x6d, 0x09, 0x80, 0xe5, 0x6c, 0x7f, 0x6c, 0x82, 0x91]

def unmangle(mangled, length):
    state = 0
    unmangled = ['\x00'] * length  

    for i in range(0, length - 1, 2):
        current_state = (mangled[i] | (mangled[i + 1] << 8)) 
        original_state = current_state

        for j in range(256):
            for k in range(256):
                test_state = (j * 257) ^ (k * 509) ^ (state * 33)
                if test_state & 0xffff == original_state:
                    unmangled[i] = chr(j)
                    unmangled[i + 1] = chr(k)
                    break
            else:
                continue
            break

        state = original_state
        print(original_state)

    if length % 2 != 0:
        last_char = mangled[length - 1]
        for j in range(256):
            test_state = (j * 257) ^ (state * 33)
            if test_state & 0xff == last_char:
                unmangled[length - 1] = chr(j)
                break

    return ''.join(unmangled)


unmangled = unmangle(data, len(data))
print("Unmangled:", unmangled)