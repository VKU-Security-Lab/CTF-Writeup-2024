from time import sleep
from machine import Pin
import rp2

KEY = b'sg\\@0\x1f\x1b]W7|fVJ*{E\x15\x13'

@rp2.asm_pio(out_shiftdir=rp2.PIO.SHIFT_RIGHT,
             in_shiftdir=rp2.PIO.SHIFT_RIGHT,
             pull_thresh=32,
             push_thresh=32,
             autopull=True,
             autopush=True)
def sm0_prog():
    set(x, 0)
    wrap_target()
    out(y, 32)
    mov(y, invert(y))
    label("2")
    jmp(y_dec, "test1")
    label("test1")
    jmp(x_dec, "2")
    mov(y, invert(y))
    mov(x, y)
    in_(y, 32)


def encrypt(data):
    sm0 = rp2.StateMachine(0, sm0_prog)
    sm0.active(1)
    enc = b""

    for char in data:
        sm0.put(char)
        enc += chr(sm0.get() & 0x7f)

    return enc

while True:
    data = bytes(input("input: "), 'latin-1')
    enc = encrypt(data)
    print(f"enc:  {enc}")
    if enc == KEY:
        print("correct!")
