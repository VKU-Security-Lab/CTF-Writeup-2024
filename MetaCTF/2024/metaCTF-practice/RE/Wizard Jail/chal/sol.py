from random import *  
from Crypto.Util.number import * 

#DEFINITION
p = 0xffffffffffffffffffffffffffffffff000000000000000000000001
K = GF(p)
a = K(0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe)
b = K(0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4)
E = EllipticCurve(K, (a, b))
G = E(0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21, 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34)
E.set_order(0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d * 0x1)
with open('../dist/out.txt','rb') as f:
    ff=f.read()
exec(ff)
print(ms[0])
priv=''
for i in range(len(ms)):
    m=E(ms[i])
    c1p=E(C1s[i])
    c2p=E(C2s[i])
    d=E(decs[i])
    dd=d-m
    pp=c1p*(2^i)
    if pp==dd:
        priv+='1'
    else:
        priv+='0'
priv=int(priv[::-1],2)
print(long_to_bytes(priv))