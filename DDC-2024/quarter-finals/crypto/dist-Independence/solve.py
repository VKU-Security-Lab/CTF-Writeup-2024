from Crypto.Util.number import long_to_bytes

with open('out.txt', 'r') as f:
    data = f.read()


pub = (5464549774190809852923763408523051958716400587576327799474715226373287205246183801056700913652415087121976663782311766735601091617825037804761387911068511, 9581257592556018473305786754018994054986440370491067910997313283399579058244765977967617476919486211692103485121526918608638896652486174462300514168144287)
g, q = pub
# Extract the encrypted message
bin_flag=[]
out_start = data.find('out = ') + len('out = ')
c = eval(data[out_start:])
for cipher in c:
    c1, c2 = cipher
    if pow(c2,(q-1)//2, q) == 1:
        bin_flag.append(0)
    else:
        bin_flag.append(1)

m = 0
for bit in reversed(bin_flag):
    m = (m << 1) | bit

flag = long_to_bytes(m)
print(flag.decode('utf-8'))