# Đảm bảo bạn đang chạy mã này trong môi trường SageMath

from sage.all import *
import hashlib

# Các giá trị đã cho trong thử thách
p = 91725037968177304595356229847249124275634668177296814741529573801095034173523

# Tọa độ điểm X
x1 = 70531110072509298803201621415592601393387767551616451246154013182556851771153
y1 = 3128592393207593101775747511252725036748347188549955655359151644135290113924

# Tọa độ điểm Y
x2 = 58557423359848065299975326112549968009731308453890093788309799350030839061814
y2 = 75706164316220403423610626861470333353921225390662051210752341134842694488677

# Tính toán y1^2 - x1^3 mod p
rhs1 = (y1**2 - x1**3) % p

# Tính toán y2^2 - x2^3 mod p
rhs2 = (y2**2 - x2**3) % p

# Tính toán A = (rhs1 - rhs2) / (x1 - x2) mod p
# Sử dụng inverse_mod để tìm nghịch đảo của (x1 - x2) mod p
A = (rhs1 - rhs2) * inverse_mod(x1 - x2, p) % p

# Tính toán B = (rhs1 - A * x1) mod p
B = (rhs1 - A * x1) % p

print(f"A = {A}")
print(f"B = {B}")

# Định nghĩa đường cong elliptic với các hệ số A và B đã tìm được
E = EllipticCurve(GF(p), [A, B])

# Định nghĩa các điểm X và Y trên đường cong
X = E(x1, y1)
Y = E(x2, y2)

# Tính toán J-invariant của đường cong
j_E = E.j_invariant()
print(f"J-invariant (j_E) = {j_E}")

# Tính toán S = j_E * (X + Y)
# Thực hiện phép cộng các điểm và sau đó nhân với j_E
S = j_E * (X + Y)

# Lấy hoành độ x của điểm S
s_x = S.xy()[0]
print(f"S.x = {s_x}")

# Tạo flag bằng cách mã hóa hoành độ x bằng MD5
flag = "flag{" + hashlib.md5(str(s_x).encode()).hexdigest() + "}"
print(f"Flag: {flag}")
