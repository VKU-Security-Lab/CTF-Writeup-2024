# pip install sympy
from sympy import symbols, Eq, solve

# Định nghĩa các biến
v4, v22, v23, v15, v39, v12, v36, v26, v27, v32, v10, v16, v28, v14, v24, v17, v13, v33, v42, v34, v21, v35, v31, v18, v37, v25, v19, v30, v20, v40, v41, v11, v38, v29 = symbols('v4 v22 v23 v15 v39 v12 v36 v26 v27 v32 v10 v16 v28 v14 v24 v17 v13 v33 v42 v34 v21 v35 v31 v18 v37 v25 v19 v30 v20 v40 v41 v11 v38 v29')

# Ở đây các biến s v6, v7, v8, v9 được gán giá trị tương ứng với mã ASCII của các ký tự 'f', 'l', 'a', 'g', '{'
s = 102
v6 = 108
v7 = 97
v8 = 103
v9 = 123

equations = [
    Eq(v22 + v23 + s + v15 - v39, 208),
    Eq(v12 + v36 + v26 - v27 + v32, 197),
    Eq(v10 + v16 - v28 - v14 + v6, 150),
    Eq(v28 + v22 + v24 - v17 - v9, -61),
    Eq(v27 + v13 + v33 - v28 - v10, 139),
    Eq(v24 + v39 + v17 - v33 + v42, 330),
    Eq(v34 + v15 + v26 + v27 - v12, 153),
    Eq(v21 + v35 + v31 - v8 - v18, 91),
    Eq(v37 + v17 + v25 + v19 + v15, 408),
    Eq(v30 + v20 - v33 - v17 - v21, -46),
    Eq(v13 + v6 - v11 - v8 + v32, 154),
    Eq(v32 + v8 - v40 - v6 - v34, -18),
    Eq(v31 + v37 + v7 - v13 - v35, 50),
    Eq(v34 + v31 + v17 - v13 - v36, 58),
    Eq(v24 + v18 + v20 - v37 + v32, 203),
    Eq(v10 + v25 - v42 - v9 + v12, -44),
    Eq(v24 + v37 + v39 - v19 + v6, 259),
    Eq(v27 + v42 + v39 - v40 - v13, 163),
    Eq(v37 + v22 + v19 + v30 + v40, 414),
    Eq(v15 + v11 + v26 + v10 + v9, 327),
    Eq(v34 + v30 + v41 - v20 - v27, 12),
    Eq(v16 + v29 - v40 - v22 - v13, -51),
    Eq(v13 + s - v40 - v41 - v24, 38),
    Eq(v36 + v32 + v9 + v39 - v7, 268),
    Eq(v30 + v14 - v23 - v39 + v29, 22),
    Eq(v8 + v23 + v39 - v25 - v7, 150),
    Eq(v14 + v24 - v27 - v40 + v22, 11),
    Eq(v6 + v9 - v34 - v16 + v29, 132),
    Eq(s + v15 - v17 - v10 - v34, -54),
    Eq(v20 + v18 - v25 - v40 - v13, -55),
    Eq(v39 + v8 - v42 - v38 + v34, 72),
    Eq(v20 + v41 + v17 - v18 - v27, 106),
    Eq(v17 + v39 - v36 - v34 - v26, 48),
    Eq(v12 + v33 - v13 - v11 + v9, 123)
]

solution = solve(equations, dict=True)

print("flag{", end="")

if solution:
    for sol in solution:
        for var in sol:
            print(chr(sol[var]), end="")
else:
    print("Hệ phương trình không có nghiệm.")
