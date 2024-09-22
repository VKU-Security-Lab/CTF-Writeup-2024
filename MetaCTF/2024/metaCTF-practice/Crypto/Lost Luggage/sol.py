import itertools
import string
import zipfile


z = zipfile.ZipFile("luggage.zip")

def bruteforce():
    for guess in range(10_000):
        guess = f"{guess:04}".encode()
        try:
            z.extract("flag.txt", pwd=guess)
            return guess.decode()
        except Exception:
            ...

print(bruteforce())