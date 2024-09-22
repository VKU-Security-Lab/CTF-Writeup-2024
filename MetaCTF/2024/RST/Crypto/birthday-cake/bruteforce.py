# Bruteforce password zip with format MMDDYY

import zipfile
import os

# Path to the zip file
zip_file = 'birthdaycake.zip'

# Generate a list of all possible passwords
passwords = []
for i in range(1000000):
    password = str(i).zfill(6)
    passwords.append(password)
    
# Try each password
for password in passwords:
    try:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(pwd=bytes(password, 'utf-8'))
        print(f'Password found: {password}')
        break
    except:
        pass
    