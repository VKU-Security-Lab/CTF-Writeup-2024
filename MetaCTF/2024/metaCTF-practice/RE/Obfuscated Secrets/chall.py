# METACTF FLAG CHECKER

# This program asks the user for a flag and responds with whether
#   the flag they entered is correct or incorrect.

# Decrypt
def decrypt():
    encrypted = "Lcq]>N?s]bV[R[_OaScQ]]NGPYDKDNG]"
    
    decrypted = ""
    for i in range(len(encrypted)):
        decrypted += chr(ord(encrypted[i]) + 1 + i)
    return decrypted

print(decrypt())

# Receive input
entered_flag = input("Please enter the flag: ")

# Function to validate flags
def validate_flag(flag):
    # Some random string we need. The program doesn't seem to work without it Â¯\_(ãƒ„)_/Â¯
    encrypted = "Lcq]>N?s]bV[R[_OaScQ]]NGPYDKDNG]"
    # Check if length matches
    if len(flag) != len(encrypted): return False
    # Check if entered flag is correct
    return all([ord(flag[i]) - 1 == ord(encrypted[i]) + i for i in range(len(encrypted))])

# Print results
if validate_flag(entered_flag):
    print("Congrats! Your flag is correct.")
else:
    print("Sorry, your flag is incorrect. Please try again.")
