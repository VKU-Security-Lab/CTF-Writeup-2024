# find hex byte ffd8ffe000104a4649 in file image

img = open('bg.jpg', 'rb').read()

# convert image to hex
hex_img = img.hex()
# find hex byte ffd8ffe000104a4649 second in file image

second = hex_img.find('ffd8ffe0', hex_img.find('ffd8ffe0') + 1)
print(second)
# find all ffd9 bytes
for i in range(274492, len(hex_img), 2):
    with open(f"flag{i}.jpg", 'wb') as f:
        f.write(bytes.fromhex(hex_img[second:i+2]))