# Get all data from ffd8ffe000 to ffd9

img = open('bg.jpg', 'rb').read()

# Find second place
start = img.find(b'\xff\xd8\xff\xe0')
second = img.find(b'\xff\xd8\xff\xe0', start+ 12)

# Find all end with ffd9
allEnd = []
ind = 2
while True:
    end = img.find(b'\xff\xd9', second + ind)
    if end == -1:
        break
    allEnd.append(end)
    ind += 2


# Get all data
for i in range(len(allEnd)):
    with open(f'img{i}.jpg', 'wb') as f:
        f.write(img[second:allEnd[i] + 2])
        
# Done
print('Done')