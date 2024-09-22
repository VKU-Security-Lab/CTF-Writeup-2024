data = open('data.txt', 'r')

data = data.read()

data = data.split('.')

new_data = []

for i in data:
    if len(i) > 2:
        new_data.append(i)
        
join_data = ''.join(new_data)
# 1054720
import base64

data = base64.b64decode(join_data)

with open('enc.tar.gz', 'wb') as f:
    f.write(data)
    
