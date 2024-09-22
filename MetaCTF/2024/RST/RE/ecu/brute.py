#!/usr/bin/python3

# Run ecu_lockdown on all possible keys

import os

# Gen key have format 2 chars and a-z0-9A-Z_
wordlist = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-!@#$%^&*()_+=-,.?/<>;:[]{}|"


for i in wordlist:
    for j in wordlist:
        for k in wordlist:
            key = i + j + k
            payload = './ecu_lockdown "RSTCON{Nuclear' + key +'owered}"'
            print("[!] Payload" + payload)
            
            # Write output to file
            os.system(payload + " >> output.txt")

