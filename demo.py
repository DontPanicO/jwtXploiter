#!/usr/bin/python3

"""
A demo file fore test single function.
If you have an idea for a new function, or for updating an existing one, you should start from here.
Write the function in this file, test it and when it's ready to work, move it in test.py.
"""

import sys
import os
import subprocess












def x5u_basic(header):
    devnull_ = open(os.devnull, 'wb')
    download = "wget " + header['x5u']
    download_output = subprocess.check_output(command, shell=True, stdin=devnull_, stderr=devnull_)
    # Retrieve the right filename    TODO: Implement it in a better way
    for file in os.listdir():
        if file.endswith(".json"):
            filename = file
            break
    else:
        filename = header['x5u'].split("/")[-1] if header['x5u'].split("/")[-1].endswith(".json") else header['x5u'].split("/")[-2]
    with open("testing.crt", 'r') as cert_file:
        my_cert = "".join([line.strip() for line in cert_file if not line.startswith('---')])
    jwks = open(filename)
    jwks_dict = json.load(jwks)
    jwks['x5c'] = my_cert
    #change something else
    file = open("crafted/jwks.json", 'w')
    file.write(json.dumps(jwks_dict))
    devnull_.close()
    file.close()
