#!/usr/bin/python3

"""
A demo file fore test single function.
If you have an idea for a new function, or for updating an existing one, you should start from here.
Write the function in this file, test it and when it's ready to work, move it in test.py.
"""

import sys
import os
import base64
import json
import subprocess


header = {"alg": "RS256", "typ": "jwt"}

n = "something"
e = "ABaQ"
kid = "kid001"

def generate_jwk(n, e, kid):
    jwk = dict()
    jwk['kty'] = "RSA"
    jwk['kid'] = kid
    jwk['use'] = "sig"
    jwk['n'] = n
    jwk['e'] = e
    return jwk

def inject_jwk(header):
    crafted_jwk = generate_jwk(n, e, kid)
    header['jwk'] = crafted_jwk
    return header

new_header = inject_jwk(header)

print(json.dumps(new_header))
