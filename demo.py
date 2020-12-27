#!/usr/bin/python3

"""
A demo file fore test single function.
If you have an idea for a new function, or for updating an existing one, you should start from here.
Write the function in this file, test it and when it's ready to work, move it in test.py.
"""

import sys
import urllib.parse


def url_escape(string, chars, spaces=True):
    """
    :param string: The string to url encode
    :param chars: The only chars you want to escape

    From a given string, the fucntions url encode only the carachters specified in the chars parameter.
    By default, the space character is automatically appended to the chars string. You can disable this behaviour,
    setting spaces=False.

    return: The original string with the specified characters url encoded
    """
    if " " not in chars and spaces:
        chars += " "
    encoded = [urllib.parse.quote(char) for char in chars]
    for i in range(len(chars)):
        string = string.replace(chars[i], encoded[i])
    return string


if __name__ == '__main__':

    final = url_escape('{"keys": [{"kty": "jwks", "e": "abaq", "alg": "rsa"}]}', "[]{}")
    print(final)
