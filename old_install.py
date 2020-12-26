#!/usr/bin/python3

import os
import sys
import subprocess
import re


SCRIPT_NAME = "jwt-crack.py"
REQUIREMENTS = "requirements.txt"
DEVNULL = open(os.devnull, "wb")
PATTERN = r'^uid=.+(\(.+\)*?) '
ABSOLUTE = os.getcwd() + "/" + "/".join(sys.argv[0].split("/")[0:-1]) + "/" + SCRIPT_NAME if not sys.argv[0].startswith("/") \
           else "/" + "/".join(sys.argv[0].split("/")[1:-1]) + "/" + SCRIPT_NAME
TOOLNAME = "jwtcrk"
# print(ABSOLUTE.encode()) # JUST FOR DEBUG



if __name__ == '__main__':

    if len(sys.argv) < 1 or len(sys.argv) > 2:
        print("[!] Too much or missing args. USAGE:\npython3 install.py; or\npython3 install.py all")
        sys.exit(2)

    if not os.path.exists(ABSOLUTE):
        print("[!] There is a problem with the path. If you are not in the repo directory please launch the script using its absolute path")

    if len(sys.argv) == 2 and (sys.argv[1] == "a" or sys.argv[1] == "all"):
        for_all = True
    elif len(sys.argv) == 2 and (sys.argv[1] != "a" or sys.argv[1] != "all"):
        print("[!] You can only specify 'all' as argument to install the tool for all users.")
        sys.exit(2)
    else:
        for_all = False

    id_output = subprocess.check_output("id", shell=True, stdin=DEVNULL, stderr=DEVNULL).decode()
    hasPrivileges = "27(sudo)" in id_output or os.getuid() == 0
    if not hasPrivileges:
        if for_all:
            print("[!] YOU DON'T HAVE THE REQUIRED PRIVILEGES")
            sys.exit(2)

    # COMMAND FOR ADD A SYMBOLIC LINK. IT WILL RUN INSIDE A bin/ DIR.
    add_sym_link = f"ln -s {ABSOLUTE} {TOOLNAME}"

    # INSTALL REQUIREMENTS.TXT
    pip_command = f"pip3 install -r {ABSOLUTE.replace(SCRIPT_NAME, REQUIREMENTS)}"

    if not for_all:
        subprocess.run(f"chmod u+x {ABSOLUTE}", shell=True, stdin=DEVNULL, stderr=DEVNULL)
        user = re.findall(PATTERN, id_output)[0].strip("()")
        if not os.path.exists(f"/home/{user}/"):
            # ASK USER FOR ITS HOME DIR.
            print("[*] Your home directory seems to have a different name from the user one.")
            print("[*] Please complete the path with the right directory name.")
            home = input("/home/")
            user = home.rstrip("/")

        # COMMAND TO ADD /home/<username>/bin TO THE PATH ENV VARIABLE. IT WILL RUN INSIDE THE /home/<username> DIR.
        add_var = f"echo 'export PATH=$PATH:/home/{user}/bin' >> .bashrc"

        try:
            os.chdir(f"/home/{user}")
        except FileNotFoundError:
            # IF THE USER INPUT A NON EXISTING HOME DIR.
            print(f"[!] /home/{user}/ seems to not exists...")
            sys.exit(1)
        if not os.path.exists(f"/home/{user}/bin"):
            # MAKE A BIN DIRECTORY INSIDE /home/<username>.
            os.mkdir("bin/")
        bin_paths = subprocess.check_output("echo $path", shell=True, stdin=DEVNULL, stderr=DEVNULL).split(":")
        if f"/home/{user}/bin" not in bin_paths:
            # ADD THE BIN DIR TO $PATH ONLY IF IT DOES NOT EXISTS YET
            subprocess.run(add_var, shell=True, stdin=DEVNULL, stderr=DEVNULL)
        os.chdir(f"/home/{user}/bin/")
        subprocess.run(add_sym_link, shell=True, stdin=DEVNULL, stderr=DEVNULL)
        print("[+] Successfully installed jwtcrk for your user. Now you can use 'jwtcrk <token> [OPTIONS]'")

    else:
        # TO INSTALL THE SCRIPT FOR ALL USERS.
        subprocess.run(f"chmod +x {ABSOLUTE}", shell=True, stdin=DEVNULL, stderr=DEVNULL)
        os.chdir("/usr/local/bin/")
        subprocess.run("sudo" + add_sym_link, shell=True, stdin=DEVNULL, stdout=DEVNULL)
        print("[+] Successfully installed jwtcrk for all user. Now you can use 'jwtcrk <token> [OPTIONS]'")

