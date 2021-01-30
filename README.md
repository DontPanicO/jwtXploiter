# jwtXploiter
A tool to test the security of json web token.
The tool is under development, plese open issues when you run into errors.

[![Python 3.7|3.9](https://img.shields.io/badge/python-3.7|3.9-blue.svg)](https://www.python.org/) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-red.svg)](https://www.gnu.org/licenses/gpl-3.0)

### Wiki
[Beta wiki](https://github.com/DontPanicO/jwtXploiter/wiki)

### Install with rpm

- Download the rpm package:
  - wget http://andreatedeschi.uno/jwtxploiter/jwtxploiter-1.0-1.noarch.rpm

- Install:
  - sudo rpm --install jwtxploiter-1.0-1.noarch.rpm

### Install using git
N.B. This options should be used only for development purposes.

- Clone the repo:
  - git clone https://github.com/DontPanicO/jwtXploiter.git

- Run installation script:
  - ./install.sh      (Install for the current user only)
  - ./install.sh all  (Install for all users)

### Install with dpkg

A DEBIAN PACKAGE WILL BE RELEASED SOON.

### Who this tool is written for?

- Web Application Penetration Tester / Bug Bounty Hunters

  - This tool has been written with the aim of become a key part of pentesters toolkit.

- Devs who need to test the secuirty of JWTs used in their applications

- CTF Players

- Not For Students

  - Since this tool automates lot of stuff, without force the user to know what's happening under the hood, it won't
    help you to understand the vulnerabilities it exploits.

### To Know

- For attacks that generates a jwks file, you could find it in the current working directory. Remeber to deletes such files
  in order to avoid conflicts.

- For jku/x5u injection that needs to merge two urls (the server vulnerable url and your one), the HERE keyword is required.
- For redirect attacks the keyword should replace the redirect url, e.g.
  - http://app.com/foo?redirect=bar&some=thing  -->  http://app.com/foo?redirect=HERE&some=thing
- For jku/x5u injections via HTTP header injection attacks, the HERE keyword sould be appended to the vulnerable parameter,
  without replacing its value, e.g.
  - http://app.com/foo?param=value  -->  http://app.com/foo?param=valueHERE
- Also, in such cases, be sure to pass the server url and your one as comma separated values.

- '/.well-known/jwks.json' is automatically appended to your url in jku/x5u attacks. So make sure to place the jwks file under
  this path on your server.
- If you don't want that happen, use the --manual option, but this option is compatible only with --jku-basic and --x5u-basic
  so, you will need to manually craft the url and pass it to those options, even for attacks that exploit Open Redirect or
  HTTP header injection.

- Look at the docs for more detailed examples.
