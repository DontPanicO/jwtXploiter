# jwtCracker
A tool to crack json web token

### Installation

- Clone the repo:

  - git clone https://github.com/DontPanicO/jwtCracker.git

- Run install.sh:

  - ./install.sh (or './install.sh all' to install it for all users)

- Now you can use the script with this syntax:

  - jwtcrk <token> [OPTIONS]

### To Know

- For attacks that generates a jwks file you will find it under the crafted/ directory.

- For jku/x5u injection that needs to merge two urls (the server vulnerable url and your one), the HERE keyword is required.
- For redirect attacks the keyword should replace the redirect url, e.g.
  - http://app.com/foo?redirect=bar&some=thing  -->  http://app.com/foo?redirect=HERE&some=thing
- For jku/x5u injections via HTTP header injection attacks, the HERE keyword sould be appended to the vulnerable parameter,
  without replacing its value, e.g.
  - http://app.com/foo?param=value  -->  http://app.com/foo?param=valueHERE
- Also, in such cases, be sure to pass the server url and your one as comma separated values.

- Look at the docs for more detailed examples.
