# jwtCracker
A tool to crack json web token

### Installation

- Clone the repo:

  - git clone https://github.com/DontPanicO/jwtCracker.git

- Run install.sh

  - ./install.sh

- At this point if the installation script failed to give executive permission to jwt-crack.py

  - chmod +x (or u+x) jwt-crack.py

### To Know

- For attacks that generates a jwks file you will find it under the crafted/ directory.

- For advanced jku/x5u injection, the HERE keyword is required.
- For redirect attacks the keyword should replace the redirect url, e.g.
  - http://app.com/foo?redirect=bar&some=thing  -->  http://app.com/foo?redirect=HERE&some=thing
- For jku/x5u injections viaHTTP header injection attacks, the HERE keyword sould be appended to the vulnerable parameter,
  without replacing its value, e.g.
  - http://app.com/foo?param=value  -->  http://app.com/foo?param=valueHERE

- Look at the docs for more detailed examples.
