# Contributing to jwtXploiter

There are several ways you can contribute to the project.
At the time of writing, I'm the only developer and mantainer
of the project, so all of the following will be very appreciated.

 - Reporting a bug, opening new issues
 - Discussing the current state of the code
 - Improving the documentation
 - Proposing new features, opening new issues
 - Submiting a fix (see How to Submit section)
 - Submiting an improvement (see How to Submit section)
 - Becoming a mantainer (see New Mantainers section)

All contributors will be properly credited in CHANGELOG, as soon
as next release will be published.

# How to Submit

The development of the jwtXploiter is done on the develop branch.
When develop branch is merged in main, it means that a new version
of the software is going to be released in the next hours. So, in
order to contribute, you should branch from develop, except for most
urgent hotfix, that need to be committed to main branch as far as
possible.
Branch naming follow this simple rules:
 - Fixing branches should have the prefix 'fix-'
 - Feature branches should have the prefix 'feature-'
WHEN SUBMITTING, YOU MUST KEEP THINGS SEPARATED. EACH LOGICAL
CHANGE MUST HAVE ITS OWN PATCH OR PR. e.g. IF YOU ARE FIXING AN
ISSUE AND IMPROVING A FEATURE, THIS MUST BE DONE VIA TWO DIFFERENT
PATHCES OR PRs.

#### Submit Patches

Patches can be sent to andrea.tedeschi@andreatedeschi.uno, including
a proper description with the following information (only ones that
apply):
 - closed issue
 - interested feature
 - it's a new feature
 - it's an improvement of an existing feature
 - tests you ran 
 - useful information to reproduce tests
 - any other relevant information
Be sure to:
 - self review you code
 - properly comment your code, especially in hard-to-understand areas
 - patch is not generating warnings

#### Pull Requests

PRs are also accepted, the repository provides a template to issue them.
In board terms, required informations are the ones listed for patches.

## New Mantainers

In order to become a mantainer, you won't necessary have to write code.
Main areas where help is required are:

 - Packaging: someone expert in building, deb, rpm and python packages
 - Documentation: someone who will take care of update and improve the documentation
 - General administration: someone with open source experience that provides value to the project

Hit me at andrea.tedeschi@andreatedeschi.uno
