#! /bin/bash

# The following commands spins-up a container using the panther-deployment-pack image, which has
# the working directory mounted under /code, uses the same docker daemon as the host machine, has
# access to the host machines AWS_XXX related variables (with AWS_REGION having AWS_DEFAULT_REGION
# as a fallback value), runs in interactive mode and makes sure not to store any container after
# it's  run, so that the temporary credentials don't persist in an environment

docker run \
    -v $(pwd):/code \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_PARTITION \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN \
    -e AWS_SECURITY_TOKEN \
    -e AWS_REGION=$(if [ -z "$AWS_REGION" ]; then echo $AWS_DEFAULT_REGION; else echo $AWS_REGION; fi) \
    -it \
    --rm \
    pantherlabs/panther-development-pack:1.15.0
