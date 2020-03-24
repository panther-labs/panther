# Troubleshooting Panther

This section acts as a quick Q&A on issues that you may face during your Panther deployment.

> My deployment timed out

Don't worry. You can safely re-deploy Panther by running `mage deploy` and it will pick up where it
left off. Alternatively, if you 're using temporary credentials, please add a longer timeout

> My deployment failed with `open deployments/bootstrap.yml: no such file or directory`

This is an issue with Docker and the way volumes work. To resolve that, please step close the container
(Ctrl+D on Mac) and reconnect to it by typing `./dev.sh` so that the container can pick
up all the necessary files. Running `mage deploy` again won't present the same issue

> I mistyped my email during `mage deploy` and I can't login
 
Don't worry, these things happen. Simply go to Cognito and create a new user through the console, by
specifying all the necessary fields.
