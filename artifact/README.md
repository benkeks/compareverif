# Using the Artifact of the CompareVerif

## Starting up

The only prerequisites for this walk-through are Docker and Bash.
(Tested on Debian GNU/Linux 14 (forky), Docker version 28.5.2.)

Load the image and start:

```
docker load < compareverif-docker.tar.gz
```

## Using the artifact

You can now run CompareVerif scripts with the prefix `docker run compareverif python3`. For example, to look for minimal attacks on the example file `examples/hashed_passwords_paper.pv`, enter:

```
docker run compareverif python3 scenario_preprocessor.py examples/hashed_passwords_paper.pv
```

## Reproducing results

All the figures of the paper can be reproduced by running the script `reproduce-results.sh` in the root of the artifact.

```
bash ./reproduce-results.sh
```

## Cleaning up

To remove the image from your system, enter:

```
docker image rm compareverif
```

To clean up the stopped containers (**IF YOU HAVE NO OTHER IMPORTANT STOPPED CONTAINERS!**):

```
docker container prune
```