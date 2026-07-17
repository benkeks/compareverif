# Using the Artifact of CompareVerif

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

## Running unit tests

The code base's unit tests can be started by:

```
docker run compareverif python3 -m pytest
```

## Reproducing results

All the figures of the paper can be reproduced by running the script `reproduce-results.sh` in the root of the artifact.

```
bash ./reproduce-results.sh
```

(As mentioned in the paper, the scripts should run virtually instantaneous for this problem size on common machines. At least, they do, on our laptops.)

## Checking other claims

If you want to check the file output of scenario preprocessing described by Section 4.1, you can inspect it interactively like this:

```
docker run compareverif -i python3 scenario_preprocessor.py examples/hashed_passwords_paper.pv
# in the container
cd _scenarios
ls -l
less manifest.json
# [... more less or more ...]
exit
```

At the beginning of Section 4, we claim that our input format works well with the VS Code extension for ProVerif. To verify, you can install it TODO: add links and open, for instance, examples/hashed_passwords_paper.pv. Note that we work with a matching input format for magical `-lib` comments to describe imports.

## Reusability illustration

As an other example of applying our tool beyond the ones used in the paper, we provide `examples/_simple_ratchet.pv` and a Jupyter notebook in `notebooks/exhaustive_generation_of_AG_simple_ratchet.ipynb` that examines interesting attack scenarios on a simple ratchet scheme of message exchange. You can examine its attack Pareto front (for the dimensions TODO: X and Y) by:

```
docker run compareverif -i python3 scenario_preprocessor.py examples/simple_ratchet.pv
```

Also, `singularized_passwords_no_elgamal.pv` presents a variation on the paper case study about singularization (Section 5). In this version of the protocol, the password communication between application and singularization server has no ElGamal encryption layer. This leads to a situation, where a compromised singularization server can leak the user password. To see that this induces a slightly lower Pareto front in our pricing scheme, you can run:

```
docker run compareverif -i python3 scenario_preprocessor.py examples/singularized_passwords_paper.pv examples/singularized_passwords_no_elgamal.pv
```

## Cleaning up

To remove the image from your system, enter:

```
docker image rm compareverif
```

To clean up all the stopped containers (**IF YOU HAVE NO OTHER IMPORTANT STOPPED CONTAINERS!**), you can run `docker container prune`.