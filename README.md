# Homomorphic Election Demo
___University of Oregon, CIS 433: Computer & Network Security (Winter 2021)___

A demonstration of how homomorphic encryption can be applied to conduct secure elections.

## Getting Started
These instructions detail how to build and launch the system with Docker for demo and testing purposes.

### Prerequisites
To run this software, you will need to make sure docker and docker-compose are installed.

On most systems, the easiest way to do this is to [get Docker Desktop](https://docs.docker.com/get-docker/).

To quickly check if/which version of docker is installed:
```
$ docker -v
```

To quickly check if/which version of docker-compose is installed:
```
$ docker-compose -v
```

### Build & Run
Once docker is installed, the project can be built and started. To quickly start the containers, simply use the `docker-compose up` command. To guarantee that new images are built, use the `--build` flag:

```
$ docker-compose up --build #build images and start containers
$ docker-compose down #stop the demo system
```

## Using the Demo
After starting the system, the landing page for the demo client can be visited in a web browser at `http://localhost:7000/panel`, which contains a menu of navigation and control items for viewing and using the demo:
- Index (`http://localhost:7000`)- A page where voters can authenticate and cast their votes
- Reset to Zero (`http://localhost:7000/new`)- resets the vote count for all candidates to zero.
- Results (`http://localhost:7000/results`) - Shows the decrypted, plaintext tally of all ballots that have been collected so far.
- Register New Voter (`http://localhost:7000/register`) - Shows the voter registration page where a voter can register to participate in the election.

## Authors
* **Patrick Higgins** -  ([phiggin5@uoregon.edu](phiggin5@uoregon.edu))
* **Jack Sanders** -  ([jsander5@uoregon.edu](jsander5@uoregon.edu))
* **Antonio Silva** -  ([antonios@uoregon.edu](antonios@uoregon.edu))
