# security

[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg?style=for-the-badge)](https://github.com/nuvlabox/security/graphs/commit-activity)
[![GitHub issues](https://img.shields.io/github/issues/nuvlabox/security?style=for-the-badge&logo=github&logoColor=white)](https://GitHub.com/nuvlabox/security/issues/)
[![Docker pulls](https://img.shields.io/docker/pulls/nuvlabox/security?style=for-the-badge&logo=Docker&logoColor=white)](https://cloud.docker.com/u/nuvlabox/repository/docker/nuvlabox/security)
[![Docker image size](https://img.shields.io/docker/image-size/nuvladev/security/main?logo=docker&logoColor=white&style=for-the-badge)](https://cloud.docker.com/u/nuvlabox/repository/docker/nuvlabox/security)

![CI Build](https://github.com/nuvlabox/security/actions/workflows/main.yml/badge.svg)
![CI Release](https://github.com/nuvlabox/security/actions/workflows/release.yml/badge.svg)

**This repository contains the source code for the NuvlaBox Security component - this microservice is responsible for performing continuous secuirty auditing on the [NuvlaBox](https://sixsq.com/products-and-services/nuvlabox/overview)**

This microservice is an integral component of the NuvlaBox Engine.

---

**NOTE:** this microservice is part of a loosely coupled architecture, thus when deployed by itself, it might not provide all of its functionalities. Please refer to https://github.com/nuvlabox/deployment for a fully functional deployment

---

## Build the NuvlaBox Security

This repository is already linked with Travis CI, so with every commit, a new Docker image is released. 

There is a [POM file](pom.xml) which is responsible for handling the multi-architecture and stage-specific builds.

**If you're developing and testing locally in your own machine**, simply run `docker build .` or even deploy the microservice via the local [compose files](docker-compose.yml) to have your changes built into a new Docker image, and saved into your local filesystem.

**If you're developing in a non-master branch**, please push your changes to the respective branch, and wait for Travis CI to finish the automated build. You'll find your Docker image in the [nuvladev](https://hub.docker.com/u/nuvladev) organization in Docker hub, names as _nuvladev/security:\<branch\>_.

## Deploy the NuvlaBox Security

### Prerequisites 

 - *Docker (version 18 or higher)*
 - *Docker Compose (version 1.23.2 or higher)*

### Launching the NuvlaBox Security

Simply run `docker-compose up --build`


## Contributing

This is an open-source project, so all community contributions are more than welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
 
## Copyright

Copyright &copy; 2021, SixSq SA


