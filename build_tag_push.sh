#!/usr/bin/env bash

docker build -t rotor:latest .
docker tag rotor:latest nutanix-docker-local.jfrog.io/rotor:latest
docker push nutanix-docker-local.jfrog.io/rotor:latest
