#!/bin/sh

docker build . -t master --build-arg PURPOSE=master
docker run -p 9999:9999 --name ma -e MASTER_PUBLIC_PORT=9999 -e MASTER_PUBLIC_IP=172.17.0.1 --rm master