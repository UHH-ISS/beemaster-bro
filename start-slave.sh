#!/bin/sh

docker build . -t slave --build-arg PURPOSE=slave
docker run -p 9991:9991 --name sl --rm -e SLAVE_PUBLIC_PORT=9991 -e SLAVE_PUBLIC_IP=127.0.0.1 -e MASTER_PUBLIC_PORT=9999 -e MASTER_PUBLIC_IP=172.17.0.1 slave