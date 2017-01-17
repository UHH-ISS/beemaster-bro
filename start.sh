#!/bin/sh

docker build . -t bro-image --build-arg PURPOSE=master
docker run --name bro-master --rm -v /var/beemaster/log/bro-master/:/usr/local/bro/logs/ -p 9999:9999 bro-image
