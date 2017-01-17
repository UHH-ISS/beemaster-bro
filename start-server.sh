#!/bin/sh

docker build . -t bro-image --build-arg PURPOSE=master
docker run --name bro-master --rm -v /var/beemaster/log/bro-master/:/usr/local/bro/logs/ bro-image