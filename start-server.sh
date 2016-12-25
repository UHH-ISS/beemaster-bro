#!/bin/sh

docker build . -t bro-image
docker run --name bro-container --rm -v /var/beemaster/log/bro-master/:/usr/local/bro/logs/ bro-image
