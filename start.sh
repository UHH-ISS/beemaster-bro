#!/bin/sh

docker build . -t bro-image
docker run --name bro-container --rm -a stderr -a stdout -v /var/log/bro-master/:/usr/local/bro/logs/ -p 9999:9999 bro-image
