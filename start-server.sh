#!/bin/sh

docker build . -t bro-master --build-arg PURPOSE=master
docker run --name bro-master --rm -v /var/beemaster/log/bro-master/:/usr/local/bro/logs/ bro-master "/bro/scripts_master/"