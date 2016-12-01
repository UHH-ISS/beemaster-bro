#!/bin/sh
docker run -v /var/log/bro-master/:/usr/local/bro/logs/ -p 9999:9999 bro-container
