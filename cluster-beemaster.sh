#!/bin/bash


##### NOTE #####
## This script should be located under /opt/ on the beemaster server,
## where the repositories of mp-ids-bro and mp-ids-hp are present in the same directory
################

NETWORK=beemaster-overlay
DIO=dionaea
SLAVE=bro-slave
MASTER=bro-master
CONNECTOR=connector

set -ea

function start {

    ## build docker images, tag them
    echo "Building docker images that are running on the host machine..."
    cd ./mp-ids-bro
    docker build . --build-arg PURPOSE=slave -t $SLAVE:latest
    docker build . --build-arg PURPOSE=master -t $MASTER:latest
    cd ../..
    echo "Docker images built"


    ## create overlay network
    echo "Creating docker overlay network, if not exists. Make sure you are in a SWARM!!!"
    if ! docker network ls|grep $NETWORK; then
        docker network create --opt encrypted --driver overlay $NETWORK
        echo "Created overlay network"
    fi

    echo "Creating docker services on this host machine ..."
    ## run three slaves
    docker service create \
        --constraint 'node.role == manager' \
        --replicas 3 \
        --network $NETWORK \
        --mount type=bind,source=/var/beemaster/log/bro-slave,destination=/usr/local/bro/logs \
        --name $SLAVE \
        $SLAVE "/bro/scripts_slave/"

    ## run a master
    docker service create \
        --constraint 'node.role == manager' \
        --replicas 1 \
        --network $NETWORK \
        --mount type=bind,source=/var/beemaster/log/bro-master,destination=/usr/local/bro/logs \
        --name $MASTER \
        $MASTER "/bro/scripts_master/"


    echo "Creating docker services on worker machine (not this machine) ..."
    ## run honeypots & connectors, make sure its _not_ on the beemaster server (which is labeled as manager)
    docker service create --constraint 'node.role != manager' --replicas 5 --network $NETWORK --name $CONNECTOR $CONNECTOR
    docker service create --constraint 'node.role != manager' --replicas 5 --network $NETWORK --name $DIO $DIO

    echo "Docker services created and spanned accross the cluster"
}

function stop {

    echo "Removing docker services..."
    docker service remove $SLAVE
    docker service remove $MASTER
    docker service remove $CONNECTOR
    docker service remove $DIO
    echo "Docker services removed accross all hosts"
}


for i in "$@"
do
case $i in
    start)
        start
    
    ;;
    stop)
        stop
    ;;
    *)
        # unknown option
    ;;
esac
done