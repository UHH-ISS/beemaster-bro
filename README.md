# Beemaster Bro IDS Komponenten

The opensource IDS [Bro](https://www.bro.org) is widely used within the Beemaster project. Bro plays a very central role, as communication and network analysis core. Bro is integrated into Beemaster in a containerized sense, featuring a variadic cluster design and different roles.

## Bro Infrastructure & Role allocation

By design, there has to be at least one Bro instance: the Master instance. Additionally, numerous Bro slave instances my be added freely. The master instance is responsible for cluster management and coordination. It can be seen as the Beemaster core. All bro slave instances, honeypot-connectors[^1] as well as ACUs[^2] must register themselves to the master. Thus, the master must be reachable for all those components (either via IP or hostname). That may as well be done via subnet reachability, as long as all components share the same network.


##### Bro master tasks

- Logging. Logfiles may then be processed by the CIM[^3]
- Management of registered components, routing table & load-balancing of honeypots <-> bro slaves
- Tunneling of slave events to registered ACUs (via Broker multihop)
- Handling of honeypot events (fallback in case no slaves are registered)

##### Bro slave tasks

- Handling of honeypot events
- Network monitoring of the hostsysten / container on which the slave is running
- Forwarding of all possible events to the Bro master instance


## Local installation of Bro

The [official docs](https://www.bro.org/development/projects/deep-cluster.html) contain all necessary details for a manual installation.

For the Beemaster project, dedicated git branches for Bro and Broker have to be used. The following commands will checkout and install all project-relevant sources:

~~~~
git clone --recursive https://github.com/bro/bro
cd bro
git checkout topic/mfischer/deep-cluster
git submodule update
git checkout 3b46716 # pinned version for Beemaster
cd aux/broker
git checkout topic/mfischer/broker-multihop
cd ../..

./configure --with-python=/usr/bin/python2
make
sudo make install
~~~~

In case ```python``` is referencing ```python2``` by default, the `configure`-step may be simplified and the ```--with-python``` flag may be opmitted.

## Docker container


Master and slave bro instances are encapsulated within docker containers. The library versions for the conainer installation should not be changed (eg. `libcaf` only works for v <= 0.14.5).

<a name="start_scripts" />
For both, master and slave, there exist predefined container startscripts:
- Bro master: [start.sh](start.sh)
- Bro slave: [start-slave.sh](start-slave.sh)

##### Bro configuration

Inside the container, bro features the following:

~~~~
====================|  Bro Build Summary  |=====================

Install prefix:    /usr/local/bro
Bro Script Path:   /usr/local/bro/share/bro
Debug mode:        false

CC:                /usr/bin/cc
CFLAGS:             -Wall -Wno-unused -O2 -g -DNDEBUG
CXX:               /usr/bin/c++
CXXFLAGS:           -Wall -Wno-unused -std=c++11 -O2 -g -DNDEBUG
CPP:               /usr/bin/c++

Broker:            true
Broker Python:     true
Broccoli:          true
Broctl:            true
Aux. Tools:        true

GeoIP:             true
gperftools found:  false
        tcmalloc:  false
       debugging:  false
jemalloc:          false

================================================================
~~~~

### Manual build

The purpose of a Beemaster Bro container is set at container build time. Therefore a Docker `build-arg` has to be provided. Eg: `docker build . -t master --build-arg PURPOSE=master`. (or `slave`, respectively). Different Bro scripts are loaded into the container, according to this argument.


### Manual start

A couple of environment variables has to be provided during container start. Those vars are needed for routing inside the Beemaster cluster (accross physical hosts):

| ENV VAR            | Example       | Details
| ------------------ |:-------------:| -------
| SLAVE_PUBLIC_IP    | 134.100.28.31 | The IP address of this slave. The slave uses this address for listening and publishes it to the Bro master. The master will then use address to share it with connectors, that then can contact the slave on that address.
| SLAVE_PUBLIC_PORT  | 9991          | The listening port of this slave (see above).
| MASTER_PUBLIC_IP   | 134.100.28.31 | The IP address of the master. The master uses this address for listening.
| MASTER_PUBLIC_PORT | 9999          | The listening port of this master (see above).


These environment are set to a default value for the specific [start-scripts](#start_scripts).


## Docker-Compose cluster

You can start a small Bro cluster by using the provided [docker-compose.yml](docker-compose.yml) file. The cluster consists of one Bro master and two slaves. The publicly routable IP address of the beemaster server (`134.100.28.31`) is used for all three components.

##### Usage of the compose cluster

- Start: `docker-compose up --build -d`: build and start the cluster; then daemonize process.
- Stop: `docker-compose down`: stop and then destroy containers.
- Inspect: `docker-compose logs -f`: tail the logs.

The folder path `/var/beemaster` of the hostsystem is mounted into the containers. This way it is possible to use the Bro logs written inside the container from the outside. The CIM uses those logs.


[^1]: More detailed information about honeypot connectors: https://git.informatik.uni-hamburg.de/iss/mp-ids-hp
[^2]: More detailed information about ACUs (Alert Correlation Units): https://git.informatik.uni-hamburg.de/iss/mp-ids-acu
[^3]: More detailed information about CIM (Cyber Incident Monitor): https://git.informatik.uni-hamburg.de/iss/mp-ids-cim