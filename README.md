# MP-IDS Bro[^0]

The open source IDS [Bro](https://www.bro.org) is widely used within the Beemaster project. Bro is the communication and network analysis core; hence it plays a central role. Bro is integrated into Beemaster in a containerized sense, featuring a variadic cluster design and different roles.

## Bro Infrastructure & Role Allocation

By design, there must be at least one Bro instance: the Master instance. Additionally, numerous Bro slave instances may be added freely. The master instance is responsible for cluster management and coordination. It can be seen as the Beemaster core. All Bro slave instances, honeypot connectors[^1] as well as ACUs[^2] must register themselves to the master. Thus, the master must be reachable for all those components (either via IP or hostname). That may as well be done via subnet reachability, as long as all components share the same network.


##### Bro Master Tasks

- Logging: Logfiles may be processed by the CIM[^3]
- Management of registered components, routing table & load balancing of honeypots <-> Bro slaves
- Tunnelling of slave events to registered ACUs (via Broker multihop)
- Handling of honeypot events (fall back in case no slaves are registered)

##### Bro Slave Tasks

- Handling of honeypot events
- Network monitoring of the host systen / container on which the slave is running
- Forwarding of all possible events to the Bro master instance


## Local Installation of Bro

The [official docs](https://www.bro.org/development/projects/deep-cluster.html) contain all necessary details for a manual installation.

For the Beemaster project, dedicated git branches must be used for Bro and Broker. The following commands will checkout and install all project-relevant sources:

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

In case ```python``` is referencing ```python2``` by default, the `configure`-step may be simplified and the ```--with-python``` flag may be omitted.


## Docker Container

Master and slave Bro instances are encapsulated within Docker containers. The library versions for the container installation should not be changed (for instance, `libcaf` only works with version v <= 0.14.5).

<a name="start_scripts" />
For both, master and slave, exist predefined container start scripts:
- Bro master: [start.sh](start.sh)
- Bro slave: [start-slave.sh](start-slave.sh)

##### Bro Configuration

Inside the container, Bro features the following:

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
Broccoli:          false
Broctl:            true
Aux. Tools:        true

GeoIP:             true
gperftools found:  false
        tcmalloc:  false
       debugging:  false
jemalloc:          false

================================================================
~~~~

### Manual Build

The purpose of the Beemaster Bro container must be set at build time. Therefore a Docker `build-arg` has to be provided. For example: `docker build . -t master --build-arg PURPOSE=master`. (or `slave`, respectively). Different Bro scripts are loaded into the container, according to this argument.


### Manual start

A couple of environment variables have to be provided during container start. Those variables are needed for routing inside the Beemaster cluster (across physical hosts):

| ENV VAR            | Example       | Details
| ------------------ |:-------------:| -------
| SLAVE_PUBLIC_IP    | 134.100.28.31 | The IP address of this slave. The slave uses this address for listening and publishes it to the Bro master. The master will then use this address to share it with connectors to allow them to contact the slave on that address.
| SLAVE_PUBLIC_PORT  | 9991          | The listening port of this slave (see above).
| MASTER_PUBLIC_IP   | 134.100.28.31 | The IP address of the master. The master uses this address for listening.
| MASTER_PUBLIC_PORT | 9999          | The listening port of this master (see above).


These environment variables are set to a default value for the specific [start scripts](#start_scripts).


## Docker-Compose Cluster

You can start a small Bro cluster by using the provided [docker-compose.yml](docker-compose.yml) file. The cluster consists of one Bro master and two slaves. The publicly routable IP address of the Beemaster server (`134.100.28.31`) is used for all three components.

##### Usage of the Compose Cluster

- Start: `docker-compose up --build -d`: Build and start the cluster; Then daemonize the process.
- Stop: `docker-compose down`: Stop and then destroy all previously started containers.
- Inspect: `docker-compose logs -f`: Tail the logs.

The folder path `/var/beemaster` of the host system is mounted into the containers. Thus, it is possible to access the Bro log files written inside the container from the outside. The CIM uses these logs.

## License attribution

Bro IDS and Broker are licensed under the (a variant of) the BSD license ([Bro IDS](https://github.com/bro/bro/blob/master/COPYING), [Broker](https://github.com/bro/broker/blob/master/COPYING))

Beemaster does solely use the Bro IDS and Broker standard installation. All credits regarding any of the above products to the respective creators of those projects. Beemaster does not claim to own, modify or redistribute any of the used software components. The applied MIT license only regards the work done during the Beemaster project, including but not limitting to the creation of custom Bro-scripts, shell-scripts and configuration files.

[^0]: A German version of this readme can be found at: [README.md@80d534a](https://git.informatik.uni-hamburg.de/iss/mp-ids-bro/blob/80d534af23cb2753574e35bc10af91a32a8f0275/README.md) (remove this hint if the German version is outdated!)
[^1]: More detailed information about honeypot connectors: https://git.informatik.uni-hamburg.de/iss/mp-ids-hp
[^2]: More detailed information about ACUs (Alert Correlation Units): https://git.informatik.uni-hamburg.de/iss/mp-ids-acu
[^3]: More detailed information about CIM (Cyber Incident Monitor): https://git.informatik.uni-hamburg.de/iss/mp-ids-cim