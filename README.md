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



Es muss zur Build-Zeit des Containers entschieden werden, ob es sich um einen Master- oder einen Slave-Container handeln soll. Dafür muss ein Docker `build-arg` übergeben werden. Zum Beispiel: `docker build . -t master --build-arg PURPOSE=master`. Durch dieses Build-Argument werden unterschiedliche (Bro-) Skripte in den Container gelegt.


### Manueller Start

Beim Start des Containers müssen Umgebungsvariablen übergeben werden. Diese Variablen sind zwingend für das Routing im Beemaster Netzwerk erforderlich:

| ENV VAR            | Beispiel   | Details
| ------------------ |:----------:| -------
| SLAVE_PUBLIC_IP    | 172.17.0.3 | Die IP-Adresse unter der dieser Slave im Netzwerk erreichbar ist. Der Slave wird auf dieser IP aktiv lauschen. Er überträgt diese IP an den Master und der Master gibt diese z.B. an die Connectoren weiter, damit sie sich mit dem Slave verbinden können.
| SLAVE_PUBLIC_PORT  | 9991       | Der Port unter dem dieser Slave im Netzwerk erreichbar ist. Siehe oben.
| MASTER_PUBLIC_IP   | 172.17.0.1 | Die IP-Adresse unter der der Master im Netzwerk erreichbar ist. Der Master wird auf dieser IP aktiv lauschen.
| MASTER_PUBLIC_PORT | 9999       | Der Port unter dem der Master im Netzwerk erreichbar ist. Siehe oben.

Diese Docker-Umgebungsvariablen werden in den jeweiligen Startskripten für Master und Slave angewandt (siehe dort).


## Docker-Compose-Cluster

In diesem Repository befindet sich eine `docker-compose` yaml Datei: [docker-compose.yml](docker-compose.yml). Die Datei startet ein kleines Bro-Cluster, bestehend aus einem Master und zwei Slaves. Dabei wird die öffentliche IP des ISS-Projekt Servers (`134.100.28.31`) verwendet. Sowohl Slaves als auch Master verwenden diese IP für das Routing im öffentlichen Netzwerk.

##### Nutzung des Compose-Clusters

- Start: `docker-compose up --build -d`: Baut und startet das Cluster; anschließender Fork als Daemon
- Stop: `docker-compose down`: Stoppt und zerstört die Container

Über Docker-Mountvolumes werden Ordner des Hostsystems in den Containern unter `/var/beemaster` für Master und Slave verfügbar gemacht. So kann auf die geschriebenen Logdateien auch von außerhalb der Container zugegriffen werden -- zum Beispiel der lesende Zugriff des CIMs.


[^1]: Für weitere Informationen zu Honeypot-Connectoren siehe: https://git.informatik.uni-hamburg.de/iss/mp-ids-hp
[^2]: Für weitere Informationen zu ACUs (Alert Correlation Units) siehe: https://git.informatik.uni-hamburg.de/iss/mp-ids-acu
[^3]: Für weitere Informationen zum CIM (Cyber Incident Monitor) siehe: https://git.informatik.uni-hamburg.de/iss/mp-ids-cim