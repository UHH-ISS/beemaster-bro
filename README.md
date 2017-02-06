# Beemaster Bro IDS Komponenten

Im Projekt Beemaster wird das opensource IDS [Bro](https://www.bro.org) verwendet. Bro kann in ggf mehrfacher Ausführung in Beemaster eingesetzt werden. Dabei werden einzelne Bro Instanzen in Docker Containern gekapselt.


## Bro Infrastruktur & Rollenverteilung

Das Setup des Projektes sieht vor, dass es mindestens eine Bro Instanz gibt, den Master. Zusätzlich können beliebig viele Slaves gestartet werden. Der Bro Master hat eine koordinierende Rolle im Zentrum von Beemaster. Beim Master registrieren sich alle Bro Slaves sowie auch alle Honeypot Connectoren und alle ACUs. Der Master muss zwingend für Slaves, Connectoren und ACUs erreichbar sein -- via Hostname / IP und Port. Das kann auch eine Subnet IP sein, solange sich alle Komponenten im gleichen Subnet befinden.

##### Aufgaben des Bro Master

- Schreiben von Logfiles. Diese Logfiles können vom CIM eingelesen werden.
- Verwaltung einer Routingtabelle & Loadbalancing von Honeypot Connectoren zu verfügbaren Bro Slaves
- Tunneln von Slave-Events an die ACU (via Broker-Multihop)
- ggf Handhabung von Honeypot Events, falls keine Slaves registriert sind

##### Aufgaben eines Bro Slaves

- Handhabung von Honeypot Events
- Netzwerk Überwachung des Hostsystems / Containers, auf dem der Slave läuft
- Weiterleitung jeglicher Events an den Bro Master


## Lokale Installation von Bro

Hier ist die offizielle [Doku](https://www.bro.org/development/projects/deep-cluster.html).

Im Projekt Beemaster werden spezielle Branches für Bro und Broker verwendet. Mit folgenden Befehlen werden die projektrelevanten Branches ausgechecked und installiert:

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

Falls ```python``` standardmäßig auf ```python2``` gesetzt ist, kann der configure Schritt vereinfacht werden und das ```--with-python``` kann weggelassen werden.

## Docker Container

In Beemaster wird Bro (Master und Slave) in einem Container Setup genutzt. Die Lib-Versionen sollten nicht verändert werden, Libcaf funktioniert nur mit v <= 0.14.5

Jeweils für Bro Master und Slave gibt es fertige Startskripte um einzelne Container zu starten.
- Bro Master [start.sh](start.sh)
- Bro Slave [start-slave.sh](start-slave.sh)

##### Bro Configuration

Der Bro im Container meldet Folgendes an aktivierten / deaktivierten Features:
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

### Manueller Build

Es muss zur Build-Zeit des Containers entschieden werden, ob es sich um einen Master oder einen Slave Container handeln soll. Dafür muss ein Docker `build-arg` übergeben werden. Bsp: `docker build . -t master --build-arg PURPOSE=master`. Durch dieses Build-Argument werden unterschiedliche Skripte in den Container gelegt.


### Manueller Start

Beim Start des Containers müssen Umgebungsvariablen übergeben werden. Diese Variablen sind zwingend erforderlich für das Routing im Beemaster Netzwerk:

| ENV VAR            | Beispiel   | Details
| ------------------ |:----------:| -------
| SLAVE_PUBLIC_IP    | 172.17.0.3 | Die IP Adresse unter der dieser Slave im Netzwerk erreichbar ist. Der Slave wird auf dieser IP aktiv lauschen. Der Slave überträgt diese an den Master und der Master gibt diese zB an die Connectoren weiter, damit sie sich mit dem Slave verbinden können.
| SLAVE_PUBLIC_PORT  | 9991       | Der Port unter dem dieser Slave Netzwerk erreichbar ist. Siehe oben.
| MASTER_PUBLIC_IP   | 172.17.0.1 | Die IP Adresse unter der der Master im Netzwerk erreichbar ist. Der Master wird auf dieser IP aktiv lauschen.
| MASTER_PUBLIC_PORT | 9999       | Der Port unter dem der Master im Netzwerk erreichbar ist. Siehe oben.

Eine beispielhafte Anwendung dieser Docker Umgebungsvariablen ist in den jeweiligen Startskripten für Master und Slave zu sehen.


## Docker Compose Cluster

In diesem Repository befindet sich eine `docker-compose` yaml Datei: [docker-compose.yml](docker-compose.yml). Die Datei ist für den Start eines kleinen Bro Clusters, bestehend aus einem Master und zwei Slaves. Dabei wird die öffentliche IP des ISS-Projekt Servers (`134.100.28.31`) verwendet. Sowohl Slaves als auch Master verwenden diese IP für das Routing im öffentlichen Netzwerk.

##### Nutzung des Compose Clusters

- Start: `docker-compose up --build -d`: Baut und startet das Cluster, anschließender Fork als Daemon
- Stop: `docker-compose down`: Stopt und zerstört die Container