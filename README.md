# Beemaster Bro IDS Komponenten

Im Projekt Beemaster wird das freie IDS [Bro](https://www.bro.org) verwendet. Bro kann mehrfach verwendet werden. Zu diesem Zweck werden einzelne Bro-Instanzen in Docker-Containern gekapselt.


## Bro Infrastruktur & Rollenverteilung

Das Setup des Projektes sieht vor, dass es mindestens eine Bro-Instanz gibt: den Master. Zusätzlich können beliebig viele Slaves gestartet werden. Der Bro-Master hat eine koordinierende Rolle im Zentrum von Beemaster. Beim Master registrieren sich alle Bro-Slaves sowie alle Honeypot-Connectoren[^1] und alle ACUs[^2]. Der Master muss zwingend für Slaves, Connectoren und ACUs erreichbar sein -- via Hostname / IP und Port. Das kann auch eine Subnet-IP sein, solange sich alle Komponenten im gleichen Subnet befinden.

##### Aufgaben des Bro-Masters

- Schreiben von Logfiles. Diese Logfiles können vom CIM[^3] eingelesen werden.
- Verwaltung einer Routing-Tabelle & Load-Balancing von Honeypot-Connectoren zu verfügbaren Bro-Slaves
- Tunneln von Slave-Events an die ACU (via Broker-Multihop)
- Handhabung von Honeypot-Events, falls keine Slaves registriert sind (Fallback).

##### Aufgaben eines Bro-Slaves

- Handhabung von Honeypot-Events
- Netzwerküberwachung des Hostsystems / Containers, auf dem der Slave läuft
- Weiterleitung jeglicher Events an den Bro-Master


## Lokale Installation von Bro

Die [offizielle Dokumentation](https://www.bro.org/development/projects/deep-cluster.html) enthält alle notwendigen Details für die Installation.

Im Projekt Beemaster werden spezielle Branches für Bro und Broker verwendet. Mit den folgenden Befehlen werden die projektrelevanten Branches ausgecheckt und installiert:

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

Falls ```python``` standardmäßig auf ```python2``` gesetzt ist, kann der configure Schritt vereinfacht und das ```--with-python``` kann weggelassen werden.

## Docker-Container

In Beemaster wird Bro (Master und Slave) in einem Container-Setup genutzt. Die Lib-Versionen sollten nicht verändert werden, Libcaf funktioniert nur mit v <= 0.14.5

Für Bro-Master und Bro-Slaves gibt es fertige Startskripte, um einzelne Container zu starten.
- Bro-Master: [start.sh](start.sh)
- Bro-Slave: [start-slave.sh](start-slave.sh)

##### Bro-Konfiguration

Bro im Container meldet folgende aktivierte / deaktivierte Features:
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