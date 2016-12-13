#Bro aus Repo installieren:

Es gibt eine [Doku](https://www.bro.org/development/projects/deep-cluster.html).

Das hier installiert bro aus dem Repo in dem Ordner, in dem ihr gerade seid. Wenn bei euch ```python``` standardmäßig auf ```python2``` gesetzt ist, könnt ihr den configure Schritt vereinfachen und das ```--with-python``` weglassen.

~~~~
git clone --recursive https://github.com/bro/bro
cd bro
git checkout topic/mfischer/deep-cluster
git submodule update
cd aux/broker
git checkout topic/mfischer/broker-multihop
cd ../..

./configure --with-python=/usr/bin/python2
make
sudo make install
~~~~

## Docker Container

Wir werden Bro in einem Container Setup nutzen. Auf Alpinebasis scheint das grade nicht machbar zu sein, weil diverse Libs nicht existieren (ist ja auch eine minimalistische Linux Distro..) Unser Image ist daher mit dem neuesten Debian gemacht, Debian:Stretch. Die Lib-Versionen sollten nicht angefasst werden...
Libcaf funktioniert nur mit v <= 0.14.5

Bro im Container bauen + starten:
~~~~
docker build . -t bro # achtung das dauert lange
docker run bro
~~~~

#### Bro Configuration

Der Bro im Container meldet folgendes an aktivierten / deaktivierten Features:
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