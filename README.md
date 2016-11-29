###Bro aus Repo installieren:

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
cd aux/broctl
git checkout topic/mfischer/broctl-overlay
cd ../..

./configure --with-python=/usr/bin/python2
make
sudo make install
~~~~

#### Docker Container

achtung: geht grad noch nicht, weil container streikt. Coming soon! :)

Bro im Container bauen + starten:
`docker build . -t bro`
`docker run bro`