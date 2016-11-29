#!/bin/sh

set -e

git clone --recursive https://github.com/bro/bro bro-git
cd bro-git
git checkout topic/mfischer/deep-cluster
git submodule update
cd aux/broker
git checkout topic/mfischer/broker-multihop
cd ../..
cd aux/broctl
git checkout topic/mfischer/broctl-overlay
cd ../..
./configure
make
sudo make install 
