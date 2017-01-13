## Demo

For the demo on thursday 2017-01-12 we need some distributed hosts that are able to communicate with each other and share container names as hostnames over either DNS or KV-based service discovery.

So here is the way we gonna do it:

#### Docker swarm cluster

We are going to connect the beemaster server and one of my servers within a docker swarm cluster.

Steps to reproduce:

Set up a swarm master node (this will be the beemaster server):

```bash
docker swarm init --advertise-addr 134.100.28.31 # beemaster address
```

On my server machine I ran the following in order to join the cluster as a worker node
```bash
docker swarm join \
     --token SWMTKN-1-5ejm1j5rsj6oyk7wyeofguzooa5bt6yaci9r9t8rvh3zglcsd0-54mm9b208cpsvxy90jz975tj8 \
     134.100.28.31:2377

#-> This node joined a swarm as a worker.
```

To verify the connection between both, one can use the `docker info` command.

Swarm-part of the output of `docker info` on beemaster server:

```
.....
Swarm: active
 NodeID: 47z927uxrfl5lx2j9ckj3k9pn
 Is Manager: true
 ClusterID: 4htpdtrew0clks7pxziwf8tu6
 Managers: 1
 Nodes: 2
 Orchestration:
  Task History Retention Limit: 5
 Raft:
  Snapshot Interval: 10000
  Heartbeat Tick: 1
  Election Tick: 3
 Dispatcher:
  Heartbeat Period: 5 seconds
 CA Configuration:
  Expiry Duration: 3 months
 Node Address: 134.100.28.31
.....
```

For whatever reason one has to manually create an overlay network to span accross the docker machines.
We go with the encrypted variant.

```
docker network create --opt encrypted --driver overlay beemaster-demo
```

TILL HERE: FINE

FROM HERE: BROKEN

Use `./cluster-beemaster.sh start` or `stop` for creating a multi host docker (service-managed) beemaster cluster. 