### Setup

- talker.py is peered with slave.bro and uses broker python bindings to communicate with the slave.bro
- slave.bro is peered with master.bro
- slave.bro forwards one normal event (to verify that things generally do work)
- slave.bro announces multihop event, but does not implement a handler

### Start / Use

- open three terminals
- do `bro -Q master.bro` in one terminal
- do `bro -Q slave.bro` in another terminal
- maybe fix the symlink to the _pybroker.so for your system
- do `python2 talker.py`
- normal events should go through, mutlihop event doesnt

### Expected normal behavior

- Master defines global event signature and implements event
- Slave defines global event signature, and implements event
- Sending from talker.py to slave.bro is possible
- Slave forwards in the event body to Master, there the event body is picked up


### Expected multihop behavior

- Master defines global event signature and implements event (with body)
- Slave defines global event signature, **_no_** impl of event
- Sending from talker.py to slave.bro is possible
- Slave **_auto-forwards_** via multihop to Master, there the event body is executed