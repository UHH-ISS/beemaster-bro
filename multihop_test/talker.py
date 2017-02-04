# -*- coding: utf-8 -*-

import pybroker as broker
from time import sleep


flags = broker.AUTO_PUBLISH | broker.AUTO_ADVERTISE | broker.AUTO_ROUTING
ep = broker.endpoint("talker", flags)
peering = ep.peer("127.0.0.1", 9990, 1)

sleep(.8)

msg = broker.message()
msg.append(broker.data("dummy"))
msg.append(broker.data("works better"))

ep.send("test/topic", msg)

print("send multihop test from python side")
msg = broker.message()
msg.append(broker.data("test_multi"))
msg.append(broker.data("Yeah awesome!"))

ep.send("test/topic", msg)


