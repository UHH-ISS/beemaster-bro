# -*- coding: utf-8 -*-

import pybroker as broker
from time import sleep


flags = broker.AUTO_PUBLISH | broker.AUTO_ADVERTISE | broker.AUTO_ROUTING
ep = broker.endpoint("talker", flags)
peering = ep.peer("127.0.0.1", 9990, 1)

sleep(.2)

print("send normal test from python side")

msg = broker.message()
msg.append(broker.data("test_normal"))
msg.append(broker.data("Normal"))

ep.send("test/topic", msg)


sleep(.5)

print("send multihop test from python side")
msg = broker.message()
msg.append(broker.data("test_multi"))
msg.append(broker.data("Yeah awesome!"))

ep.send("test/topic", msg)


