const broker_port: port = 9990/tcp &redef;
const master_port: port = 9999/tcp &redef;

event bro_init() {
    Broker::enable([$auto_publish=T, $auto_routing=T]);

    Broker::subscribe_to_events_multi("test/topic");

    Broker::listen(broker_port, "127.0.0.1");

    Broker::connect("127.0.0.1", master_port, 1sec);
}