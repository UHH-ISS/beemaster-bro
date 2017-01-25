const broker_port: port = 9990/tcp &redef;
const master_port: port = 9999/tcp &redef;

global test_multi: event(body: string);
global test_normal: event(body: string);


event bro_init() {
    Broker::enable();
    Broker::set_endpoint_flags([$auto_publish=T, $auto_routing=T]);

    Broker::subscribe_to_events_multi("test/topic");

    Broker::listen(broker_port, "127.0.0.1");

    Broker::connect("127.0.0.1", master_port, 1sec);
    local published_events: set[string] = { "test_multi", "test_normal" };
    Broker::register_broker_events("test/topic", published_events);
}

event test_normal(body: string) {
    print "slave normal event forward: " + body;
    event test_normal(body); # manual publish (works via auto_publish)
}