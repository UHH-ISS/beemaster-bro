const broker_port: port = 9999/tcp &redef;

global test_multi: event(body: string);
global test_normal: event(body: string);

event bro_init() {
    Broker::enable();

    Broker::set_endpoint_flags([$auto_publish=T, $auto_routing=T]);

    Broker::subscribe_to_events_multi("test/topic");

    Broker::listen(broker_port, "127.0.0.1");
}

event test_multi(body: string) {
    print "Master received multihop event: " + body;
}

event test_normal(body: string) {
    print "Master received normal event: " + body;
}