const broker_port: port = 9999/tcp &redef;

global test_multi: event(body: string);

event bro_init() {
    Broker::enable([$auto_publish=T, $auto_routing=T]);

    Broker::subscribe_to_events_multi("test/topic");

    Broker::listen(broker_port, "127.0.0.1");
}

event test_multi(body: string) {
    print "Master received multihop event: " + body;
}

event Broker::incoming_connection_established(peer_name: string) {
    print "Incoming connection established " + peer_name;
}