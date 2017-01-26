@load ./beemaster_events
@load ./beemaster_types
@load ./beemaster_log

@load base/bif/plugins/Bro_TCP.events.bif
@load base/protocols/conn/main

redef exit_only_after_terminate = T;

# the ports and IPs that are externally routable for a master and this slave
const slave_broker_port: string = getenv("SLAVE_PUBLIC_PORT") &redef;
const slave_broker_ip: string = getenv("SLAVE_PUBLIC_IP") &redef;
const master_broker_port: port = to_port(cat(getenv("MASTER_PUBLIC_PORT"), "/tcp")) &redef;
const master_broker_ip: string = getenv("MASTER_PUBLIC_IP") &redef;

# the port that is internally used (inside the container) to listen to
const broker_port: port = 9999/tcp &redef;
redef Broker::endpoint_name = cat("bro-slave-", slave_broker_ip, ":", slave_broker_port);

global published_events: set[string] = { "Beemaster::log_conn", "Beemaster::tcp_event" };

event bro_init() {
    Beemaster::log("bro_slave.bro: bro_init()");

    # Enable broker and listen for incoming connectors/acus
    Broker::enable([$auto_publish=T, $auto_routing=T]);
    Broker::listen(broker_port, "0.0.0.0");

    # Connect to bro-master for load-balancing and relaying events
    Broker::connect(master_broker_ip, master_broker_port, 1sec);

    # Publish our local events to forward them to master/acus
    Broker::register_broker_events("slave/events", published_events);

    Beemaster::log("bro_slave.bro: bro_init() done");
}

event bro_done() {
  Beemaster::log("bro_slave.bro: bro_done()");
}

event Broker::incoming_connection_established(peer_name: string) {
    local msg: string = "Incoming connection established to: " + peer_name;
    Beemaster::log(msg);
}
event Broker::incoming_connection_broken(peer_name: string) {
    local msg: string = "Incoming connection broken with: " + peer_name;
    Beemaster::log(msg);
}
event Broker::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string) {
    local msg: string = "Outgoing connection established to: " + peer_address;
    Beemaster::log(msg);
}
event Broker::outgoing_connection_broken(peer_address: string, peer_port: port, peer_name: string) {
    local msg: string = "Outgoing connection broken with: " + peer_address;
    Beemaster::log(msg);
}

# forwarding when some local connection is beeing logged. Throws an explicit beemaster event to forward.
event Conn::log_conn(rec: Conn::Info) {
    event Beemaster::log_conn(rec);
}

event connection_SYN_packet(c: connection, pkt: SYN_packet) {
    Beemaster::log("connection_SYN_packet on slave");
    event Beemaster::tcp_event(Beemaster::connection_to_alertinfo(c), 1);
}
