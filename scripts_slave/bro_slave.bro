@load ./slave_log.bro

@load ./beemaster_types
@load ./beemaster_events

redef exit_only_after_terminate = T;

# the ports and IPs that are externally routable for a master and this slave
const slave_broker_port: string = getenv("SLAVE_PUBLIC_PORT") &redef;
const slave_broker_ip: string = getenv("SLAVE_PUBLIC_IP") &redef;
const master_broker_port: port = to_port(cat(getenv("MASTER_PUBLIC_PORT"), "/tcp")) &redef;
const master_broker_ip: string = getenv("MASTER_PUBLIC_IP") &redef;

# the port that is internally used (inside the container) to listen to
const broker_port: port = 9999/tcp &redef;
redef Broker::endpoint_name = cat("bro-slave-", slave_broker_ip, ":", slave_broker_port);

global log_bro: function(msg: string);

global published_events: set[string] = {
    "Beemaster::dionaea_access",
    "Beemaster::dionaea_download_complete",
    "Beemaster::dionaea_download_offer",
    "Beemaster::dionaea_ftp",
    "Beemaster::dionaea_mysql_command",
    "Beemaster::dionaea_mysql_login",
    "Beemaster::dionaea_smb_bind",
    "Beemaster::dionaea_smb_request",
    "Beemaster::log_conn"
};

event bro_init() {
    log_bro("bro_slave.bro: bro_init()");
    Broker::enable([$auto_publish=T, $auto_routing=T]);

    # Listening
    Broker::listen(broker_port, "0.0.0.0");
    Broker::subscribe_to_events_multi("honeypot/dionaea");

    # Forwarding
    Broker::connect(master_broker_ip, master_broker_port, 1sec);
    Broker::register_broker_events("honeypot/dionaea", published_events);

    log_bro("bro_slave.bro: bro_init() done");
}

event bro_done() {
  log_bro("bro_slave.bro: bro_done()");
}


event Broker::incoming_connection_established(peer_name: string) {
    local msg: string = "Incoming_connection_established " + peer_name;
    log_bro(msg);
}
event Broker::incoming_connection_broken(peer_name: string) {
    local msg: string = "Incoming_connection_broken " + peer_name;
    log_bro(msg);
}
event Broker::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string) {
    local msg: string = "Outgoing connection established to: " + peer_address;
    log_bro(msg);
}
event Broker::outgoing_connection_broken(peer_address: string, peer_port: port, peer_name: string) {
    local msg: string = "Outgoing connection broken with: " + peer_address;
    log_bro(msg);
}

# forwarding when some local connection is beeing logged. Throws an explicit beemaster event to forward.
event Conn::log_conn(rec: Conn::Info) {
    event Beemaster::log_conn(rec);
}

function log_bro(msg: string) {
    local rec: Brolog::Info = [$msg=msg];
    Log::write(Brolog::LOG, rec);
}
