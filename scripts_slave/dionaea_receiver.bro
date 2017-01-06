@load ./bro_log.bro
const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = unique_id("bro-slave-");
global dionaea_access: event(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string);
global dionaea_mysql: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, args: string, connector_id: string);
#global log_dionaea_access: event(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string);
#global log_dionaea_mysql: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, args: string, connector_id: string);
global log_bro: function(msg: string);
global published_events: set[string] = { "dionaea_access", "dionaea_mysql" };


event bro_init() {
    log_bro("dionaea_receiver.bro: bro_init()");
    Broker::enable([$auto_publish=T, $auto_routing=T]);
    
    # Listening
    Broker::listen(broker_port, "0.0.0.0");
    Broker::subscribe_to_events("honeypot/dionaea/");
    
    # Forwarding
    Broker::connect("bro-master", broker_port, 1sec);
    Broker::register_broker_events("bro/forwarder/dionaea", published_events);

    # Try unsolicited option, which should prevent topic issues
    Broker::auto_event("bro/forwarder/dionaea", dionaea_access, [$unsolicited=T]);
    Broker::auto_event("bro/forwarder/dionaea", dionaea_mysql, [$unsolicited=T]);
    log_bro("dionaea_receiver.bro: bro_init() done");
}

event bro_done() {
  log_bro("dionaea_receiver.bro: bro_done()");
}

event dionaea_access(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string) {
  log_bro("Dionaea access event received!");

  # forward:
  event dionaea_access(timestamp, dst_ip, dst_port, src_hostname, src_ip, src_port, transport, protocol, connector_id);
}

event dionaea_mysql(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, args: string, connector_id: string) {
  log_bro("Dionaea mysql event received!");

  # forward:
  event dionaea_mysql(timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, args, connector_id);
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

function log_bro(msg: string) {
  local rec: Brolog::Info = [$msg=msg];
  Log::write(Brolog::LOG, rec);
}
