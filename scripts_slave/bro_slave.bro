@load ./slave_log.bro

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "bro-slave-" + gethostname(); # make sure this is unique (for docker-compose, it is!)
global dionaea_access: event(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string);
global dionaea_ftp: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, command: string, arguments: string, origin: string, connector_id: string);
global dionaea_mysql: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, args: string, connector_id: string);
global dionaea_download_complete: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, md5hash: string, filelocation: string, origin: string, connector_id: string);
global dionaea_download_offer: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, origin: string, connector_id: string);
global dionaea_smb_request: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, opnum: count, uuid: string, origin: string, connector_id: string);
global dionaea_smb_bind: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, transfersyntax: string, uuid: string, origin: string, connector_id: string);
global log_bro: function(msg: string);
global published_events: set[string] = { "dionaea_access", "dionaea_mysql" };


event bro_init() {
    log_bro("bro_slave.bro: bro_init()");
    Broker::enable([$auto_publish=T, $auto_routing=T]);
    
    # Listening
    Broker::listen(broker_port, "0.0.0.0");
    Broker::subscribe_to_events("honeypot/dionaea");
    Broker::subscribe_to_events_multi("honeypot/dionaea");
    
    # Forwarding
    Broker::connect("bro-master", broker_port, 1sec);
    Broker::register_broker_events("honeypot/dionaea", published_events);

    # Try unsolicited option, which should prevent topic issues
    Broker::auto_event("honeypot/dionaea", dionaea_access);
    log_bro("bro_slave.bro: bro_init() done");
}

event bro_done() {
  log_bro("bro_slave.bro: bro_done()");
}

event dionaea_access(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string) {
    event dionaea_access(timestamp, dst_ip, dst_port, src_hostname, src_ip, src_port, transport, protocol, connector_id);
}
event dionaea_ftp(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, command: string, arguments: string, origin: string, connector_id: string) {

    event dionaea_ftp(timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, command, arguments, origin, connector_id);
}
event dionaea_mysql(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, args: string, connector_id: string) {

    event dionaea_mysql(timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, args, connector_id);
}
event dionaea_download_complete(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, md5hash: string, filelocation: string, origin: string, connector_id: string) {

    event dionaea_download_complete(timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, url, md5hash, filelocation, origin, connector_id);
}
event dionaea_download_offer(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, origin: string, connector_id: string) {
    event dionaea_download_offer(timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, url, origin, connector_id);
}
event dionaea_smb_request(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, opnum: count, uuid: string, origin: string, connector_id: string) {

    event dionaea_smb_request(timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, opnum, uuid, origin, connector_id);
}
event dionaea_smb_bind(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, transfersyntax: string, uuid: string, origin: string, connector_id: string) {

    event dionaea_smb_bind(timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, transfersyntax, uuid, origin, connector_id);
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
