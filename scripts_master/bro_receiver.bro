@load ./dio_log.bro
@load ./bro_log.bro
@load ./dio_mysql_log.bro
const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "bro_receiver";
global dionaea_access: event(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string);
global dionaea_mysql: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, args: string, connector_id: string); 
global get_protocol: function(proto_str: string) : transport_proto;
global log_bro: function(msg: string);

event bro_init() {
    log_bro("bro_receiver.bro: bro_init()");
    Broker::enable([$auto_publish=T]);

    Broker::listen(broker_port, "0.0.0.0");

    Broker::subscribe_to_events("bro/forwarder");

    log_bro("bro_receiver.bro: bro_init() done");
}
event bro_done() {
    log_bro("bro_receiver.bro: bro_done()");
}
event dionaea_access(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string) {
    log_bro("Bro Master log access event!");
    local sport: port = count_to_port(src_port, get_protocol(transport));
    local dport: port = count_to_port(dst_port, get_protocol(transport));
    print fmt("dionaea_access: timestamp=%s, dst_ip=%s, dst_port=%s, src_hostname=%s, src_ip=%s, src_port=%s, transport=%s, protocol=%s, connector_id=%s", timestamp, dst_ip, dst_port, src_hostname, src_ip, src_port, transport, protocol, connector_id);
    local rec: Dio_access::Info = [$ts=timestamp, $dst_ip=dst_ip, $dst_port=dport, $src_hostname=src_hostname, $src_ip=src_ip, $src_port=sport, $transport=transport, $protocol=protocol, $connector_id=connector_id];

    Log::write(Dio_access::LOG, rec);
}
event dionaea_mysql(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, args: string, connector_id: string) {
    log_bro("Bro Master log mysql event!");
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));
    print fmt("dionaea_mysql: timestamp=%s, id=%s, local_ip=%s, local_port=%s, remote_ip=%s, remote_port=%s, transport=%s, args=%s, connector_id=%s", timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, args, connector_id);
    local rec: Dio_mysql::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $args=args, $connector_id=connector_id];
    Log::write(Dio_mysql::LOG, rec);
}
event Broker::incoming_connection_established(peer_name: string) {
    local msg: string = "-> Broker::incoming_connection_established " + peer_name;
    log_bro(msg);
}
event Broker::incoming_connection_broken(peer_name: string) {
    local msg: string = "-> Broker::incoming_connection_broken " + peer_name;
    log_bro(msg);
}
function get_protocol(proto_str: string) : transport_proto {
    # https://www.bro.org/sphinx/scripts/base/init-bare.bro.html#type-transport_proto
    if (proto_str == "tcp") {
        return tcp;
    }
    if (proto_str == "udp") {
        return udp;
    }
    if (proto_str == "icmp") {
        return icmp;
    }
    return unknown_transport;
}

function log_bro(msg:string) {
  local rec: Brolog::Info = [$msg=msg];
  Log::write(Brolog::LOG, rec);
}
