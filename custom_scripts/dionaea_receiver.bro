@load ./dio_json_log.bro
@load ./dio_mysql_log.bro
@load ./dio_download_complete_log.bro
@load ./dio_download_offer_log.bro
@load ./dio_smb_bind_log.bro
@load ./dio_smb_request_log.bro
const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "listener";
global dionaea_access: event(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string);
global dionaea_mysql: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, args: string, connector_id: string); 
global dionaea_download_complete: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, md5hash: string, filelocation: string, origin: string, connector_id: string);
global dionaea_download_offer: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, origin: string, connector_id: string);
global dionaea_smb_request: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, opnum: count, uuid: string, origin: string, connector_id: string);
global dionaea_smb_bind: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, transfersyntax: string, uuid: string, origin: string, connector_id: string);
global get_protocol: function(proto_str: string) : transport_proto;


event bro_init() {
    print "dionaea_receiver.bro: bro_init()";
    Broker::enable();
    Broker::listen(broker_port, "0.0.0.0");
    Broker::subscribe_to_events("honeypot/dionaea/");
    print "dionaea_receiver.bro: bro_init() done";
}
event bro_done() {
    print "dionaea_receiver.bro: bro_done()";
}

event dionaea_access(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string) {
    local sport: port = count_to_port(src_port, get_protocol(transport));
    local dport: port = count_to_port(dst_port, get_protocol(transport));

    print fmt("dionaea_access: timestamp=%s, dst_ip=%s, dst_port=%s, src_hostname=%s, src_ip=%s, src_port=%s, transport=%s, protocol=%s, connector_id=%s", timestamp, dst_ip, dst_port, src_hostname, src_ip, src_port, transport, protocol, connector_id);
    local rec: Dio_access::Info = [$ts=timestamp, $dst_ip=dst_ip, $dst_port=dport, $src_hostname=src_hostname, $src_ip=src_ip, $src_port=sport, $transport=transport, $protocol=protocol, $connector_id=connector_id];

    Log::write(Dio_access::LOG, rec);
}

event dionaea_mysql(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, args: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    print fmt("dionaea_mysql: timestamp=%s, id=%s, local_ip=%s, local_port=%s, remote_ip=%s, remote_port=%s, transport=%s, protocol=%s, args=%s, connector_id=%s", timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, args, connector_id);
    print fmt("converted ports %s %s", lport, rport);
    local rec: Dio_mysql::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $args=args, $connector_id=connector_id];

    Log::write(Dio_mysql::LOG, rec);
}

event dionaea_download_complete(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, md5hash: string, filelocation: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    print fmt("dionaea_download_complete: timestamp=%s, id=%s, local_ip=%s, local_port=%s, remote_ip=%s, remote_port=%s, transport=%s, protocol=%s, url=%s, md5hash=%s, filelocation=%s, origin=%s, connector_id=%s", timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, url, md5hash, filelocation, origin, connector_id);
    print fmt("converted ports %s %s", lport, rport);
    local rec: Dio_download_complete::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $url=url, $md5hash=md5hash, $filelocation=filelocation, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_download_complete::LOG, rec);
}

event dionaea_download_offer(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    print fmt("dionaea_download_offer: timestamp=%s, id=%s, local_ip=%s, local_port=%s, remote_ip=%s, remote_port=%s, transport=%s, protocol=%s, url=%s, origin=%s, connector_id=%s", timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, url, origin, connector_id);
    print fmt("converted ports %s %s", lport, rport);
    local rec: Dio_download_offer::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $url=url, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_download_offer::LOG, rec);
}

event dionaea_smb_request(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, opnum: count, uuid: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    print fmt("dionaea_smb_request: timestamp=%s, id=%s, local_ip=%s, local_port=%s, remote_ip=%s, remote_port=%s, transport=%s, protocol=%s, opnum=%d, uuid=%s, origin=%s, connector_id=%s", timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, opnum, uuid, origin, connector_id);
    print fmt("converted ports %s %s", lport, rport);
    local rec: Dio_smb_request::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $opnum=opnum, $uuid=uuid, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_smb_request::LOG, rec);
}

event dionaea_smb_bind(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, transfersyntax: string, uuid: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    print fmt("dionaea_smb_bind: timestamp=%s, id=%s, local_ip=%s, local_port=%s, remote_ip=%s, remote_port=%s, transport=%s, protocol=%s, transfersyntax=%s, uuid=%s, origin=%s, connector_id=%s", timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, protocol, transfersyntax, uuid, origin, connector_id);
    print fmt("converted ports %s %s", lport, rport);
    local rec: Dio_smb_bind::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $transfersyntax=transfersyntax, $uuid=uuid, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_smb_bind::LOG, rec);
}


event Broker::incoming_connection_established(peer_name: string) {
    print "-> Broker::incoming_connection_established", peer_name;
}
event Broker::incoming_connection_broken(peer_name: string) {
    print "-> Broker::incoming_connection_broken", peer_name;
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
