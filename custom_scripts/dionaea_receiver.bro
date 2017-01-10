@load ./dio_json_log.bro
@load ./dio_ftp_log.bro
@load ./dio_mysql_log.bro
@load ./dio_download_complete_log.bro
@load ./dio_download_offer_log.bro
@load ./dio_smb_bind_log.bro
@load ./dio_smb_request_log.bro
const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "listener";
global dionaea_access: event(timestamp: time, local_ip: addr, local_port: count, remote_hostname: string, remote_ip: addr, remote_port: count, transport: string, protocol: string, connector_id: string);
global dionaea_ftp: event(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, command: string, arguments: string, origin: string, connector_id: string);
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

event dionaea_access(timestamp: time, local_ip: addr, local_port: count, remote_hostname: string, remote_ip: addr, remote_port: count, transport: string, protocol: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_access::Info = [$ts=timestamp, $local_ip=local_ip, $local_port=lport, $remote_hostname=remote_hostname, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $connector_id=connector_id];

    Log::write(Dio_access::LOG, rec);
}

event dionaea_ftp(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, command: string, arguments: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_ftp::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $command=command, $arguments=arguments, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_ftp::LOG, rec);
}

event dionaea_mysql(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, args: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_mysql::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $args=args, $connector_id=connector_id];

    Log::write(Dio_mysql::LOG, rec);
}

event dionaea_download_complete(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, md5hash: string, filelocation: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_download_complete::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $url=url, $md5hash=md5hash, $filelocation=filelocation, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_download_complete::LOG, rec);
}

event dionaea_download_offer(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_download_offer::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $url=url, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_download_offer::LOG, rec);
}

event dionaea_smb_request(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, opnum: count, uuid: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_smb_request::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $opnum=opnum, $uuid=uuid, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_smb_request::LOG, rec);
}

event dionaea_smb_bind(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, transfersyntax: string, uuid: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

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
