# Configuration
const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "listener";
# Simple test event
global remote: event(peer: string, number: int);
# Dionaea sample events
global dionaea_connection_new: event(timestamp: time, id: count, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string);
global dionaea_connection: event(name: string, timestamp: time, id: count, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string); 

event bro_init() {
    print "auto_event.bro: bro_init()";
    Broker::enable();
    Broker::listen(broker_port, "0.0.0.0");
    Broker::subscribe_to_events("remote/event/");
    print "auto_event.bro: bro_init() done";
}
event bro_done() {
    print "auto_event.bro: bro_done()";
}

event dionaea_connection(name: string, timestamp: time, id: count, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string) {
    # This doesnt work yet. We want to concat port and transport(=protocol) values to match broker port format (1337/tcp).
    #local lport = to_port(string_cat(somethingsomething);
    #local rport = to_port(rport_str);
    local lport: port = 1337/tcp;
    local rport: port = 1337/tcp;
    print fmt("dionaea_connection: name=%s, timestamp=%s, id=%s, local_ip=%s, local_port=%s, remote_ip=%s, remote_port=%s, transport=%s", name, timestamp, id, local_ip, local_port, remote_ip, remote_port, transport);
    local rec: Dio::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport];

    Log::write(Dio::LOG, rec);
}
event remote(peer: string, number: int) {
    print fmt("remote_event: peer=%s, number=%d", peer, number);
}
event Broker::incoming_connection_established(peer_name: string) {
    print "-> Broker::incoming_connection_established", peer_name;
}
event Broker::incoming_connection_broken(peer_name: string) {
    print "-> Broker::incoming_connection_broken", peer_name;
}
