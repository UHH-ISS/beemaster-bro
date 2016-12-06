# Configuration
const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "listener";

# Simple test event
global remote: event(peer: string, number: int);

# Dionaea sample events
global dionaea_connection_new: event(timestamp: time, id: count, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string);
global dionaea_connection: event(name: string, timestamp: time, protocol: string, local_ip: addr, transport: string, remote_ip: addr);

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

event dionaea_connection(name: string, timestamp: time, protocol: string, local_ip: addr, transport: string, remote_ip: addr) {
	print fmt("dionaea_connection: name=%s, timestamp=%s, protocol=%s, transport=%s, local_ip=%s, remote_ip=%s", name, timestamp, protocol, transport, local_ip, remote_ip);
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
