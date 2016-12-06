const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "listener";
global my_event: event(msg: string);
global remote: event(peer: string, number: int);

event bro_init() {
	print "auto_event.bro: bro_init()";
	Broker::enable();
	Broker::listen(broker_port, "0.0.0.0");
	Broker::subscribe_to_events("remote/event/");
	Broker::auto_event("bro/event/new_connection", new_connection);
	Broker::auto_event("bro/event/my_event", my_event);
	Broker::auto_event("bro/event/connection_external", connection_external);
	print "auto_event.bro: bro_init() done";
}

event bro_done() {
	print "auto_event.bro: bro_done()";
}

event Broker::incoming_connection_established(peer_name: string) {
	print "-> Broker::incoming_connection_established", peer_name;
	event my_event(peer_name);

	local con_id = conn_id($orig_h = 127.0.0.1, $orig_p = 80/tcp, $resp_h = 127.0.0.1, $resp_p = 443/tcp);
	local src = endpoint($size = 1, $state = TCP_INACTIVE, $flow_label = 1);
	local dest = endpoint($size = 1, $state = TCP_INACTIVE, $flow_label = 1);
	local conn = connection($id = con_id, $orig = src, $resp = dest, $start_time = current_time(), $duration = 1sec, $service = set("http", "https"), $history = "history", $uid = "1337");

	# event connection_external(conn, "broker tag");
}

event Broker::incoming_connection_broken(peer_name: string) {
	print "-> Broker::incoming_connection_broken", peer_name;
}

event remote(peer: string, number: int) {
	print fmt("remote_event: peer=%s, number=%d", peer, number);
}

event new_connection(c: connection) {
	print "new_connection received";
}
