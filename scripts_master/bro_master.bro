@load ./balance_log

@load ./beemaster_events
@load ./beemaster_log

@load ./dio_access
@load ./dio_download_complete
@load ./dio_download_offer
@load ./dio_ftp
@load ./dio_mysql_command
@load ./dio_login
@load ./dio_smb_bind
@load ./dio_smb_request
@load ./dio_blackhole.bro
@load ./acu_result.bro

redef exit_only_after_terminate = T;
# the port and IP that are externally routable for this master
const public_broker_port: string = getenv("MASTER_PUBLIC_PORT") &redef;
const public_broker_ip: string = getenv("MASTER_PUBLIC_IP") &redef;

# the port that is internally used (inside the container) to listen to
const broker_port: port = 9999/tcp &redef;
redef Broker::endpoint_name = cat("bro-master-", public_broker_ip, ":", public_broker_port);

global get_protocol: function(proto_str: string) : transport_proto;
global log_balance: function(connector: string, slave: string);
global slaves: table[string] of count;
global connectors: opaque of Broker::Handle;
global add_to_balance: function(peer_name: string);
global remove_from_balance: function(peer_name: string);
global rebalance_all: function();

event bro_init() {
    Beemaster::log("bro_master.bro: bro_init()");

    # Enable broker and listen for incoming slaves/acus
    Broker::enable([$auto_publish=T, $auto_routing=T]);
    Broker::listen(broker_port, "0.0.0.0");

    # Subscribe to dionaea events for logging
    Broker::subscribe_to_events_multi("honeypot/dionaea");

    # Subscribe to slave events for logging
    Broker::subscribe_to_events_multi("beemaster/bro/base");

    # Subscribe to tcp events for logging
    Broker::subscribe_to_events_multi("beemaster/bro/tcp");
		
		Broker::subscribe_to_events_multi("beemaster/acu/acu_result");

		# Subscribe to lattice events for logging
		Broker::subscribe_to_events_multi("beemaster/bro/udp");

    ## create a distributed datastore for the connector to link against:
    connectors = Broker::create_master("connectors");

    Beemaster::log("bro_master.bro: bro_init() done");
}
event bro_done() {
    Beemaster::log("bro_master.bro: bro_done()");
}

event Beemaster::dionaea_access(timestamp: time, local_ip: addr, local_port: count, remote_hostname: string, remote_ip: addr, remote_port: count, transport: string, protocol: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_access::Info = [$ts=timestamp, $local_ip=local_ip, $local_port=lport, $remote_hostname=remote_hostname, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $connector_id=connector_id];

    Log::write(Dio_access::LOG, rec);
}

event Beemaster::dionaea_download_complete(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, md5hash: string, filelocation: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_download_complete::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $url=url, $md5hash=md5hash, $filelocation=filelocation, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_download_complete::LOG, rec);
}

event Beemaster::dionaea_download_offer(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_download_offer::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $url=url, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_download_offer::LOG, rec);
}

event Beemaster::dionaea_ftp(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, command: string, arguments: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_ftp::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $command=command, $arguments=arguments, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_ftp::LOG, rec);
}

event Beemaster::dionaea_mysql_command(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, args: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_mysql_command::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $args=args, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_mysql_command::LOG, rec);
}

event Beemaster::dionaea_login(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, username: string, password: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_login::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $username=username, $password=password, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_login::LOG, rec);
}

event Beemaster::dionaea_smb_bind(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, transfersyntax: string, uuid: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_smb_bind::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $transfersyntax=transfersyntax, $uuid=uuid, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_smb_bind::LOG, rec);
}

event Beemaster::dionaea_smb_request(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, opnum: count, uuid: string, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_smb_request::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $opnum=opnum, $uuid=uuid, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_smb_request::LOG, rec);
}

event dionaea_blackhole(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, protocol: string, input: string, length: count, origin: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));

    local rec: Dio_blackhole::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $input=input, $length=length, $origin=origin, $connector_id=connector_id];

    Log::write(Dio_blackhole::LOG, rec);
}
event Beemaster::lattice_result(timestamp: time, attack: string) {
    Beemaster::log("Got lattice_result!");
    local rec: Acu_result::Info = [$ts=timestamp, $attack=attack];
    Log::write(Acu_result::LOG, rec);
}
# TODO: Adjust to changes in fw
event Beemaster::acu_result(timestamp: time, attack: string) {
    Beemaster::log("Got acu_result!");
    local rec: Acu_result::Info = [$ts=timestamp, $attack=attack];
    Log::write(Acu_result::LOG, rec);
}
event Beemaster::tcp_event(rec: Beemaster::AlertInfo, discriminant: count) {
    Beemaster::log("Got tcp_event!!");
}
event Beemaster::udp_event(rec: Beemaster::LatticeInfo, discriminant: count) {
    Beemaster::log("Got udp_event!");
}
event Broker::incoming_connection_established(peer_name: string) {
    print "Incoming connection established " + peer_name;
    Beemaster::log("Incoming connection established " + peer_name);
    add_to_balance(peer_name);
}
event Broker::incoming_connection_broken(peer_name: string) {
    print "Incoming connection broken for " + peer_name;
    Beemaster::log("Incoming connection broken for " + peer_name);
    remove_from_balance(peer_name);
}

# Log slave log_conn events to the master's conn.log
event Beemaster::log_conn(rec: Conn::Info) {
    Log::write(Conn::LOG, rec);
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

function add_to_balance(peer_name: string) {
    if(/bro-slave-/ in peer_name) {
        slaves[peer_name] = 0;

        print "Registered new slave ", peer_name;
        Beemaster::log("Registered new slave " + peer_name);
        log_balance("", peer_name);
        rebalance_all();
    }
    if(/beemaster-connector-/ in peer_name) {
        local min_count_conn = 100000;
        local best_slave = "";

        for(slave in slaves) {
            local count_conn = slaves[slave];
            if (count_conn < min_count_conn) {
                best_slave = slave;
                min_count_conn = count_conn;
            }
        }
        # add the connector, regardless if any slave is ready. Thus, at least a reference is stored, that will get rebalanced once a new slave registers.
        Broker::insert(connectors, Broker::data(peer_name), Broker::data(best_slave));
        if (best_slave != "") {
            ++slaves[best_slave];
            print "Registered connector", peer_name, "and balanced to", best_slave;
            log_balance(peer_name, best_slave);
            Beemaster::log("Registered connector " + peer_name + " and balanced to " + best_slave);
        }
        else {
            print "Could not balance connector", peer_name, "because no slaves are ready";
            Beemaster::log("Could not balance connector " + peer_name + " because no slaves are ready");
            log_balance(peer_name, "");
        }

    }
}

function remove_from_balance(peer_name: string) {
    if(/bro-slave-/ in peer_name) {
        delete slaves[peer_name];

        print "Unregistered old slave ", peer_name;
        Beemaster::log("Unregistered old slave " + peer_name + " ...");

        rebalance_all();
    }
    if(/beemaster-connector-/ in peer_name) {
        when(local cs = Broker::lookup(connectors, Broker::data(peer_name))) {
            local connected_slave = Broker::refine_to_string(cs$result);
            Broker::erase(connectors, Broker::data(peer_name));
            if (connected_slave == "") {
                # connector was registered, but no slave was there to handle it. If it now goes away, OK!
                print "Unregistered old connector", peer_name, "no connected slave found";
                Beemaster::log("Unregistered old connector " + peer_name + " no connected slave found");
                return;
            }
            local count_conn = slaves[connected_slave];
            if (count_conn > 0) {
                slaves[connected_slave] = count_conn - 1;
                print "Unregistered old connector", peer_name, "from slave", connected_slave;
                log_balance("", connected_slave);
                Beemaster::log("Unregistered old connector " + peer_name + " from slave " + connected_slave);
            }
        }
        timeout 100msec {
            print "Timeout unregistering connector", peer_name;
            Beemaster::log("Timeout unregistering connector " + peer_name);
        }
    }
}

function rebalance_all() {
    local total_slaves = |slaves|;
    local slave_vector: vector of string;
    slave_vector = vector();
    local i = 0;
    for (slave in slaves) {
        slave_vector[i] = slave;
        ++i;
    }
    i = 0;
    when (local keys = Broker::keys(connectors)) {
        local connector_vector: vector of string;
        connector_vector = vector();
        local total_connectors = Broker::vector_size(keys$result);
        while (i < total_connectors) {
            connector_vector[i] = Broker::refine_to_string(Broker::vector_lookup(keys$result, i));
            ++i;
        }
        if (total_slaves == 0) {
            print "No registered slaves found, invalidating all connectors";
            Beemaster::log("No registered slaves found, invalidating all connectors");
            local j = 0;
            while (j < i) {
                local connector = connector_vector[j];
                log_balance(connector, "");
                Broker::insert(connectors, Broker::data(connector), Broker::data(""));
                ++j;
            }
            return; # break out.
        }
        while (total_slaves > 0 && total_connectors > 0) {
            local balance_amount = total_connectors / total_slaves;
            if (total_connectors % total_slaves > 0) {
                balance_amount = total_connectors / total_slaves + 1;
            }
            --total_slaves;
            local balanced_to = slave_vector[total_slaves];
            slaves[balanced_to] = balance_amount;
            local balance_index = total_connectors - balance_amount; # do this once, do this here!
            while (total_connectors > balance_index) {
                --total_connectors;
                local rebalanced_conn = connector_vector[total_connectors];
                Broker::insert(connectors, Broker::data(rebalanced_conn), Broker::data(balanced_to));
                print "Rebalanced connector", rebalanced_conn, "to slave", balanced_to;
                log_balance(rebalanced_conn, balanced_to);
                Beemaster::log("Rebalanced connector " + rebalanced_conn + " to slave " + balanced_to);
            }
        }
    }
    timeout 100msec {
        Beemaster::log("ERROR: Unable to query keys in 'connectors-data-store' within 100ms, timeout");
    }
}

function log_balance(connector: string, slave: string) {
    local rec: BalanceLog::Info = [$connector=connector, $slave=slave];
    Log::write(BalanceLog::LOG, rec);
}
