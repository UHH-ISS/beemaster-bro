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
global slaves: table[string] of count;
global connectors: opaque of Broker::Handle;
global add_to_balance: function(peer_name: string);
global remove_from_balance: function(peer_name: string);

event bro_init() {
    log_bro("bro_receiver.bro: bro_init()");
    Broker::enable([$auto_publish=T]);

    Broker::listen(broker_port, "0.0.0.0");

    Broker::subscribe_to_events("bro/forwarder");

    ## create a distributed datastore for the connector to link against:
    connectors = Broker::create_master("connectors");

    log_bro("bro_receiver.bro: bro_init() done");
}
event bro_done() {
    log_bro("bro_receiver.bro: bro_done()");
}
event dionaea_access(timestamp: time, dst_ip: addr, dst_port: count, src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string) {
    local sport: port = count_to_port(src_port, get_protocol(transport));
    local dport: port = count_to_port(dst_port, get_protocol(transport));
    print fmt("dionaea_access: timestamp=%s, dst_ip=%s, dst_port=%s, src_hostname=%s, src_ip=%s, src_port=%s, transport=%s, protocol=%s, connector_id=%s", timestamp, dst_ip, dst_port, src_hostname, src_ip, src_port, transport, protocol, connector_id);
    local rec: Dio_access::Info = [$ts=timestamp, $dst_ip=dst_ip, $dst_port=dport, $src_hostname=src_hostname, $src_ip=src_ip, $src_port=sport, $transport=transport, $protocol=protocol, $connector_id=connector_id];

    Log::write(Dio_access::LOG, rec);
}
event dionaea_mysql(timestamp: time, id: string, local_ip: addr, local_port: count, remote_ip: addr, remote_port: count, transport: string, args: string, connector_id: string) {
    local lport: port = count_to_port(local_port, get_protocol(transport));
    local rport: port = count_to_port(remote_port, get_protocol(transport));
    print fmt("dionaea_mysql: timestamp=%s, id=%s, local_ip=%s, local_port=%s, remote_ip=%s, remote_port=%s, transport=%s, args=%s, connector_id=%s", timestamp, id, local_ip, local_port, remote_ip, remote_port, transport, args, connector_id);
    local rec: Dio_mysql::Info = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $args=args, $connector_id=connector_id];
    Log::write(Dio_mysql::LOG, rec);
}
event Broker::incoming_connection_established(peer_name: string) {
    log_bro("Incoming connection extablished " + peer_name);
    add_to_balance(peer_name);
}
event Broker::incoming_connection_broken(peer_name: string) {
    log_bro("Incoming connection broken for " + peer_name);
    remove_from_balance(peer_name);
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

function add_to_balance(peer_name: string) {
    if(/bro-slave-/ in peer_name) {
        print "Registering new slave ", peer_name;
        log_bro("Registering new slave " + peer_name);
        slaves[peer_name] = 0;
        local total_slaves = |slaves|;
        local slave_vector = vector();
        local i = 0;
        for (slave in slaves) {
            slave_vector[i] = slave;
            ++i;
        }
        i = 0;
        when (local keys = Broker::keys(connectors)) {
            local connector_vector = vector();
            local total_connectors = Broker::vector_size(keys$result);
            while (i < total_connectors) {
                connector_vector[i] = Broker::vector_lookup(keys$result, i);
                ++i;
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
                    local rebalanced_conn = Broker::refine_to_string(connector_vector[total_connectors]);
                    Broker::insert(connectors, Broker::data(rebalanced_conn), Broker::data(balanced_to));
                    print "Rebalanced connector", rebalanced_conn, "to slave", balanced_to;
                    #log_bro("Rebalanced connector " + rebalanced_conn + " to slave " + balanced_to);
                }
            }
        }
        timeout 100msec {
            log_bro("ERROR: Unable to query keys in 'connectors-data-store' within 100ms, timeout");
        }
        
    }
    if(/beemaster-connector-/ in peer_name) {
        print "Registering new connector ", peer_name;
        log_bro("Registering new connector " + peer_name);
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
            log_bro("Registered connector " + peer_name + " and balanced to " + best_slave);
        }
        else {
            print "Could not register connector", peer_name;
            log_bro("Could not register connector " + peer_name);
        }
        
    }
}

function remove_from_balance(peer_name: string) {
    if(/bro-slave-/ in peer_name) {
        log_bro("Unregistering old slave " + peer_name);
        delete slaves[peer_name];
        # TODO rebalance
    }
    if(/beemaster-connector-/ in peer_name) {
        when(local cs = Broker::lookup(connectors, Broker::data(peer_name))) {
            local connected_slave = Broker::refine_to_string(cs$result);
            Broker::erase(connectors, Broker::data(peer_name));
            if (connected_slave == "") {
                # connector was registered, but no slave was there to handle it. If it now goes away, OK!
                print "Unregistered old connector", peer_name, "no connected slave found";
                log_bro("Unregistered old connector " + peer_name + " no connected slave found");
                return;
            }
            local count_conn = slaves[connected_slave];
            if (count_conn > 0) {
                slaves[connected_slave] = count_conn - 1;
                print "Unregistered old connector", peer_name, "from slave", connected_slave;
                log_bro("Unregistered old connector " + peer_name + " from slave " + connected_slave);
            }
        }
        timeout 100msec {
            print "Timeout unregistering connector", peer_name;
            log_bro("Timeout unregistering connector " + peer_name);
        }
    }
}