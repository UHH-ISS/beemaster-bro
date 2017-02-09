@load ./beemaster_events
@load ./beemaster_log
@load ./beemaster_util

@load ./log

redef exit_only_after_terminate = T;

# Broker setup
# the port and IP that are externally routable for this master
const public_broker_port: string = getenv("MASTER_PUBLIC_PORT") &redef;
const public_broker_ip: string = getenv("MASTER_PUBLIC_IP") &redef;
const broker_port: port = 9999/tcp &redef;
redef Broker::endpoint_name = cat("bro-master-", public_broker_ip, ":", public_broker_port);

# Loadbalancing
global slaves: table[string] of count;
global connectors: opaque of Broker::Handle;
global add_to_balance: function(peer_name: string);
global remove_from_balance: function(peer_name: string);
global rebalance_all: function();
global log_balance: function(connector: string, slave: string);

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

    # Subscribe to lattice events for logging
    Broker::subscribe_to_events_multi("beemaster/bro/lattice");

    # Subscribe to acu alerts
    Broker::subscribe_to_events_multi("beemaster/acu/alert");

    ## create a distributed datastore for the connector to link against:
    connectors = Broker::create_master("connectors");

    Beemaster::log("bro_master.bro: bro_init() done");
}
event bro_done() {
    Beemaster::log("bro_master.bro: bro_done()");
}

event Beemaster::dionaea_access(timestamp: time, local_ip: addr, local_port: count,
    remote_hostname: string, remote_ip: addr, remote_port: count, transport: string,
    protocol: string, connector_id: string)
{
    local lport: port = count_to_port(local_port, Beemaster::string_to_proto(transport));
    local rport: port = count_to_port(remote_port, Beemaster::string_to_proto(transport));

    local rec: Beemaster::DioAccessInfo = [$ts=timestamp, $local_ip=local_ip, $local_port=lport, $remote_hostname=remote_hostname, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $connector_id=connector_id];

    Log::write(Beemaster::DIO_ACCESS_LOG, rec);
}

event Beemaster::dionaea_blackhole(timestamp: time, id: string, local_ip: addr, local_port: count,
    remote_ip: addr, remote_port: count, transport: string, protocol: string, input: string,
    length: count, origin: string, connector_id: string)
{
    local lport: port = count_to_port(local_port, Beemaster::string_to_proto(transport));
    local rport: port = count_to_port(remote_port, Beemaster::string_to_proto(transport));

    local rec: Beemaster::DioBlackholeInfo = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $input=input, $length=length, $origin=origin, $connector_id=connector_id];

    Log::write(Beemaster::DIO_BLACKHOLE_LOG, rec);
}

event Beemaster::dionaea_download_complete(timestamp: time, id: string, local_ip: addr, local_port: count,
    remote_ip: addr, remote_port: count, transport: string, protocol: string,
    url: string, md5hash: string, filelocation: string, origin: string, connector_id: string)
{
    local lport: port = count_to_port(local_port, Beemaster::string_to_proto(transport));
    local rport: port = count_to_port(remote_port, Beemaster::string_to_proto(transport));

    local rec: Beemaster::DioDownloadCompleteInfo = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $url=url, $md5hash=md5hash, $filelocation=filelocation, $origin=origin, $connector_id=connector_id];

    Log::write(Beemaster::DIO_DOWNLOAD_COMPLETE_LOG, rec);
}

event Beemaster::dionaea_download_offer(timestamp: time, id: string, local_ip: addr, local_port: count,
    remote_ip: addr, remote_port: count, transport: string, protocol: string, url: string,
    origin: string, connector_id: string)
{
    local lport: port = count_to_port(local_port, Beemaster::string_to_proto(transport));
    local rport: port = count_to_port(remote_port, Beemaster::string_to_proto(transport));

    local rec: Beemaster::DioDownloadOfferInfo = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $url=url, $origin=origin, $connector_id=connector_id];

    Log::write(Beemaster::DIO_DOWNLOAD_OFFER_LOG, rec);
}

event Beemaster::dionaea_ftp(timestamp: time, id: string, local_ip: addr, local_port: count,
    remote_ip: addr, remote_port: count, transport: string, protocol: string,
    command: string, arguments: string, origin: string, connector_id: string)
{
    local lport: port = count_to_port(local_port, Beemaster::string_to_proto(transport));
    local rport: port = count_to_port(remote_port, Beemaster::string_to_proto(transport));

    local rec: Beemaster::DioFtpInfo = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $command=command, $arguments=arguments, $origin=origin, $connector_id=connector_id];

    Log::write(Beemaster::DIO_FTP_LOG, rec);
}

event Beemaster::dionaea_mysql_command(timestamp: time, id: string, local_ip: addr, local_port: count,
    remote_ip: addr, remote_port: count, transport: string, protocol: string, args: string,
    origin: string, connector_id: string)
{
    local lport: port = count_to_port(local_port, Beemaster::string_to_proto(transport));
    local rport: port = count_to_port(remote_port, Beemaster::string_to_proto(transport));

    local rec: Beemaster::DioMysqlCommandInfo = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $args=args, $origin=origin, $connector_id=connector_id];

    Log::write(Beemaster::DIO_MYSQL_COMMAND_LOG, rec);
}

event Beemaster::dionaea_login(timestamp: time, id: string, local_ip: addr, local_port: count,
    remote_ip: addr, remote_port: count, transport: string, protocol: string,
    username: string, password: string, origin: string, connector_id: string)
{
    local lport: port = count_to_port(local_port, Beemaster::string_to_proto(transport));
    local rport: port = count_to_port(remote_port, Beemaster::string_to_proto(transport));

    local rec: Beemaster::DioLoginInfo = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $username=username, $password=password, $origin=origin, $connector_id=connector_id];

    Log::write(Beemaster::DIO_LOGIN_LOG, rec);
}

event Beemaster::dionaea_smb_bind(timestamp: time, id: string, local_ip: addr, local_port: count,
    remote_ip: addr, remote_port: count, transport: string, protocol: string,
    transfersyntax: string, uuid: string, origin: string, connector_id: string)
{
    local lport: port = count_to_port(local_port, Beemaster::string_to_proto(transport));
    local rport: port = count_to_port(remote_port, Beemaster::string_to_proto(transport));

    local rec: Beemaster::DioSmbBindInfo = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $transfersyntax=transfersyntax, $uuid=uuid, $origin=origin, $connector_id=connector_id];

    Log::write(Beemaster::DIO_SMB_BIND_LOG, rec);
}

event Beemaster::dionaea_smb_request(timestamp: time, id: string, local_ip: addr, local_port: count,
    remote_ip: addr, remote_port: count, transport: string, protocol: string,
    opnum: count, uuid: string, origin: string, connector_id: string)
{
    local lport: port = count_to_port(local_port, Beemaster::string_to_proto(transport));
    local rport: port = count_to_port(remote_port, Beemaster::string_to_proto(transport));

    local rec: Beemaster::DioSmbRequestInfo = [$ts=timestamp, $id=id, $local_ip=local_ip, $local_port=lport, $remote_ip=remote_ip, $remote_port=rport, $transport=transport, $protocol=protocol, $opnum=opnum, $uuid=uuid, $origin=origin, $connector_id=connector_id];

    Log::write(Beemaster::DIO_SMB_REQUEST_LOG, rec);
}

event Beemaster::acu_meta_alert(timestamp: time, attack: string) {
    Beemaster::log("Got acu_meta_alert!");
    local rec: Beemaster::AcuAlertInfo = [$ts=timestamp, $attack=attack];
    Log::write(Beemaster::ACU_ALERT_LOG, rec);
}

event Beemaster::portscan_meta_alert(timestamp: time, attack: string, ips: vector of string) {
    local rec: Beemaster::PortscanAlertInfo = [$ts=timestamp, $attack=attack, $ips=ips];
    Log::write(Beemaster::PORTSCAN_ALERT_LOG, rec);
}

event Broker::incoming_connection_established(peer_name: string) {
    local msg: string = "Incoming_connection_established " + peer_name;
    Beemaster::log(msg);
    # Add new client to balance
    add_to_balance(peer_name);
}
event Broker::incoming_connection_broken(peer_name: string) {
    local msg: string = "Incoming_connection_broken " + peer_name;
    Beemaster::log(msg);
    # Remove disconnected client from balance
    remove_from_balance(peer_name);
}
event Broker::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string) {
    local msg: string = "Outgoing connection established to: " + peer_address;
    Beemaster::log(msg);
}
event Broker::outgoing_connection_broken(peer_address: string, peer_port: port, peer_name: string) {
    local msg: string = "Outgoing connection broken with: " + peer_address;
    Beemaster::log(msg);
}

# Log slave log_conn events to the master's conn.log
event Beemaster::log_conn(rec: Conn::Info) {
    Log::write(Conn::LOG, rec);
}

function add_to_balance(peer_name: string) {
    if(/bro-slave-/ in peer_name) {
        slaves[peer_name] = 0;

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
            log_balance(peer_name, best_slave);
            Beemaster::log("Registered connector " + peer_name + " and balanced to " + best_slave);
        }
        else {
            Beemaster::log("Could not balance connector " + peer_name + " because no slaves are ready");
            log_balance(peer_name, "");
        }

    }
}

function remove_from_balance(peer_name: string) {
    if(/bro-slave-/ in peer_name) {
        delete slaves[peer_name];

        Beemaster::log("Unregistered old slave " + peer_name + " ...");
        rebalance_all();
    }
    if(/beemaster-connector-/ in peer_name) {
        when(local cs = Broker::lookup(connectors, Broker::data(peer_name))) {
            local connected_slave = Broker::refine_to_string(cs$result);
            Broker::erase(connectors, Broker::data(peer_name));
            if (connected_slave == "") {
                # connector was registered, but no slave was there to handle it. If it now goes away, OK!
                Beemaster::log("Unregistered old connector " + peer_name + " no connected slave found");
                return;
            }
            local count_conn = slaves[connected_slave];
            if (count_conn > 0) {
                slaves[connected_slave] = count_conn - 1;
                log_balance("", connected_slave);
                Beemaster::log("Unregistered old connector " + peer_name + " from slave " + connected_slave);
            }
        }
        timeout 100msec {
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
    local rec: Beemaster::BalanceInfo = [$connector=connector, $slave=slave];
    Log::write(Beemaster::BALANCE_LOG, rec);
}
