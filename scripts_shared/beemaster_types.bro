module Beemaster;

@load base/protocols/conn/main
@load base/utils/addrs

export {
    type AlertInfo: record {
        timestamp: time;
        source_ip: string;
        source_port: count;
        destination_ip: string;
        destination_port: count;
    };

    type LatticeInfo: record {
        timestamp: time;
        source_ip: string;
        source_port: count;
        destination_port: count;
        protocol : string;
    };

    global connid_to_alertinfo: function(input: conn_id, timestamp: time): AlertInfo;
    global connection_to_alertinfo: function(input: connection): AlertInfo;
    global conninfo_to_alertinfo: function(input: Conn::Info): AlertInfo;
    global connid_to_latticeinfo: function(input: conn_id, timestamp: time, proto : string): LatticeInfo;
		global connection_to_latticeinfo: function(input: connection, proto : string) : LatticeInfo;
    global conninfo_to_latticeinfo: function(input: Conn::Info, proto: string): LatticeInfo;
}

function connid_to_alertinfo(input: conn_id, timestamp: time): AlertInfo {
    return AlertInfo($timestamp = timestamp,
        $source_ip = addr_to_uri(input$orig_h), $source_port = port_to_count(input$orig_p),
        $destination_ip = addr_to_uri(input$resp_h), $destination_port = port_to_count(input$resp_p));
}

function connection_to_alertinfo(input: connection): AlertInfo {
    if (input?$conn) {
        return conninfo_to_alertinfo(input$conn);
    }
    return connid_to_alertinfo(input$id, input$start_time);
}

function conninfo_to_alertinfo(input: Conn::Info): AlertInfo {
    return connid_to_alertinfo(input$id, input$ts);
}

# create info record for lattice acu
function connection_to_latticeinfo(input: connection, proto : string): LatticeInfo {
    if (input?$conn) {
        return conninfo_to_latticeinfo(input$conn, proto);
    }
    return connid_to_latticeinfo(input$id, input$start_time, proto);
}
function connid_to_latticeinfo(input: conn_id, timestamp: time, proto : string): LatticeInfo{
    return LatticeInfo($timestamp = timestamp,
        $source_ip = addr_to_uri(input$orig_h), $source_port = port_to_count(input$orig_p),
        $destination_port = port_to_count(input$resp_p), $protocol = proto);
}
function conninfo_to_latticeinfo(input: Conn::Info, proto : string): LatticeInfo {
    return connid_to_latticeinfo(input$id, input$ts, proto);
}
