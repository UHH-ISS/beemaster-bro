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

    global connid_to_alertinfo: function(input: conn_id, timestamp: time): AlertInfo;
    global connection_to_alertinfo: function(input: connection): AlertInfo;
    global conninfo_to_alertinfo: function(input: Conn::Info): AlertInfo;
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
