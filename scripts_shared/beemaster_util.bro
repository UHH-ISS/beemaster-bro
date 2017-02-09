module Beemaster;

export {
    global proto_to_string: function(proto: transport_proto): string;
    global string_to_proto: function(proto: string): transport_proto;
}

function string_to_proto(proto: string) : transport_proto {
    # https://www.bro.org/sphinx/scripts/base/init-bare.bro.html#type-transport_proto
    if (proto == "tcp") {
        return tcp;
    }
    if (proto == "udp") {
        return udp;
    }
    if (proto == "icmp") {
        return icmp;
    }
    return unknown_transport;
}

function proto_to_string(proto: transport_proto) : string {
    # https://www.bro.org/sphinx/scripts/base/init-bare.bro.html#type-transport_proto
    if (proto == tcp) {
        return "tcp";
    }
    if (proto == udp) {
        return "udp";
    }
    if (proto == icmp) {
        return "icmp";
    }
    return "unknown_transport";
}
