module Beemaster;

export{
    redef enum Log::ID += { PORTSCAN_LOG };
    redef LogAscii::empty_field = "EMPTY";
    type PortscanAlertInfo: record {
        ts: time &log;
        attack: string &log;
        ips: vector of string &log;
    };
}
event bro_init() &priority=5 {
    Log::create_stream(PORTSCAN_LOG, [$columns=PortscanAlertInfo, $path="portscan_alert"]);
}