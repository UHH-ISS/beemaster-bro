module Dio_access;

export {
  redef enum Log::ID += { LOG };
  
  type Info: record {
    ts: time &log;
    dst_ip: time &log;
    dst_port: string &log;
    src_hostname: addr &log;
    src_ip: port &log;
    src_port: addr &log; 
    remote_port: port &log;
    transport: string &log;
    protocol: string &log;
    connector_id: string &log;
  };
}

event bro_init() &priority=5 {
  Log::create_stream(Dio_access::LOG, [$columns=Info, $path="dionaea_access"]); 
}
