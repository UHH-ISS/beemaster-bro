module Dio_access;

export {
  redef enum Log::ID += { LOG };
  redef LogAscii::empty_field = "EMPTY";
  
  type Info: record {
    ts: time &log;
    dst_ip: addr &log;
    dst_port: port &log;
    src_hostname: string &log;
    src_ip: addr &log;
    src_port: port &log; 
    transport: string &log;
    protocol: string &log;
    connector_id: string &log;
  };
}

event bro_init() &priority=5 {
  Log::create_stream(Dio_access::LOG, [$columns=Info, $path="dionaea_access"]); 
}
