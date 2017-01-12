module Dio_mysql;

export {
  redef enum Log::ID += { LOG };
  redef LogAscii::empty_field = "EMPTY";
  
  type Info: record {
    ts: time &log;
    id: string &log;
    local_ip: addr &log;
    local_port: port &log;
    remote_ip: addr &log; 
    remote_port: port &log;
    transport: string &log;
    protocol: string &log;
    args: string &log;
    connector_id: string &log;
  };
}

event bro_init() &priority=5 {
  Log::create_stream(Dio_mysql::LOG, [$columns=Info, $path="dionaea_mysql"]);
}