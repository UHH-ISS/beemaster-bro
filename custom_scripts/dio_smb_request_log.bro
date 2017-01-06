module Dio_smb_request;

export {
  redef enum Log::ID += { LOG };
  
  type Info: record {
    ts: time &log;
    id: string &log;
    local_ip: addr &log;
    local_port: port &log;
    remote_ip: addr &log; 
    remote_port: port &log;
    transport: string &log;
    opnum: count &log;
    uuid: string &log;
    origin: string &log;
    connector_id: string &log;
  };
}

event bro_init() &priority=5 {
  Log::create_stream(Dio_smb_request::LOG, [$columns=Info, $path="Dionaea_SMBRequest"]); 
}
