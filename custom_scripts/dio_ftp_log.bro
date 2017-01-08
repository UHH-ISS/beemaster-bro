module Dio_ftp;

export {
  redef enum Log::ID += { LOG };
  redef LogAscii::empty_field = "EMPTY";
  
  type Commands: record {
    command: string &log;
    arguments: string &log;
  };
  
  type VectorCommands: vector of Commands;
  
  type Info: record {
    ts: time &log;
    dst_ip: addr &log;
    dst_port: port &log;
    src_hostname: string &log;
    src_ip: addr &log;
    src_port: port &log; 
    transport: string &log;
    protocol: string &log;
    commands: Dio_ftp::VectorCommands;
    connector_id: string &log;
  };
}

event bro_init() &priority=5 {
  Log::create_stream(Dio_ftp::LOG, [$columns=Info, $path="Dionaea_FTP"]); 
}
