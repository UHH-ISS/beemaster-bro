module Brolog;

export {
  redef enum Log::ID += { LOG };
  
  type Info: record {
    msg: string &log;
  };
}

event bro_init() &priority=5 {
  Log::create_stream(Brolog::LOG, [$columns=Info, $path="Brolog"]);
}
