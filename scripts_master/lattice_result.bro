module Lattice_result;

export{
  redef enum Log::ID += { LOG };
  redef LogAscii::empty_field = "EMPTY";
  
  type Info: record {
    ts: time &log;
    attack: string &log;
  };
}

event bro_init() &priority=5 {
  Log::create_stream(Lattice_result::LOG, [$columns=Info, $path="lattice_result"]);
}
