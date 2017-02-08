module Balance;

export {
  redef enum Log::ID += { LOG };
  redef LogAscii::empty_field = "EMPTY";

  type Info: record {
    connector: string &log;
    slave: string &log;
  };
}

event bro_init() &priority=5 {
  Log::create_stream(Balance::LOG, [$columns=Info, $path="balance"]);
}
