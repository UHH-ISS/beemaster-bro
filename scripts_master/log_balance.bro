module Beemaster;

export {
    redef enum Log::ID += { LOG_BALANCE };
    redef LogAscii::empty_field = "EMPTY";

    type LogInfoBalance: record {
        connector: string &log;
        slave: string &log;
    };

    global log_balance: function(connector: string, slave: string);
}

event bro_init() &priority=5 {
    Log::create_stream(LOG_BALANCE, [$columns=LogInfoBalance, $path="balance"]);
}

function log_balance(connector: string, slave: string) {
    local rec: LogInfoBalance = [$connector=connector, $slave=slave];
    Log::write(LOG_BALANCE, rec);
}
