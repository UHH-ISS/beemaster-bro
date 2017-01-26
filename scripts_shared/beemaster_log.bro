module Beemaster;

export {
    redef enum Log::ID += { LOG };
    redef LogAscii::empty_field = "EMPTY";

    type LogInfo: record {
        msg: string &log;
    };

    global log: function(msg: string);
}

event bro_init() &priority=5 {
    Log::create_stream(LOG, [$columns=LogInfo, $path="beemaster"]);
}

function log(msg: string) {
    local rec: LogInfo = [$msg=msg];
    Log::write(LOG, rec);
}
