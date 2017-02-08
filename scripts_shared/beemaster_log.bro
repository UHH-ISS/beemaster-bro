module Beemaster;

export {
    redef enum Log::ID += { LOG };
    redef LogAscii::empty_field = "EMPTY";

    type Info: record {
        msg: string &log;
    };

    global log: function(msg: string);
}

event bro_init() &priority=5 {
    Log::create_stream(Beemaster::LOG, [$columns=Info, $path="beemaster"]);
}

function log(msg: string) {
    Log::write(LOG, [$msg=msg]);
}
