module Lattice;

export {
    redef enum Log::ID += { LOG };
    redef LogAscii::empty_field = "EMPTY";

    type Info: record {
        msg: string &log;
    };

    global log: function(msg: string);
}

event bro_init() &priority=5 {
    Log::create_stream(Lattice::LOG, [$columns=Info, $path="lattice"]);
}

function log(msg: string) {
    local rec: Info = [$msg=msg];
    Log::write(LOG, rec);
}
