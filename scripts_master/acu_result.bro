module Beemaster;

export{
    redef enum Log::ID += { ACU_LOG };
    redef LogAscii::empty_field = "EMPTY";

    type AcuResultInfo: record {
        ts: time &log;
        attack: string &log;
    };
}

event bro_init() &priority=5 {
    Log::create_stream(ACU_LOG, [$columns=AcuResultInfo, $path="acu_result"]);
}
