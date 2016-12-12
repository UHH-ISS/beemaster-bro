#include <iostream>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/time_point.hh>

const char *ep_name = "cpp_peer";

std::string address = "127.0.0.1";
const uint16_t port = 9999;

void verify_connection(broker::endpoint *ep) {
    auto conn_status = ep->outgoing_connection_status().need_pop();

    for (auto cs : conn_status) {
        if (cs.status == broker::outgoing_connection_status::tag::established)
            std::cout << "established connection to: " << cs.peer_name << std::endl;
        else
            std::cout << "connection error" << std::endl;
    }
}

void send_remote_event(broker::endpoint *ep) {
    std::cout << "sending remote_event" << std::endl;
    auto ts = broker::time_point::now();
    uint64_t id = 12345;
    auto local_ip = broker::address::from_string(address).get();
    uint64_t local_port = 1337;
    auto remote_ip = broker::address::from_string(address).get();
    uint64_t remote_port = 1337;
    std::string transport = "tcp";
    
    ep->send("honeypot/dionaea/", broker::message{"dionaea_connection", ts, id, local_ip, local_port, remote_ip, remote_port, transport});
}

int main() {
    broker::init();
    broker::endpoint ep(ep_name);

    ep.peer(address, port);
    verify_connection(&ep);

    send_remote_event(&ep);

    std::cin.get();

    broker::done();
}
