#include <iostream>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/time_point.hh>
#include <future>


const char *ep_name = "cpp_peer";

std::string address = "127.0.0.1";
const uint16_t port = 9999;

void DoPeer(std::string address, uint16_t port, std::vector<std::string> *topics) {
    auto endpoint = new broker::endpoint("ACU_TEST",
                                         broker::AUTO_ROUTING | broker::AUTO_PUBLISH | broker::AUTO_ADVERTISE);
    endpoint->peer(address.c_str(), port);

    auto queues = new std::vector<broker::message_queue*>();
    for (auto &topic : *topics) {
        queues->push_back(new broker::message_queue(topic, *endpoint, broker::GLOBAL_SCOPE));
    }

    fd_set fds;
    for (;;) {
        // Init fds
        FD_ZERO(&fds);
        for (auto q : *queues) {
            FD_SET(q->fd(), &fds);
        }
        // Block until at least one alertQueue is ready to read
        auto result = select(FD_SETSIZE, &fds, nullptr, nullptr, nullptr);
        if (result == -1) {
            //TODO: Report error?
            return;
        }

        // Find readable queues
        for (auto &q : *queues) {
            if (FD_ISSET(q->fd(), &fds)) {
                auto topic = q->get_topic_prefix();
                if (q->get_topic_prefix() != "") {
                    for (auto &msg : q->want_pop()) {
                        std::cout << "Hurra" << std::endl;
                    }
                }
            }
        }
    }
}

void Peer(std::string address, uint16_t port, std::vector<std::string> *topics) {
    // Fork an asynchronous receiver, return control flow / execution to caller:
    std::thread(DoPeer, address, port, topics).detach();
    return;
}

int main() {
    broker::init();
    // receive:
    auto topic = "test/topic";
    auto topics = new std::vector<std::string>();
    topics->push_back(topic);

    Peer(address, port, topics);

    std::cin.get();

    broker::done();
}
