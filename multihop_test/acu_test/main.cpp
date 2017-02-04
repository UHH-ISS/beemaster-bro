#include <iostream>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/time_point.hh>
#include <future>
#include <queue>


const char *ep_name = "cpp_peer";

std::string address = "127.0.0.1";
const uint16_t port = 9999;

class IncomingAlert {
public:
    IncomingAlert(const std::string *topic, const broker::message &msg) : topic(topic), message(msg) {}
private:
    const std::string *topic;
    const std::vector<broker::data> message;
};

class AlertMapper {
public:
    IncomingAlert* GetAlert(const std::string *topic, const broker::message &msg) const {
        return new IncomingAlert(topic, msg);
    }
};

void DoPeer(std::string address, uint16_t port, std::vector<std::string> *topics,
                  AlertMapper *mapper, std::queue<IncomingAlert*> *alertQueue) {

    auto endpoint = new broker::endpoint("acu_test",
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
                        std::cout << "blurbs" << std::endl;
                        auto alert = mapper->GetAlert(new std::string(topic), msg);
                        if (alert != nullptr) {
                            alertQueue->emplace(alert);
                        }
                    }
                }
            }
        }
    }
}

class Receiver {
private:
    std::string address;
    uint16_t port;
    std::vector<std::string> *topics;
    AlertMapper *mapper;

public:
    Receiver(std::string address, uint16_t port, std::vector<std::string>* topics, AlertMapper *mapper)
                : address(address), port(port), topics(topics), mapper(mapper) {};

    void Peer(std::queue<IncomingAlert*> *queue) {
        // Fork an asynchronous receiver, return control flow / execution to caller:
        std::thread(DoPeer, address, port, topics, mapper, queue).detach();
        return;
    }
};

int main() {
    broker::init();
    // receive:
    auto topic = "test/topic";
    auto topics = new std::vector<std::string>();
    topics->push_back(topic);
    Receiver *rec = new Receiver("127.0.0.1", 9999, topics, new AlertMapper());

    auto queue = new std::queue<IncomingAlert*>();
    rec->Peer(queue);

    std::cin.get();

    broker::done();
}