#include "helloworld.service.hpp"
#include <hpp_proto/grpc/client.hpp>
#include <iostream>
#include <iterator>
#include <memory>

// See include/hpp_proto/grpc/README.md for adapter usage and streaming best practices.
namespace helloworld::Greeter {

class Client {
  ::hpp::proto::grpc::Stub<_methods> stub_;

public:
  explicit Client(const std::shared_ptr<::grpc::Channel> &channel, ::grpc::StubOptions options)
      : stub_(channel, options) {}

  // Assembles the client's payload, sends it and prints the response back
  // from the server.
  void SayHello(const std::string &user) {
    // Data we are sending to the server.
    helloworld::HelloRequest<hpp::proto::non_owning_traits> request;
    request.name = user;
    // Container for the data we expect from the server.
    std::pmr::monotonic_buffer_resource mr;
    helloworld::HelloReply<hpp::proto::non_owning_traits> reply;

    ::grpc::ClientContext context;

    auto status = stub_.call<::helloworld::Greeter::SayHello>(context, request, reply, hpp::proto::alloc_from{mr});

    // Handles the reply
    if (status.ok()) {
      std::cout << "SayHello Ok. ReplyMessage=" << reply.message << "\n";
    } else {
      std::cout << "SayHello Failed. Code=" << status.error_code() << " Message=" << status.error_message() << "\n";
    }
  }

  void SayHelloStreamReply(const std::string &user) {

    class SayHelloStreamReplyReactor
        : public ::hpp::proto::grpc::ClientCallbackReactor<::helloworld::Greeter::SayHelloStreamReply> {
      std::mutex mu_;
      std::condition_variable cv_;
      ::grpc::Status result_;
      bool has_result_ = false;

    public:
      ::grpc::ClientContext context;
      SayHelloStreamReplyReactor() = default;
      SayHelloStreamReplyReactor(const SayHelloStreamReplyReactor &) = delete;
      SayHelloStreamReplyReactor &operator=(const SayHelloStreamReplyReactor &) = delete;
      SayHelloStreamReplyReactor(SayHelloStreamReplyReactor &&) = delete;
      SayHelloStreamReplyReactor &operator=(SayHelloStreamReplyReactor &&) = delete;

      void start() {
        this->start_read();
        this->start_call();
      }

      ~SayHelloStreamReplyReactor() override {
        std::unique_lock lock(mu_);
        cv_.wait(lock, [&] { return has_result_; });
        const auto &result = result_;
        if (result.ok()) {
          std::cout << "SayHelloStreamReply Success\n";
        } else {
          std::cerr << "SayHelloStreamReply Failed with error: " << result.error_message() << "\n";
        }
      }

      void OnReadDone(bool ok) override {
        if (!ok) {
          return;
        }

        std::pmr::monotonic_buffer_resource mr;
        helloworld::HelloReply<hpp::proto::non_owning_traits> reply;
        auto r = this->get_response(reply, hpp::proto::alloc_from(mr));
        if (!r.ok()) {
          context.TryCancel();
          std::unique_lock lock(mu_);
          result_ = std::move(r);
          has_result_ = true;
          return;
        }
        std::cout << "Received reply: " << reply.message << "\n";
        sleep(1);
        start_read();
      }

      void OnDone(const ::grpc::Status &status) override {
        std::unique_lock lock(mu_);
        if (!has_result_) {
          result_ = status;
          has_result_ = true;
        }
        cv_.notify_one();
      }

    } reactor;
    helloworld::HelloRequest<hpp::proto::non_owning_traits> request;
    request.name = user;
    // See README streaming cookbook for write/read sequencing rules.
    stub_.async_call(reactor.context, request, &reactor);
    reactor.start();
  }

  void Shutdown() {
    ::google::protobuf::Empty empty{};
    ::grpc::ClientContext context;

    auto status = stub_.call<helloworld::Greeter::Shutdown>(context, empty, empty);
    if (status.ok()) {
      std::cout << "Shutdown Ok\n";
    } else {
      std::cerr << "Shutdown Failed with error: " << status.error_message() << "\n";
    }
  }
};
}; // namespace helloworld::Greeter

int main(int argc, char **argv) {
  const auto *endpoint = "localhost:50051";
  if (argc == 2) {
    endpoint = *std::next(argv);
  } else if (argc > 2) {
    std::cerr << "Usage: " << *argv << " <hostname:port>\n";
    return 1;
  }

  helloworld::Greeter::Client greeter(::grpc::CreateChannel(endpoint, ::grpc::InsecureChannelCredentials()),
                                      ::grpc::StubOptions{});
  greeter.SayHello("World");
  greeter.SayHello("gRPC");
  greeter.SayHelloStreamReply("World");
  greeter.Shutdown();
  return 0;
}
