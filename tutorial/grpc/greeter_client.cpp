#include <grpcpp/generic/generic_stub.h>
#include <grpcpp/grpcpp.h>

#include <condition_variable>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>

#include "helloworld.service.hpp"

template <typename Method>
::grpc::Status unary_call(::grpc::GenericStub *stub, typename Method::request &request,
                          typename Method::response &response,
                          hpp::proto::concepts::is_option_type auto &&...response_option) {
  ::grpc::Status status;
  ::grpc::ByteBuffer request_buffer;
  status = hpp::proto::grpc_support::write_proto(request, request_buffer);
  if (!status.ok()) {
    return status;
  }

  ::grpc::ClientContext context;
  std::mutex mu;
  std::condition_variable cv;
  bool done = false;
  ::grpc::ByteBuffer response_buffer;

  stub->UnaryCall(&context, Method::method_name, grpc::StubOptions(), &request_buffer, &response_buffer,
                  [&](::grpc::Status s) {
                    status = std::move(s);
                    std::lock_guard<std::mutex> lock(mu);
                    done = true;
                    cv.notify_one();
                  });
  std::unique_lock<std::mutex> lock(mu);
  // NOLINTNEXTLINE(bugprone-infinite-loop)
  while (!done) {
    cv.wait(lock);
  }

  if (!status.ok()) {
    return status;
  }

  return hpp::proto::grpc_support::read_proto(response, response_buffer, response_option...);
}

template <typename Method, typename OnResponseCallback>
class ServerStreamingClientReactor : public ::grpc::ClientBidiReactor<grpc::ByteBuffer, grpc::ByteBuffer> {
public:
  ServerStreamingClientReactor(Method, ::grpc::GenericStub *stub, ::grpc::ClientContext &context,
                               const typename Method::request &req, OnResponseCallback &&on_response)
      : context_(context), on_response_(std::move(on_response)) {
    if (auto status = hpp::proto::grpc_support::write_proto(req, req_buf_); !status.ok()) {
      result_ = status;
      return;
    }
    grpc::StubOptions options;
    stub->PrepareBidiStreamingCall(&context, Method::method_name, options, this);
  }

  void Start() {
    if (result_.has_value()) {
      return;
    }
    StartWrite(&req_buf_);
    StartRead(&res_buf_);
    StartCall();
  }

  grpc::Status WaitForDone() {
    std::unique_lock lock(mu_);

    cv_.wait(lock, [&] { return result_.has_value(); });
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    return *result_;
  }

  void OnReadDone(bool ok) override {
    if (!ok) {
      return;
    }

    typename Method::response res;
    if (auto status = hpp::proto::grpc_support::read_proto(res, res_buf_); !status.ok()) {
      context_.TryCancel();
      std::unique_lock lock(mu_);
      result_ = status;
      return;
    }
    on_response_(res);
    StartRead(&res_buf_);
  }

  void OnDone(const grpc::Status &status) override {
    std::unique_lock lock(mu_);
    if (!result_.has_value()) {
      result_ = status;
    }
    cv_.notify_one();
  }

private:
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  ::grpc::ClientContext &context_;
  std::mutex mu_;
  std::condition_variable cv_;
  std::optional<grpc::Status> result_;
  grpc::ByteBuffer req_buf_;
  grpc::ByteBuffer res_buf_;
  OnResponseCallback on_response_;
};

class GreeterClient {
public:
  explicit GreeterClient(const std::shared_ptr<::grpc::Channel> &channel) : stub_(new ::grpc::GenericStub(channel)) {}

  // Assembles the client's payload, sends it and prints the response back
  // from the server.
  void SayHello(const std::string &user) {
    // Data we are sending to the server.
    helloworld::HelloRequest request;
    request.name = user;
    // Container for the data we expect from the server.
    helloworld::HelloReply reply;

    auto status = unary_call<helloworld::Greeter::SayHello>(stub_.get(), request, reply);

    // Handles the reply
    if (status.ok()) {
      std::cout << "SayHello Ok. ReplyMessage=" << reply.message << "\n";
    } else {
      std::cout << "SayHello Failed. Code=" << status.error_code() << " Message=" << status.error_message() << "\n";
    }
  }

  void SayHelloStreamReply(const std::string &user) {
    helloworld::HelloRequest req;
    req.name = user;
    ::grpc::ClientContext context;
    ServerStreamingClientReactor reactor(helloworld::Greeter::SayHelloStreamReply{}, stub_.get(), context, req,
                                         [](helloworld::HelloReply &reply) {
                                           std::cout << "Received reply: " << reply.message << "\n";
                                           sleep(1);
                                         });
    reactor.Start();
    auto status = reactor.WaitForDone();
    if (status.ok()) {
      std::cout << "SayHelloStreamReply Success\n";
    } else {
      std::cerr << "SayHelloStreamReply Failed with error: " << status.error_message() << "\n";
    }
  }

  void Shutdown() {
    helloworld::Greeter::Shutdown::request req;
    helloworld::Greeter::Shutdown::response res;
    auto status = unary_call<helloworld::Greeter::Shutdown>(stub_.get(), req, res);
    if (status.ok()) {
      std::cout << "Shutdown Ok\n";
    } else {
      std::cerr << "Shutdown Failed with error: " << status.error_message() << "\n";
    }
  }

private:
  // Instead of `Greeter::Stub`, it uses `GenericStub` to send any calls.
  std::unique_ptr<::grpc::GenericStub> stub_;
};

int main(int argc, char **argv) {
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  const char *endpoint = (argc == 2) ? argv[1] : "localhost:50051";
  if (argc > 2) {
    std::cerr << "Usage: " << argv[0] << " <hostname:port>\n";
    return 1;
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  GreeterClient greeter(grpc::CreateChannel(endpoint, grpc::InsecureChannelCredentials()));
  greeter.SayHello("World");
  greeter.SayHello("gRPC");
  greeter.SayHelloStreamReply("World");
  greeter.Shutdown();
  return 0;
}
