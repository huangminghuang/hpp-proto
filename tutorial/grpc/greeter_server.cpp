
#include <condition_variable>
#include <iostream>
#include <memory>
#include <string>

#include "helloworld.service.hpp"
#include <hpp_proto/grpc/server.hpp>

// Additional guidance lives in include/hpp_proto/grpc/README.md.
static const ::grpc::Status name_not_specified_status{::grpc::StatusCode::INVALID_ARGUMENT, "name is not specified"};

namespace helloworld::Greeter {

class Service : public ::hpp::proto::grpc::CallbackService<Service, _methods> {
  std::mutex mu_;
  std::condition_variable shutdown_cv_;
  bool done_ = false;

public:
  // define the callback handler for SayHello
  struct SayHelloHandler {
    SayHelloHandler(Service &, ::hpp::proto::grpc::ServerRPC<SayHello> &rpc,
                    ::hpp::proto::grpc::RequestToken<SayHello> token) {
      std::cerr << "rpc_handler<SayHello> called\n";
      helloworld::HelloRequest request;
      auto status = token.get(request);
      if (status.ok()) {
        if (request.name.empty()) {
          rpc.finish(name_not_specified_status);
        } else {
          using namespace std::string_literals;
          helloworld::HelloReply reply{.message = "Hello "s + request.name};
          rpc.finish(reply);
        }
      } else {
        rpc.finish(status);
        std::cerr << "request serialization error\n";
      }
    }
  };
  // declare to use SayHelloHandler to handle SayHello
  auto handle(SayHello) -> SayHelloHandler;

  // define the callback handler for SayHelloStreamReply
  struct SayHelloStreamReplyHandler {
    std::mutex mx;
    int count = 10;
    std::string message;
    using rpc_t = ::hpp::proto::grpc::ServerRPC<SayHelloStreamReply>;

    SayHelloStreamReplyHandler(Service &, rpc_t &rpc, ::hpp::proto::grpc::RequestToken<SayHelloStreamReply> token) {
      std::pmr::monotonic_buffer_resource mr;
      helloworld::HelloRequest<hpp::proto::non_owning_traits> request;
      auto status = token.get(request, hpp::proto::alloc_from(mr));
      if (status.ok()) {
        if (request.name.empty()) {
          rpc.finish(name_not_specified_status);
        } else {
          std::unique_lock lock(mx);
          message = "Hello " + std::string{request.name};
          using Reply = helloworld::HelloReply<hpp::proto::non_owning_traits>;
          rpc.write(Reply{.message = this->message});
        }
      } else {
        rpc.finish(status);
      }
    }

    void on_write_ok(rpc_t &rpc) {
      std::unique_lock lock(mx);
      count--;
      if (count == 0) {
        rpc.finish(::grpc::Status::OK);
      } else {
        using Reply = helloworld::HelloReply<hpp::proto::non_owning_traits>;
        rpc.write(Reply{.message = message});
      }
    }

    void on_cancel() const {
      // Called from ServerBidiReactor::OnCancel()
      // handle cancel events if desired
    }

    void on_send_initial_metadata_done(bool /* ok */) const {
      // Called from ServerBidiReactor::OnSendInitialMetadataDone()
      // handle send initial metadata done event if desired
    }
  };
  // declare to use SayHelloStreamReplyHandler to handle SayHelloStreamReply
  auto handle(SayHelloStreamReply) -> SayHelloStreamReplyHandler;

  // define the handler to handle Shutdown
  struct ShutdownHandler {
    Service *service;
    explicit ShutdownHandler(Service &service, ::hpp::proto::grpc::ServerRPC<Shutdown> &rpc,
                             ::hpp::proto::grpc::RequestToken<Shutdown> token)
        : service(&service) {
      rpc.finish(google::protobuf::Empty{});
    }
    void on_done() const { service->notify_done(); }
  };
  // declare to use ShutdownHandler to handle Shutdown
  auto handle(Shutdown) -> ShutdownHandler;

  void notify_done() {
    std::unique_lock<std::mutex> lock(mu_);
    done_ = true;
    shutdown_cv_.notify_all();
  }

  void wait() {
    std::unique_lock<std::mutex> lock(mu_);
    shutdown_cv_.wait(lock, [this] { return done_; });
  }
};

} // namespace helloworld::Greeter

void RunServer(const char *server_address) {
  helloworld::Greeter::Service greeter_service;
  ::grpc::EnableDefaultHealthCheckService(true);
  ::grpc::ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, ::grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&greeter_service);
  // Finally assemble the server.
  std::unique_ptr<::grpc::Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << "\n";

  greeter_service.wait();
  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  std::cout << "Server shutting down\n";
  server->Shutdown();
}

int main(int argc, char **argv) {
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  const char *endpoint = (argc == 2) ? argv[1] : "localhost:50051";
  if (argc > 2) {
    std::cerr << "Usage: " << argv[0] << " <hostname:port>\n";
    return 1;
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  RunServer(endpoint);
  return 0;
}
