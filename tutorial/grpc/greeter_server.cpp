#include <grpcpp/generic/async_generic_service.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include <condition_variable>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_set>

#include "helloworld.service.hpp"

template <typename Method, typename ServiceImpl>
class ServerUnaryCallReactor : public ::grpc::ServerGenericBidiReactor {
  ServiceImpl *service_;
  using Request = typename Method::request;
  using Response = typename Method::response;
  using member_fun_t = grpc::Status (ServiceImpl::*)(const Request &, Response &);
  member_fun_t fun_;

public:
  constexpr static auto method_name = Method::method_name;
  ServerUnaryCallReactor(ServiceImpl *s, member_fun_t fun) : service_(s), fun_(fun) { StartRead(&request_); }

private:
  void OnDone() override { delete this; }
  void OnReadDone(bool ok) override {
    if (!ok) {
      return;
    }
    grpc::Status result;
    // Deserialize a request message
    Request request;
    result = hpp::proto::grpc_support::read_proto(request, request_);
    if (!result.ok()) {
      Finish(result);
      return;
    }
    // Call the response handler
    Response reply;
    result = (service_->*fun_)(request, reply);
    if (!result.ok()) {
      Finish(result);
      return;
    }
    // Serialize a reply message
    result = hpp::proto::grpc_support::write_proto(reply, response_);
    if (!result.ok()) {
      Finish(result);
      return;
    }
    StartWrite(&response_);
  }
  void OnWriteDone(bool ok) override {
    Finish(ok ? grpc::Status::OK : grpc::Status(grpc::StatusCode::UNKNOWN, "Unexpected failure"));
  }
  ::grpc::ByteBuffer request_;
  ::grpc::ByteBuffer response_;
};

template <typename Method, typename ServiceImpl, typename Writer>
class ServerStreamReactor : public ::grpc::ServerGenericBidiReactor {
  using member_fun_t = void (ServiceImpl::*)(const typename Method::request &, Writer &, ServerStreamReactor &);

public:
  constexpr static auto method_name = Method::method_name;
  ServerStreamReactor(ServiceImpl *s, member_fun_t on_read_done) : service_(s), on_read_done_(on_read_done) {
    StartRead(&buffer_);
  }

  void OnReadDone(bool ok) override {
    if (!ok) {
      return;
    }
    grpc::Status result;
    // Deserialize a request message
    typename Method::request request;
    result = hpp::proto::grpc_support::read_proto(request, buffer_);
    if (!result.ok()) {
      Finish(result);
      return;
    }
    // Call the response handler
    (service_->*on_read_done_)(request, writer_, *this);
  }

  void Write(const typename Method::response &reply) {
    hpp::proto::grpc_support::write_proto(reply, buffer_);
    StartWrite(&buffer_);
  }

  void OnWriteDone(bool ok) override {
    if (!ok) {
      Finish(grpc::Status::OK);
    }
    writer_(*this);
  }

  void OnDone() override { delete this; }

private:
  ::grpc::ByteBuffer buffer_;
  ServiceImpl *service_;
  member_fun_t on_read_done_;
  Writer writer_;
};

using reactor_factory_t = std::function<::grpc::ServerGenericBidiReactor *()>;
// Logic and data behind the server's behavior.
class GenericService : public ::grpc::CallbackGenericService {
  std::unordered_map<std::string_view, reactor_factory_t> reactor_factories_;

public:
  ::grpc::ServerGenericBidiReactor *CreateReactor(::grpc::GenericCallbackServerContext *context) override {
    if (auto it = reactor_factories_.find(context->method()); it != reactor_factories_.end()) {
      return it->second();
    } else {
      // Forward this to the implementation of the base class returning
      // UNIMPLEMENTED.
      return CallbackGenericService::CreateReactor(context);
    }
  }

  template <typename Factory>
  void add_reactor_factory(Factory &&factory) {
    constexpr auto method_name = std::remove_pointer_t<decltype(factory())>::method_name;
    reactor_factories_.emplace(method_name, std::forward<Factory>(factory));
  }
};

class GreeterServiceImpl {
  struct SayHelloStreamReplyWriter {
    std::string name;
    std::atomic<int> count{10};

    void operator()(auto &reactor) {
      int n = count--;
      if (n == 0) {
        reactor.Finish(grpc::Status::OK);
        std::cout << "SayHelloStreamReply Finished" << std::endl;
      } else {
        helloworld::HelloReply reply;
        reply.message = "Hello " + name + " " + std::to_string(n);
        std::cout << "SayHelloStreamReply Sending reply: " << reply.message << std::endl;
        reactor.Write(reply);
      }
    }
  };

  std::mutex mu_;
  std::condition_variable shutdown_cv_;
  bool done_ = false;

public:
  GreeterServiceImpl(GenericService &service) {
    service.add_reactor_factory([&] {
      return new ServerUnaryCallReactor<helloworld::Greeter::SayHello, GreeterServiceImpl>{
          this, &GreeterServiceImpl::SayHello};
    });
    service.add_reactor_factory([&] {
      return new ServerStreamReactor<helloworld::Greeter::SayHelloStreamReply, GreeterServiceImpl,
                                     SayHelloStreamReplyWriter>(this, &GreeterServiceImpl::SayHelloStreamReply);
    });

    service.add_reactor_factory([&] {
      return new ServerUnaryCallReactor<helloworld::Greeter::Shutdown, GreeterServiceImpl>(
          this, &GreeterServiceImpl::Shutdown);
    });
  }
  grpc::Status SayHello(const helloworld::HelloRequest &request, helloworld::HelloReply &reply) {
    if (request.name == "") {
      return grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "name is not specified");
    }
    reply.message = "Hello " + request.name;
    return grpc::Status::OK;
  }

  void SayHelloStreamReply(const helloworld::HelloRequest &request, SayHelloStreamReplyWriter &writer, auto &reactor) {
    if (request.name == "") {
      reactor.Finish(grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "name is not specified"));
    } else {
      std::cout << "SayHelloStreamReply Started" << std::endl;
      writer.name = request.name;
      writer(reactor);
    }
  }

  grpc::Status Shutdown(const google::protobuf::Empty &request, google::protobuf::Empty &reply) {
    std::unique_lock<std::mutex> lock(mu_);
    done_ = true;
    shutdown_cv_.notify_all();
    return grpc::Status::OK;
  }

  void wait() {
    std::unique_lock<std::mutex> lock(mu_);
    shutdown_cv_.wait(lock, [this] { return done_; });
  }
};

void RunServer(const char *server_address) {
  GenericService service;
  GreeterServiceImpl greeter_service(service);
  grpc::EnableDefaultHealthCheckService(true);
  ::grpc::ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterCallbackGenericService(&service);
  // Finally assemble the server.
  std::unique_ptr<::grpc::Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  greeter_service.wait();
  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  std::cout << "Server shutting down" << std::endl;
  server->Shutdown();
}

int main(int argc, char **argv) {
  const char *endpoint = (argc == 2) ? argv[1] : "localhost:50051";
  if (argc > 2) {
    std::cerr << "Usage: " << argv[0] << " <hostname:port>\n";
    return 1;
  }
  RunServer(endpoint);
  return 0;
}
