#include <boost/ut.hpp>
#include <grpcpp/grpcpp.h>

#include <hpp_proto/grpc/client.hpp>
#include <hpp_proto/grpc/server.hpp>

#include "echo_stream.pb.hpp"
#include "echo_stream.service.hpp"

namespace {
using EchoMethods = hpp_proto_test::EchoStreamService::_methods;
using UnaryEcho = hpp_proto_test::EchoStreamService::UnaryEcho;
using EchoRequest = hpp_proto_test::EchoRequest<>;
using EchoResponse = hpp_proto_test::EchoResponse<>;

class FailingService : public ::hpp_proto::grpc::CallbackService<FailingService, EchoMethods> {
public:
  struct UnaryHandler {
    using rpc_t = ::hpp_proto::grpc::ServerRPC<UnaryEcho>;
    UnaryHandler(FailingService &, rpc_t &rpc, ::hpp_proto::grpc::RequestToken<UnaryEcho> /*token*/) {
      EchoResponse response;
      response.message = std::string{"\xFF"};
      response.sequence = 1;
      rpc.finish(response);
    }
  };

  auto handle(UnaryEcho) -> UnaryHandler;
};

class FailureHarness {
public:
  using stub_type = ::hpp_proto::grpc::Stub<EchoMethods>;

  FailureHarness(const FailureHarness &) = delete;
  FailureHarness &operator=(const FailureHarness &) = delete;
  FailureHarness(FailureHarness &&) = delete;
  FailureHarness &operator=(FailureHarness &&) = delete;

  FailureHarness() {
    ::grpc::ServerBuilder builder;
    int selected_port = 0;
    builder.AddListeningPort("127.0.0.1:0", ::grpc::InsecureServerCredentials(), &selected_port);
    builder.RegisterService(&service_);
    server_ = builder.BuildAndStart();
    const std::string target = "127.0.0.1:" + std::to_string(selected_port);
    channel_ = ::grpc::CreateChannel(target, ::grpc::InsecureChannelCredentials());
    stub_ = std::make_unique<stub_type>(channel_, options_);
  }

  ~FailureHarness() {
    if (server_) {
      server_->Shutdown();
      server_->Wait();
    }
  }

  stub_type &stub() { return *stub_; }

private:
  FailingService service_;
  std::unique_ptr<::grpc::Server> server_;
  std::shared_ptr<::grpc::Channel> channel_;
  ::grpc::StubOptions options_;
  std::unique_ptr<stub_type> stub_;
};

const boost::ut::suite grpc_server_failure_tests = [] {
  using namespace boost::ut;

  "unary_serialization_failure_returns_internal"_test = [] {
    FailureHarness harness;
    EchoRequest request;
    request.message = "hello";
    request.sequence = 0;
    EchoResponse response;
    ::grpc::ClientContext context;
    auto status = harness.stub().call<UnaryEcho>(context, request, response);
    expect(status.error_code() == ::grpc::StatusCode::INTERNAL);
  };
};
} // namespace
