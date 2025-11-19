#include <boost/ut.hpp>
#include <grpcpp/grpcpp.h>

#include <cstdlib>
#include <memory>
#include <string>

#include "echo_stream.grpc.pb.h"

namespace {
using namespace boost::ut;
using hpp::proto::grpc::EchoRequest;
using hpp::proto::grpc::EchoResponse;
using hpp::proto::grpc::EchoStreamService;


class OfficialUnaryHarness {
public:
  OfficialUnaryHarness() {
    const char *endpoint = std::getenv("HPP_PROTO_GRPC_TEST_ENDPOINT");
    endpoint_ = endpoint;
    channel_ = ::grpc::CreateChannel(endpoint_, ::grpc::InsecureChannelCredentials());
    stub_ = EchoStreamService::NewStub(channel_);
  }

  ~OfficialUnaryHarness() {
    
  }

  EchoStreamService::Stub &stub() { return *stub_; }

private:
  std::string endpoint_;
  std::shared_ptr<::grpc::Channel> channel_;
  std::unique_ptr<EchoStreamService::Stub> stub_;
};

void run_official_unary_blocking_case() {
  OfficialUnaryHarness harness;
  ::grpc::ClientContext context;
  EchoRequest request;
  request.set_message("ping");
  request.set_sequence(41);

  EchoResponse response;
  auto status = harness.stub().UnaryEcho(&context, request, &response);

  expect(status.ok()) << status.error_message();
  expect(eq(response.sequence(), 42));
  expect(eq(response.message(), std::string{"ping-unary"}));
}

const suite official_unary_suite = [] {
  "unary_echo_official_blocking"_test = [] { run_official_unary_blocking_case(); };
};
} // namespace
