#include <boost/ut.hpp>
#include <grpcpp/grpcpp.h>

#include <atomic>
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

namespace unit_test_detail {
struct fake_context {
  bool cancelled = false;
  [[nodiscard]] bool IsCancelled() const { return cancelled; }
};

struct fake_client_stream_method {
  static constexpr auto rpc_type = hpp_proto::grpc::RpcType::CLIENT_STREAMING;
  static constexpr bool client_streaming = true;
  template <typename>
  using request_t = EchoRequest;
  template <typename>
  using response_t = EchoResponse;
};

struct fake_server_stream_method {
  static constexpr auto rpc_type = hpp_proto::grpc::RpcType::SERVER_STREAMING;
  static constexpr bool client_streaming = false;
  static constexpr bool server_streaming = true;
  template <typename>
  using request_t = EchoRequest;
  template <typename>
  using response_t = EchoResponse;
};

struct cancel_read_state {
  std::atomic<int> on_read_cancel_calls{0};
};

struct write_error_state {
  std::atomic<int> on_write_error_calls{0};
};
} // namespace unit_test_detail
} // namespace

namespace hpp_proto::grpc {
template <>
class ServerRPC<unit_test_detail::fake_client_stream_method, RpcType::CLIENT_STREAMING>
    : public ::grpc::ServerReadReactor<::grpc::ByteBuffer> {
  unit_test_detail::fake_context context_{};
  ::grpc::Status finished_status_;
  bool finished_ = false;
  ::grpc::ByteBuffer request_;

protected:
  [[nodiscard]] const ::grpc::ByteBuffer *request_buf() const { return &request_; }

public:
  ServerRPC(::grpc::CallbackServerContext *, ::grpc::ByteBuffer *) {}

  void start_read() {}
  [[nodiscard]] unit_test_detail::fake_context &context() { return context_; }

  void set_cancelled(bool cancelled) { context_.cancelled = cancelled; }
  [[nodiscard]] bool finished() const { return finished_; }
  [[nodiscard]] const ::grpc::Status &finished_status() const { return finished_status_; }

  void Finish(::grpc::Status status) {
    finished_ = true;
    finished_status_ = std::move(status);
  }
};

template <>
class ServerRPC<unit_test_detail::fake_server_stream_method, RpcType::SERVER_STREAMING>
    : public ::grpc::ServerWriteReactor<::grpc::ByteBuffer> {
  unit_test_detail::fake_context context_{};
  ::grpc::Status finished_status_;
  bool finished_ = false;

public:
  ServerRPC(::grpc::CallbackServerContext *, ::grpc::ByteBuffer *) {}

  [[nodiscard]] unit_test_detail::fake_context &context() { return context_; }

  void set_cancelled(bool cancelled) { context_.cancelled = cancelled; }
  [[nodiscard]] bool finished() const { return finished_; }
  [[nodiscard]] const ::grpc::Status &finished_status() const { return finished_status_; }

  void Finish(::grpc::Status status) {
    finished_ = true;
    finished_status_ = std::move(status);
  }
};
} // namespace hpp_proto::grpc

namespace {
struct CancelReadHandler {
  using rpc_t = ::hpp_proto::grpc::ServerRPC<unit_test_detail::fake_client_stream_method>;
  unit_test_detail::cancel_read_state *state_;

  explicit CancelReadHandler(unit_test_detail::cancel_read_state &state, rpc_t &rpc) : state_(&state) {
    rpc.start_read();
  }

  void on_read_ok(rpc_t &, ::hpp_proto::grpc::RequestToken<unit_test_detail::fake_client_stream_method>) const {}

  bool on_read_cancel(rpc_t &) const {
    state_->on_read_cancel_calls.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
};

struct WriteErrorHandler {
  using rpc_t = ::hpp_proto::grpc::ServerRPC<unit_test_detail::fake_server_stream_method>;
  unit_test_detail::write_error_state *state_;

  WriteErrorHandler(unit_test_detail::write_error_state &state, rpc_t &,
                    ::hpp_proto::grpc::RequestToken<unit_test_detail::fake_server_stream_method>)
      : state_(&state) {}

  void on_write_ok(rpc_t &) {}

  bool on_write_error(rpc_t &) const {
    state_->on_write_error_calls.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
};

class CancelReadReactor
    : public ::hpp_proto::grpc::BasicServerReactor<unit_test_detail::fake_client_stream_method, CancelReadHandler> {
public:
  using base_t = ::hpp_proto::grpc::BasicServerReactor<unit_test_detail::fake_client_stream_method, CancelReadHandler>;
  using base_t::base_t;
  using base_t::finished;
  using base_t::finished_status;
  using base_t::set_cancelled;

  void trigger_on_read_done(bool ok) { this->on_read_done(ok); }
};

class WriteErrorReactor
    : public ::hpp_proto::grpc::BasicServerReactor<unit_test_detail::fake_server_stream_method, WriteErrorHandler> {
public:
  using base_t = ::hpp_proto::grpc::BasicServerReactor<unit_test_detail::fake_server_stream_method, WriteErrorHandler>;
  using base_t::base_t;
  using base_t::finished;
  using base_t::finished_status;
  using base_t::set_cancelled;

  void trigger_on_write_done(bool ok) { this->on_write_done(ok); }
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

  "reactor_on_read_done_cancel_calls_handler_and_fallback"_test = [] {
    ::grpc::CallbackServerContext context;
    ::grpc::ByteBuffer response;
    unit_test_detail::cancel_read_state state;
    CancelReadReactor reactor(&context, &response, state);

    reactor.set_cancelled(true);
    reactor.trigger_on_read_done(false);

    expect(state.on_read_cancel_calls.load(std::memory_order_relaxed) == 1_i);
    expect(reactor.finished());
    expect(reactor.finished_status().error_code() == ::grpc::StatusCode::CANCELLED);
  };

  "reactor_on_write_done_error_calls_handler_and_fallback"_test = [] {
    ::grpc::CallbackServerContext context;
    ::grpc::ByteBuffer request;
    ::grpc::ByteBuffer response;
    unit_test_detail::write_error_state state;
    WriteErrorReactor reactor(&context, &request, &response, state);

    reactor.set_cancelled(false);
    reactor.trigger_on_write_done(false);

    expect(state.on_write_error_calls.load(std::memory_order_relaxed) == 1_i);
    expect(reactor.finished());
    expect(reactor.finished_status().error_code() == ::grpc::StatusCode::UNKNOWN);
  };
};
} // namespace
