#pragma once

#include <grpcpp/grpcpp.h>

#include <hpp_proto/grpc/client.hpp>
#include <hpp_proto/grpc/server.hpp>

#include <cstdlib>
#include <deque>
#include <memory>
#include <mutex>
#include <string>

#include "echo_stream.msg.hpp"
#include "echo_stream.pb.hpp"
#include "echo_stream.service.hpp"

namespace hpp_proto::grpc::test_utils {

constexpr int32_t kTerminalSequence = -1;

using EchoMethods = hpp_proto_test::EchoStreamService::_methods;
using UnaryEcho = hpp_proto_test::EchoStreamService::UnaryEcho;
using ClientStreamAggregate = hpp_proto_test::EchoStreamService::ClientStreamAggregate;
using ServerStreamFanout = hpp_proto_test::EchoStreamService::ServerStreamFanout;
using BidiStreamChat = hpp_proto_test::EchoStreamService::BidiStreamChat;

using EchoRequest = hpp_proto_test::EchoRequest<>;
using EchoResponse = hpp_proto_test::EchoResponse<>;
using StreamSummary = hpp_proto_test::StreamSummary<>;

class EchoService : public ::hpp_proto::grpc::CallbackService<EchoService, EchoMethods> {
public:
  struct UnaryHandler {
    using rpc_t = ::hpp_proto::grpc::ServerRPC<UnaryEcho>;
    UnaryHandler(EchoService &, rpc_t &rpc, ::hpp_proto::grpc::RequestToken<UnaryEcho> token) {
      EchoRequest request;
      auto status = token.get(request);
      if (!status.ok()) {
        rpc.finish(status);
        return;
      }
      EchoResponse response;
      response.message = std::string{request.message} + "-unary";
      response.sequence = request.sequence + 1;
      rpc.finish(response);
    }
  };
  auto handle(UnaryEcho) -> UnaryHandler;

  struct ClientStreamHandler {
    using rpc_t = ::hpp_proto::grpc::ServerRPC<ClientStreamAggregate>;
    StreamSummary summary_;

    explicit ClientStreamHandler(EchoService &, rpc_t &rpc) { rpc.start_read(); }

    void on_read_ok(rpc_t &rpc, ::hpp_proto::grpc::RequestToken<ClientStreamAggregate> token) {
      EchoRequest request;
      auto status = token.get(request);
      if (!status.ok()) {
        rpc.finish(status);
        return;
      }
      if (request.sequence == kTerminalSequence) {
        rpc.finish(summary_);
        return;
      }
      summary_.total_messages += 1;
      summary_.last_message = std::string{request.message};
      rpc.start_read();
    }

    bool on_read_eof(rpc_t &rpc) const {
      rpc.finish(summary_);
      return true;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool on_read_cancel(rpc_t &) const {
      // Let reactor fallback finish with CANCELLED.
      return false;
    }
  };
  auto handle(ClientStreamAggregate) -> ClientStreamHandler;

  struct ServerStreamHandler {
    using rpc_t = ::hpp_proto::grpc::ServerRPC<ServerStreamFanout>;
    int remaining_ = 0;
    std::string payload_;

    ServerStreamHandler(EchoService &, rpc_t &rpc, ::hpp_proto::grpc::RequestToken<ServerStreamFanout> token) {
      EchoRequest request;
      auto status = token.get(request);
      if (!status.ok() || request.sequence <= 0 || request.message.empty()) {
        rpc.finish(status.ok() ? ::grpc::Status{::grpc::StatusCode::INVALID_ARGUMENT, "bad request"} : status);
        return;
      }
      remaining_ = request.sequence;
      payload_ = std::string{request.message};
      write_next(rpc);
    }

    void on_write_ok(rpc_t &rpc) {
      if (--remaining_ == 0) {
        rpc.finish(::grpc::Status::OK);
      } else {
        write_next(rpc);
      }
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool on_write_error(rpc_t &) {
      // Let reactor fallback finish with CANCELLED/UNKNOWN.
      return false;
    }

  private:
    void write_next(rpc_t &rpc) const {
      EchoResponse response;
      response.message = payload_;
      response.sequence = remaining_;
      rpc.write(response);
    }
  };
  auto handle(ServerStreamFanout) -> ServerStreamHandler;

  struct BidiStreamHandler {
    using rpc_t = ::hpp_proto::grpc::ServerRPC<BidiStreamChat>;
    std::mutex mu_;
    std::deque<EchoResponse> pending_;
    EchoResponse current_;

    BidiStreamHandler(EchoService &, rpc_t &rpc) { rpc.start_read(); }

    void on_read_ok(rpc_t &rpc, ::hpp_proto::grpc::RequestToken<BidiStreamChat> token) {
      EchoRequest request;
      auto status = token.get(request);
      if (!status.ok()) {
        rpc.finish(status);
        return;
      }

      EchoResponse response;
      response.message = std::string{request.message} + "-bidi";
      response.sequence = request.sequence;
      {
        std::scoped_lock lock(mu_);
        pending_.emplace_back(std::move(response));
      }
      next_write(rpc);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void on_write_ok(rpc_t &rpc) { next_write(rpc); }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool on_write_error(rpc_t &) { return false; }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool on_read_eof(rpc_t &rpc) {
      rpc.finish(::grpc::Status::OK);
      return true;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool on_read_cancel(rpc_t &) { return false; }

  private:
    void next_write(rpc_t &rpc) {
      std::unique_lock lock(mu_);
      if (!pending_.empty()) {
        EchoResponse current = pending_.front();
        pending_.pop_front();
        lock.unlock();
        if (current.sequence != kTerminalSequence) {
          rpc.write(current);
        } else {
          rpc.finish(::grpc::Status::OK);
        }
      } else {
        rpc.start_read();
      }
    }
  };
  auto handle(BidiStreamChat) -> BidiStreamHandler;
};

class Harness {
public:
  using stub_type = ::hpp_proto::grpc::Stub<EchoMethods>;

  Harness();
  ~Harness();
  Harness(const Harness &) = delete;
  Harness &operator=(const Harness &) = delete;
  Harness(Harness &&) = delete;
  Harness &operator=(Harness &&) = delete;

  stub_type &stub() { return *stub_; }

private:
  EchoService service_;
  std::unique_ptr<::grpc::Server> server_;
  std::shared_ptr<::grpc::Channel> channel_;
  ::grpc::StubOptions options_;
  std::unique_ptr<stub_type> stub_;
};

inline Harness::Harness() {
  const char *external_endpoint = std::getenv("HPP_PROTO_GRPC_TEST_ENDPOINT");
  if (external_endpoint == nullptr) {
    ::grpc::ServerBuilder builder;
    int selected_port = 0;
    builder.AddListeningPort("127.0.0.1:0", ::grpc::InsecureServerCredentials(), &selected_port);
    builder.RegisterService(&service_);
    server_ = builder.BuildAndStart();
    const std::string target = "127.0.0.1:" + std::to_string(selected_port);
    channel_ = ::grpc::CreateChannel(target, ::grpc::InsecureChannelCredentials());
  } else {
    channel_ = ::grpc::CreateChannel(external_endpoint, ::grpc::InsecureChannelCredentials());
  }
  stub_ = std::make_unique<stub_type>(channel_, options_);
}

inline Harness::~Harness() {
  if (server_) {
    server_->Shutdown();
    server_->Wait();
  }
}

} // namespace hpp_proto::grpc::test_utils
