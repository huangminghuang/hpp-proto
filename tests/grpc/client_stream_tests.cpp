#include <boost/ut.hpp>

#include <chrono>
#include <condition_variable>
#include <limits>
#include <memory_resource>
#include <mutex>
#include <string>
#include <vector>

#include "test_harness.hpp"

namespace {
using namespace boost::ut;
using namespace hpp_proto;
using namespace hpp_proto::grpc;
using namespace hpp_proto::grpc::test_utils;

class ClientStreamReactor : public ::hpp_proto::grpc::ClientCallbackReactor<ClientStreamAggregate> {
  std::mutex mu_;
  std::condition_variable cv_;
  bool done_ = false;
  size_t next_message_ = 0;
  std::vector<std::string> payloads_;
  bool use_sentinel_ = true;
  bool sentinel_sent_ = false;
  bool writes_complete_ = false;
  size_t write_done_count_ = 0;
  size_t auto_write_limit_ = std::numeric_limits<size_t>::max();
  ::grpc::Status status_;
  hpp_proto_test::StreamSummary<> summary_;
  ::grpc::ClientContext *context_ = nullptr;

public:
  using request_t = hpp_proto_test::EchoRequest<>;

  void set_payloads(std::vector<std::string> payloads) { payloads_ = std::move(payloads); }
  void set_use_sentinel(bool use_sentinel) { use_sentinel_ = use_sentinel; }
  void set_auto_write_limit(size_t n) { auto_write_limit_ = n; }

  void begin(Harness::stub_type &stub, ::grpc::ClientContext &context) {
    context_ = &context;
    stub.async_call<ClientStreamAggregate>(context, this);
    this->start_call();
    send_next();
  }

  void wait() {
    std::unique_lock lock(mu_);
    cv_.wait(lock, [&] { return done_; });
  }

  [[nodiscard]] ::grpc::Status status() {
    const std::scoped_lock lock(mu_);
    return status_;
  }
  [[nodiscard]] hpp_proto_test::StreamSummary<> summary() {
    const std::scoped_lock lock(mu_);
    return summary_;
  }
  [[nodiscard]] bool wait_for_writes(size_t n, std::chrono::milliseconds timeout) {
    std::unique_lock lock(mu_);
    return cv_.wait_for(lock, timeout, [&] { return write_done_count_ >= n || done_; });
  }

  void OnWriteDone(bool ok) override {
    if (!ok) {
      // gRPC will deliver OnDone() for terminal write failure.
      return;
    }
    {
      const std::scoped_lock lock(mu_);
      ++write_done_count_;
      cv_.notify_all();
    }
    send_next();
  }

  void OnDone(const ::grpc::Status &status) override {
    const std::unique_lock lock(mu_);
    status_ = status;
    if (status_.ok()) {
      auto read_status = this->get_response(summary_);
      if (!read_status.ok()) {
        status_ = read_status;
      }
    }
    done_ = true;
    cv_.notify_all();
  }

private:
  void send_next() {
    const std::scoped_lock<std::mutex> lock(mu_);
    if (writes_complete_) {
      return;
    }

    if (next_message_ >= payloads_.size()) {
      if (writes_complete_) {
        return;
      }
      if (use_sentinel_) {
        if (sentinel_sent_) {
          writes_complete_ = true;
          this->write_done();
          return;
        }
        sentinel_sent_ = true;
        request_t sentinel;
        sentinel.message = "final";
        sentinel.sequence = kTerminalSequence;
        auto status = this->write(sentinel, hpp_proto::contiguous_mode);
        if (!status.ok()) {
          writes_complete_ = true;
          context_->TryCancel();
        }
      } else {
        writes_complete_ = true;
        this->write_done();
      }
      return;
    }

    if (write_done_count_ >= auto_write_limit_) {
      return;
    }

    request_t request;
    request.message = payloads_[next_message_];
    request.sequence = static_cast<int32_t>(next_message_);
    ++next_message_;
    auto status = this->write(request, hpp_proto::contiguous_mode);
    if (!status.ok()) {
      writes_complete_ = true;
      context_->TryCancel();
    }
  }
};

void run_client_stream_case() {
  Harness harness;
  auto &stub = harness.stub();

  ::grpc::ClientContext context;
  ClientStreamReactor reactor;
  reactor.set_payloads({"chunk_0", "chunk_1", "chunk_2"});
  reactor.begin(stub, context);
  reactor.wait();

  expect(reactor.status().ok()) << reactor.status().error_message();
  expect(eq(static_cast<int>(reactor.summary().total_messages), 3));
  expect(eq(reactor.summary().last_message, std::string{"chunk_2"}));
}

void run_client_stream_eof_without_sentinel_case() {
  Harness harness;
  auto &stub = harness.stub();

  ::grpc::ClientContext context;
  ClientStreamReactor reactor;
  reactor.set_use_sentinel(false);
  reactor.set_payloads({"chunk_0", "chunk_1", "chunk_2"});
  reactor.begin(stub, context);
  reactor.wait();

  expect(reactor.status().ok()) << reactor.status().error_message();
  expect(eq(static_cast<int>(reactor.summary().total_messages), 3));
  expect(eq(reactor.summary().last_message, std::string{"chunk_2"}));
}

void run_client_stream_cancel_case() {
  Harness harness;
  auto &stub = harness.stub();

  ::grpc::ClientContext context;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
  context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
  ClientStreamReactor reactor;
  reactor.set_use_sentinel(false);
  reactor.set_auto_write_limit(1);
  reactor.set_payloads({"chunk_0",  "chunk_1",  "chunk_2",  "chunk_3",  "chunk_4",  "chunk_5",  "chunk_6",
                        "chunk_7",  "chunk_8",  "chunk_9",  "chunk_10", "chunk_11", "chunk_12", "chunk_13",
                        "chunk_14", "chunk_15", "chunk_16", "chunk_17", "chunk_18", "chunk_19"});
  reactor.begin(stub, context);
  expect(reactor.wait_for_writes(1, std::chrono::seconds(2)));
  context.TryCancel();
  reactor.wait();

  expect(reactor.status().error_code() == ::grpc::StatusCode::CANCELLED);
}

const suite client_stream_suite = [] {
  "client_stream_aggregate"_test = [] { run_client_stream_case(); };
  "client_stream_eof_without_sentinel"_test = [] { run_client_stream_eof_without_sentinel_case(); };
  "client_stream_explicit_cancel"_test = [] { run_client_stream_cancel_case(); };
};
} // namespace
