#include <boost/ut.hpp>

#include <condition_variable>
#include <memory_resource>
#include <mutex>
#include <string>
#include <vector>

#include "test_harness.hpp"

namespace {
using namespace boost::ut;
using namespace hpp::proto;
using namespace hpp::proto::grpc;
using hpp::proto::grpc::test_utils::ClientStreamAggregate;
using hpp::proto::grpc::test_utils::Harness;
using hpp::proto::grpc::test_utils::kTerminalSequence;

class ClientStreamReactor : public ::hpp::proto::grpc::ClientCallbackReactor<ClientStreamAggregate> {
  std::mutex mu_;
  std::mutex write_mu_;
  std::condition_variable cv_;
  bool done_ = false;
  size_t next_message_ = 0;
  std::vector<std::string> payloads_;
  bool sentinel_sent_ = false;
  bool writes_complete_ = false;
  ::grpc::Status status_;
  StreamSummary<> summary_;

public:
  using request_t = EchoRequest<>;

  void set_payloads(std::vector<std::string> payloads) { payloads_ = std::move(payloads); }

  void begin(Harness::stub_type &stub, ::grpc::ClientContext &context) {
    stub.async_call<ClientStreamAggregate>(context, this);
    this->start_call();
    send_next();
  }

  void wait() {
    std::unique_lock lock(mu_);
    cv_.wait(lock, [&] { return done_; });
  }

  [[nodiscard]] const ::grpc::Status &status() const { return status_; }
  [[nodiscard]] const StreamSummary<> &summary() const { return summary_; }

  void OnWriteDone(bool ok) override {
    if (!ok) {
      OnDone(::grpc::Status(::grpc::StatusCode::CANCELLED, "write cancelled"));
      return;
    }
    send_next();
    bool should_close = false;
    {
      std::scoped_lock<std::mutex> lock(write_mu_);
      if (sentinel_sent_ && !writes_complete_ && next_message_ >= payloads_.size()) {
        writes_complete_ = true;
        should_close = true;
      }
    }
    if (should_close) {
      this->write_done();
    }
  }

  void OnDone(const ::grpc::Status &status) override {
    std::unique_lock lock(mu_);
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
    std::scoped_lock<std::mutex> lock(write_mu_);
    if (writes_complete_) {
      return;
    }

    if (next_message_ >= payloads_.size()) {
      if (sentinel_sent_) {
        return;
      }
      sentinel_sent_ = true;
      request_t sentinel;
      sentinel.message = "final";
      sentinel.sequence = kTerminalSequence;
      auto status = this->write(sentinel);
      if (!status.ok()) {
        OnDone(status);
      }
      return;
    }

    request_t request;
    request.message = payloads_[next_message_];
    request.sequence = static_cast<int32_t>(next_message_);
    ++next_message_;
    auto status = this->write(request);
    if (!status.ok()) {
      OnDone(status);
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

const suite client_stream_suite = [] { "client_stream_aggregate"_test = [] { run_client_stream_case(); }; };
} // namespace
