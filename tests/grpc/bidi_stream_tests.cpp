#include <boost/ut.hpp>

#include <chrono>
#include <condition_variable>
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

class BidiReactor : public ::hpp_proto::grpc::ClientCallbackReactor<BidiStreamChat> {
  std::mutex mu_;
  std::mutex write_mu_;
  std::condition_variable cv_;
  bool done_ = false;
  bool writes_complete_ = false;
  size_t next_payload_ = 0;
  std::vector<std::string> payloads_;
  ::grpc::Status status_;
  std::vector<std::string> responses_;
  ::grpc::ClientContext *context_ = nullptr;
  bool use_sentinel_ = true;
  bool sentinel_sent_ = false;

public:
  using request_t = hpp_proto_test::EchoRequest<>;

  void set_payloads(std::vector<std::string> payloads) { payloads_ = std::move(payloads); }
  void set_use_sentinel(bool use_sentinel) { use_sentinel_ = use_sentinel; }

  void start(Harness::stub_type &stub, ::grpc::ClientContext &context) {
    context_ = &context;
    stub.async_call<BidiStreamChat>(context, this);
    this->start_read();
    this->start_call();
    send_next();
  }

  void wait() {
    std::unique_lock lock(mu_);
    cv_.wait(lock, [&] { return done_; });
  }
  template <class Rep, class Period>
  bool wait_for_responses(std::size_t count, const std::chrono::duration<Rep, Period> &timeout) {
    std::unique_lock lock(mu_);
    return cv_.wait_for(lock, timeout, [&] { return responses_.size() >= count || done_; });
  }

  [[nodiscard]] const ::grpc::Status &status() const { return status_; }
  [[nodiscard]] const std::vector<std::string> &responses() const { return responses_; }

  void OnReadDone(bool ok) override {
    if (!ok) {
      return;
    }
    std::pmr::monotonic_buffer_resource mr;
    hpp_proto_test::EchoResponse<> response;
    auto read_status = this->get_response(response, hpp_proto::alloc_from{mr});
    {
      std::unique_lock lock(mu_);
      if (!read_status.ok()) {
        status_ = read_status;
        lock.unlock();
        context_->TryCancel();
        return;
      }
      responses_.emplace_back(response.message.begin(), response.message.end());
      cv_.notify_all();
    }
    this->start_read();
  }

  void OnWriteDone(bool ok) override {
    if (!ok) {
      // gRPC will deliver OnDone() for terminal write failure.
      return;
    }
    send_next();
  }

  void OnDone(const ::grpc::Status &status) override {
    std::unique_lock lock(mu_);
    if (status_.ok() || !done_) {
      status_ = status;
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
    if (next_payload_ >= payloads_.size()) {
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
        sentinel.message = "bye";
        sentinel.sequence = kTerminalSequence;
        auto status = this->write(sentinel);
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

    request_t request;
    request.message = payloads_[next_payload_];
    request.sequence = static_cast<int32_t>(next_payload_);
    ++next_payload_;
    auto status = this->write(request);
    if (!status.ok()) {
      writes_complete_ = true;
      context_->TryCancel();
    }
  }
};

void run_bidi_case() {
  Harness harness;
  auto &stub = harness.stub();
  ::grpc::ClientContext context;
  BidiReactor reactor;
  reactor.set_payloads({"chat_0", "chat_1"});
  reactor.start(stub, context);
  reactor.wait();

  expect(reactor.status().ok()) << reactor.status().error_message();
  expect(eq(reactor.responses().size(), std::size_t{2}));
  using namespace std::string_literals;
  expect(eq(reactor.responses()[0], "chat_0-bidi"s));
  expect(eq(reactor.responses()[1], "chat_1-bidi"s));
}

void run_bidi_half_close_without_sentinel_case() {
  Harness harness;
  auto &stub = harness.stub();
  ::grpc::ClientContext context;
  BidiReactor reactor;
  reactor.set_use_sentinel(false);
  reactor.set_payloads({"chat_0", "chat_1"});
  reactor.start(stub, context);
  reactor.wait();

  expect(reactor.status().ok()) << reactor.status().error_message();
  expect(eq(reactor.responses().size(), std::size_t{2}));
  using namespace std::string_literals;
  expect(eq(reactor.responses()[0], "chat_0-bidi"s));
  expect(eq(reactor.responses()[1], "chat_1-bidi"s));
}

void run_bidi_explicit_cancel_case() {
  Harness harness;
  auto &stub = harness.stub();
  ::grpc::ClientContext context;
  context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
  BidiReactor reactor;
  reactor.set_use_sentinel(false);
  reactor.set_payloads(
      {"chat_0", "chat_1", "chat_2", "chat_3", "chat_4", "chat_5", "chat_6", "chat_7", "chat_8", "chat_9"});
  reactor.start(stub, context);
  expect(reactor.wait_for_responses(1, std::chrono::seconds(2)));
  context.TryCancel();
  reactor.wait();

  expect(reactor.status().error_code() == ::grpc::StatusCode::CANCELLED);
}

const suite bidi_suite = [] {
  "bidi_chat_round_trip"_test = [] { run_bidi_case(); };
  "bidi_half_close_without_sentinel"_test = [] { run_bidi_half_close_without_sentinel_case(); };
  "bidi_explicit_cancel"_test = [] { run_bidi_explicit_cancel_case(); };
};
} // namespace
