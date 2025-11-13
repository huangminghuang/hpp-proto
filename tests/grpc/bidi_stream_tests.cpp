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
using hpp::proto::grpc::test_utils::BidiStreamChat;
using hpp::proto::grpc::test_utils::Harness;
using hpp::proto::grpc::test_utils::kTerminalSequence;

class BidiReactor : public ::hpp::proto::grpc::ClientCallbackReactor<BidiStreamChat> {
  std::mutex mu_;
  std::condition_variable cv_;
  bool done_ = false;
  bool writes_complete_ = false;
  size_t next_payload_ = 0;
  std::vector<std::string> payloads_;
  ::grpc::Status status_;
  std::vector<std::string> responses_;
  ::grpc::ClientContext *context_;

public:
  using request_t = EchoRequest<>;

  void set_payloads(std::vector<std::string> payloads) { payloads_ = std::move(payloads); }

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

  [[nodiscard]] const ::grpc::Status &status() const { return status_; }
  [[nodiscard]] const std::vector<std::string> &responses() const { return responses_; }

  void OnReadDone(bool ok) override {
    if (!ok) {
      return;
    }
    std::pmr::monotonic_buffer_resource mr;
    EchoResponse<> response;
    auto read_status = this->get_response(response, hpp::proto::alloc_from{mr});
    if (!read_status.ok()) {
      status_ = read_status;
      done_ = true;
      cv_.notify_all();
      context_->TryCancel();
      return;
    }
    responses_.emplace_back(response.message.begin(), response.message.end());
    this->start_read();
  }

  void OnWriteDone(bool ok) override {
    if (!ok) {
      OnDone(::grpc::Status(::grpc::StatusCode::CANCELLED, "write cancelled"));
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
    if (writes_complete_) {
      return;
    }
    if (next_payload_ >= payloads_.size()) {
      request_t sentinel;
      sentinel.message = "bye";
      sentinel.sequence = kTerminalSequence;
      auto status = this->write_last(sentinel, ::grpc::WriteOptions{});
      if (!status.ok()) {
        OnDone(status);
      }
      writes_complete_ = true;
      return;
    }

    request_t request;
    request.message = payloads_[next_payload_];
    request.sequence = static_cast<int32_t>(next_payload_);
    ++next_payload_;
    auto status = this->write(request);
    if (!status.ok()) {
      OnDone(status);
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

const suite bidi_suite = [] {
  "bidi_chat_round_trip"_test = [] { run_bidi_case(); };
};
} // namespace
