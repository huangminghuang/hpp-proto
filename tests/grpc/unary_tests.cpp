#include <boost/ut.hpp>

#include <condition_variable>
#include <memory_resource>
#include <mutex>
#include <string>

#include "test_harness.hpp"

namespace {
using namespace boost::ut;
using namespace hpp::proto;
using namespace hpp::proto::grpc;
using hpp::proto::grpc::test_utils::Harness;
using hpp::proto::grpc::test_utils::UnaryEcho;

void run_unary_blocking_case() {
  Harness harness;
  auto &stub = harness.stub();
  ::grpc::ClientContext context;
  EchoRequest request;
  request.message = "ping";
  request.sequence = 41;

  EchoResponse<> response;
  auto status = stub.call<UnaryEcho>(context, request, response);

  expect(status.ok()) << status.error_message();
  expect(eq(static_cast<int>(response.sequence), 42));
  expect(eq(response.message, std::string{"ping-unary"}));
}

class UnaryAsyncReactor : public ::hpp::proto::grpc::ClientCallbackReactor<UnaryEcho> {
  std::mutex mu_;
  std::condition_variable cv_;
  bool done_ = false;
  ::grpc::Status status_;
  EchoResponse<> response_;

public:
  void OnDone(const ::grpc::Status &status) override {
    std::unique_lock lock(mu_);
    status_ = status;
    if (status_.ok()) {
      auto read_status = this->get_response(response_);
      if (!read_status.ok()) {
        status_ = read_status;
      }
    }
    done_ = true;
    cv_.notify_all();
  }

  void wait() {
    std::unique_lock lock(mu_);
    cv_.wait(lock, [&] { return done_; });
  }

  [[nodiscard]] const ::grpc::Status &status() const { return status_; }
  [[nodiscard]] const EchoResponse<> &response() const { return response_; }
};

void run_unary_async_reactor_case() {
  Harness harness;
  auto &stub = harness.stub();
  ::grpc::ClientContext context;
  EchoRequest request;
  request.message = "async-reactor";
  request.sequence = 10;

  auto *reactor = new UnaryAsyncReactor();
  stub.async_call<UnaryEcho>(context, request, reactor);
  reactor->start_call();
  reactor->wait();

  expect(reactor->status().ok()) << reactor->status().error_message();
  expect(eq(static_cast<int>(reactor->response().sequence), 11));
  expect(eq(reactor->response().message, std::string{"async-reactor-unary"}));
  delete reactor;
}

void run_unary_async_callback_case() {
  Harness harness;
  auto &stub = harness.stub();
  ::grpc::ClientContext context;
  EchoRequest request;
  request.message = "async-callback";
  request.sequence = 5;

  EchoResponse response;
  std::mutex mu;
  std::condition_variable cv;
  bool done = false;
  ::grpc::Status status;

  stub.async_call<UnaryEcho>(context, request, response, [&](::grpc::Status s) {
    std::unique_lock lock(mu);
    status = s;
    done = true;
    cv.notify_all();
  });

  std::unique_lock lock(mu);
  cv.wait(lock, [&] { return done; });

  expect(status.ok()) << status.error_message();
  expect(eq(static_cast<int>(response.sequence), 6));
  expect(eq(response.message, std::string{"async-callback-unary"}));
}

const suite unary_suite = [] {
  "unary_echo_blocking"_test = [] { run_unary_blocking_case(); };
  "unary_echo_async_reactor"_test = [] { run_unary_async_reactor_case(); };
  "unary_echo_async_callback"_test = [] { run_unary_async_callback_case(); };
};
} // namespace
