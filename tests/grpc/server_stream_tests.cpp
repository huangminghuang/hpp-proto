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
using hpp::proto::grpc::test_utils::Harness;
using hpp::proto::grpc::test_utils::ServerStreamFanout;

class ServerStreamReactor : public ::hpp::proto::grpc::ClientCallbackReactor<ServerStreamFanout> {
  std::mutex mu_;
  std::condition_variable cv_;
  bool done_ = false;
  ::grpc::Status status_;
  std::vector<std::string> messages_;
  bool forced_status_ = false;

public:
  using request_t = EchoRequest<>;

  void start(Harness::stub_type &stub, request_t &request, ::grpc::ClientContext &context) {
    stub.async_call<ServerStreamFanout>(context, request, &(*this));
    this->start_read();
    this->start_call();
  }

  void wait() {
    std::unique_lock lock(mu_);
    cv_.wait(lock, [&] { return done_; });
  }

  [[nodiscard]] const ::grpc::Status &status() const { return status_; }
  [[nodiscard]] const std::vector<std::string> &messages() const { return messages_; }

  void OnReadDone(bool ok) override {
    if (!ok) {
      return;
    }
    std::pmr::monotonic_buffer_resource mr;
    EchoResponse<> response;
    auto read_status = this->get_response(response, hpp::proto::alloc_from{mr});
    if (!read_status.ok()) {
      std::unique_lock lock(mu_);
      status_ = read_status;
      forced_status_ = true;
      done_ = true;
      cv_.notify_all();
      return;
    }
    messages_.emplace_back(response.message.begin(), response.message.end());
    this->start_read();
  }

  void OnDone(const ::grpc::Status &status) override {
    std::unique_lock lock(mu_);
    if (!forced_status_) {
      status_ = status;
    }
    done_ = true;
    cv_.notify_all();
  }
};

void run_server_stream_case() {
  Harness harness;
  auto &stub = harness.stub();
  ::grpc::ClientContext context;
  typename ServerStreamReactor::request_t request;
  request.message = "fanout";
  request.sequence = 3;

  ServerStreamReactor reactor;
  reactor.start(stub, request, context);
  reactor.wait();

  expect(reactor.status().ok()) << reactor.status().error_message();
  expect(eq(reactor.messages().size(), std::size_t{3}));
  using namespace std::string_literals;
  expect(eq(reactor.messages().front(), "fanout"s));
  expect(eq(reactor.messages().back(), "fanout"s));
}

const suite server_stream_suite = [] { "server_stream_fanout"_test = [] { run_server_stream_case(); }; };
} // namespace
