#include <fstream>

#include <benchmark/benchmark.h>

#include "benchmark_messages_proto2.pb.h"
#include "non_owning/benchmark_messages_proto2.pb.hpp"
#include "owning/benchmark_messages_proto2.pb.hpp"

#include "benchmark_messages_proto3.pb.h"
#include "non_owning/benchmark_messages_proto3.pb.hpp"
#include "owning/benchmark_messages_proto3.pb.hpp"

inline void set_message_google(auto& message) {
    message.set_field1("");
    message.set_field2(8);
    message.set_field3(2066379);
    message.set_field4("3K+6)#");
    message.set_field9("10)2uiSuoXL1^)v}icF@>P(j<t#~tz\\lg??S&(<hr7EVs\'l{\'5`Gohc_(=t eS s{_I?iCwaG]L\'*Pu5(&w_:4{~Z");
    message.set_field12(true);
    message.set_field14(true);
    auto submsg = message.mutable_field15();
    submsg->set_field1(25);
    submsg->set_field2(36);
    submsg->set_field15("\"?6PY4]L2c<}~2;\\TVF_w^[@YfbIc*v/N+Z-oYuaWZr4C;5ib|*s@RCBbuvrQ3g(k,N");
    submsg->set_field21(2813090458170031956);
    submsg->set_field22(38);
    submsg->set_field23(true);
    message.set_field18("{=Qwfe~#n{");
    message.set_field67(1591432);
    message.set_field100(31);
}

inline void set_message_hpp(auto& message) {
    message.field1 = "";
    message.field2 = 8;
    message.field3 = 2066379;
    message.field4 = "3K+6)#";
    message.field9 = "10)2uiSuoXL1^)v}icF@>P(j<t#~tz\\lg??S&(<hr7EVs\'l{\'5`Gohc_(=t eS s{_I?iCwaG]L\'*Pu5(&w_:4{~Z";
    message.field12 = true;
    message.field14 = true;
    auto &submsg = message.field15.emplace();
    submsg.field1 = 25;
    submsg.field2 = 36;
    submsg.field15 = "\"?6PY4]L2c<}~2;\\TVF_w^[@YfbIc*v/N+Z-oYuaWZr4C;5ib|*s@RCBbuvrQ3g(k,N";
    submsg.field21 = 2813090458170031956;
    submsg.field22 = 38;
    submsg.field23 = true;
    message.field18 = "{=Qwfe~#n{";
    message.field67 = 1591432;
    message.field100 = 31;

}

struct monotonic_buffer_resource {
  std::size_t size;
  void *mem = 0;
  void *cur = 0;
  monotonic_buffer_resource(std::size_t sz) : size(sz), mem(malloc(sz)), cur(mem) {}
  monotonic_buffer_resource(const monotonic_buffer_resource &) = delete;

  ~monotonic_buffer_resource() { free(mem); }
  void *allocate(std::size_t n, std::size_t alignment) noexcept {
    if (std::align(alignment, n, cur, size)) {
      size -= n;
      auto result = cur;
      cur = (char *)cur + n;
      return result;
    }
    abort();
  }

  void reset() { cur = mem; }
};

std::span<char> get_data() {
  static std::span<char> data;
  if (data.empty()) {
    benchmarks::proto2::GoogleMessage1 msg;
    set_message_google(msg);
    static std::string storage = msg.SerializeAsString();
    data = std::span{storage};
  }
  return data;
}

template <typename Message>
void google_deserialize(benchmark::State &state) {
  auto data = get_data();
  for (auto _ : state) {  
    Message message;  
    auto r = message.ParseFromArray(data.data(), static_cast<int>(data.size()));
    benchmark::DoNotOptimize(r);
  }
}
BENCHMARK(google_deserialize<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_deserialize<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void google_deserialize_arena(benchmark::State &state) {
  auto data = get_data();
  for (auto _ : state) {
    google::protobuf::Arena arena;
    Message *message = google::protobuf::Arena::CreateMessage<Message>(&arena);
    auto r = message->ParseFromArray(data.data(), static_cast<int>(data.size()));
    benchmark::DoNotOptimize(r);
  }
}

BENCHMARK(google_deserialize_arena<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_deserialize_arena<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_deserialize_owning(benchmark::State &state) {
  auto data = get_data();
  for (auto _ : state) {
    Message message;
    auto r = hpp::proto::read_proto(message, data);
    benchmark::DoNotOptimize(r);
  }
}
BENCHMARK(hpp_deserialize_owning<owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_deserialize_owning<owning::benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_deserialize_non_owning(benchmark::State &state) {
  auto data = get_data();
  monotonic_buffer_resource memory_resource(data.size());
  
  for (auto _ : state) {
    memory_resource.reset();
    Message message;
    auto r = hpp::proto::read_proto(message, data, hpp::proto::pb_context{memory_resource});
    benchmark::DoNotOptimize(r);
  }
}
BENCHMARK(hpp_deserialize_non_owning<non_owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_deserialize_non_owning<non_owning::benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void google_serialize(benchmark::State &state) {
  for (auto _ : state) {
    Message message;
    set_message_google(message);
    std::string buffer;
    auto r = message.SerializeToString(&buffer);
    benchmark::DoNotOptimize(r);
  }
}
BENCHMARK(google_serialize<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_serialize<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_serialize_owning(benchmark::State &state) {
  for (auto _ : state) {
    Message message;
    set_message_hpp(message);
    std::vector<char> buffer;
    auto r = hpp::proto::write_proto(message, buffer);
    benchmark::DoNotOptimize(r);
  }
}
BENCHMARK(hpp_serialize_owning<owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_serialize_owning<owning::benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_serialize_nonowning(benchmark::State &state) {
  for (auto _ : state) {
    Message message;
    set_message_hpp(message);
    std::vector<char> buffer;
    auto r = hpp::proto::write_proto(message, buffer);
    benchmark::DoNotOptimize(r);
  }
}
BENCHMARK(hpp_serialize_nonowning<non_owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_serialize_nonowning<non_owning::benchmarks::proto3::GoogleMessage1>);

BENCHMARK_MAIN();
