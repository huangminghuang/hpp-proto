#include "benchmark_messages_proto2.pb.h"
#include "non_owning/benchmark_messages_proto2.pb.hpp"
#include "owning/benchmark_messages_proto2.pb.hpp"
#include <benchmark/benchmark.h>
#include <fstream>
#include <memory_resource>
#include <random>

#include "benchmark_messages_proto3.pb.h"
#include "non_owning/benchmark_messages_proto3.pb.hpp"
#include "owning/benchmark_messages_proto3.pb.hpp"

#include "non_owning/packed_repeated_message.pb.hpp"
#include "owning/packed_repeated_message.pb.hpp"
#include "packed_repeated_message.pb.h"

inline void set_message_google(auto &message) {
  message.set_field1("");
  message.set_field2(8);
  message.set_field3(2066379);
  message.set_field4("3K+6)#");
  message.set_field9(R"(10)2uiSuoXL1^)v}icF@>P(j<t#~tz\lg??S&(<hr7EVs'l{'5`Gohc_(=t eS s{_I?iCwaG]L'*Pu5(&w_:4{~Z)");
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

inline void set_message_hpp(auto &message) {
  message.field1 = "";
  message.field2 = 8;
  message.field3 = 2066379;
  message.field4 = "3K+6)#";
  message.field9 = R"(10)2uiSuoXL1^)v}icF@>P(j<t#~tz\lg??S&(<hr7EVs'l{'5`Gohc_(=t eS s{_I?iCwaG]L'*Pu5(&w_:4{~Z)";
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

std::span<char> get_GoogleMessage1_data() {
  static std::span<char> data;
  if (data.empty()) {
    benchmarks::proto2::GoogleMessage1 msg;
    set_message_google(msg);
    static std::string storage = msg.SerializeAsString();
    data = std::span{storage};
  }
  return data;
}

std::span<char> get_data(benchmarks::proto2::GoogleMessage1 * /*unused*/) { return get_GoogleMessage1_data(); }
std::span<char> get_data(benchmarks::proto3::GoogleMessage1 * /*unused*/) { return get_GoogleMessage1_data(); }
std::span<char> get_data(owning::benchmarks::proto2::GoogleMessage1 * /*unused*/) { return get_GoogleMessage1_data(); }
std::span<char> get_data(owning::benchmarks::proto3::GoogleMessage1 * /*unused*/) { return get_GoogleMessage1_data(); }
std::span<char> get_data(non_owning::benchmarks::proto2::GoogleMessage1 * /*unused*/) {
  return get_GoogleMessage1_data();
}
std::span<char> get_data(non_owning::benchmarks::proto3::GoogleMessage1 * /*unused*/) {
  return get_GoogleMessage1_data();
}

std::span<char> get_packed_repeated_data() {
  const int len = 1000;
  const std::size_t max_value = 0x0100000000000000ULL;
  static std::vector<char> data;

  if (data.empty()) {
    std::random_device rd;
    std::mt19937 engine(rd());

    std::uniform_int_distribution<unsigned long long> dis(0, max_value);

    repeated_packed::TestMessage msg;
    auto *x = msg.mutable_x();
    x->Resize(len, 0);
    for (int i = 0; i < len; ++i) {
      x->Set(i, dis(engine));
    }

    data.resize(msg.ByteSizeLong());
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    msg.SerializeWithCachedSizesToArray(reinterpret_cast<uint8_t *>(data.data()));
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  }
  return data;
}

std::span<char> get_data(repeated_packed::TestMessage * /*unused*/) { return get_packed_repeated_data(); }
std::span<char> get_data(owning::repeated_packed::TestMessage * /*unused*/) { return get_packed_repeated_data(); }
std::span<char> get_data(non_owning::repeated_packed::TestMessage * /*unused*/) { return get_packed_repeated_data(); }

template <typename Message>
void google_deserialize(benchmark::State &state) {
  auto data = get_data((Message *)nullptr);
  size_t total = 0;
  for (auto _ : state) {
    Message message;
    auto r = message.ParseFromArray(data.data(), static_cast<int>(data.size()));
    total += data.size();
    benchmark::DoNotOptimize(r);
  }
  state.SetBytesProcessed(static_cast<int64_t>(total));
}
BENCHMARK(google_deserialize<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_deserialize<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void google_deserialize_arena(benchmark::State &state) {
  auto data = get_data((Message *)nullptr);
  google::protobuf::Arena arena;
  size_t total = 0;
  for (auto _ : state) {
    arena.Reset();
    auto *message = google::protobuf::Arena::Create<Message>(&arena);
    auto r = message->ParseFromArray(data.data(), static_cast<int>(data.size()));
    total += data.size();
    benchmark::DoNotOptimize(r);
  }
  state.SetBytesProcessed(static_cast<int64_t>(total));
}

BENCHMARK(google_deserialize_arena<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_deserialize_arena<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_proto_deserialize_owning(benchmark::State &state) {
  auto data = get_data((Message *)nullptr);
  size_t total = 0;
  for (auto _ : state) {
    Message message;
    auto r = hpp::proto::read_proto(message, data);
    total += data.size();
    benchmark::DoNotOptimize(r);
  }
  state.SetBytesProcessed(static_cast<int64_t>(total));
}
BENCHMARK(hpp_proto_deserialize_owning<owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_proto_deserialize_owning<owning::benchmarks::proto3::GoogleMessage1>);
BENCHMARK(hpp_proto_deserialize_owning<owning::benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_proto_deserialize_non_owning(benchmark::State &state) {
  auto data = get_data((Message *)nullptr);

  std::vector<char> buf(16 * 1024ULL);
  size_t total = 0;
  for (auto _ : state) {
    std::pmr::monotonic_buffer_resource memory_resource(buf.data(), buf.size());
    Message message;
    auto r = hpp::proto::read_proto(message, data,
                                    hpp::proto::pb_context{memory_resource, hpp::proto::always_allocate_memory{}});
    total += data.size();
    benchmark::DoNotOptimize(r);
  }
  state.SetBytesProcessed(static_cast<int64_t>(total));
}
BENCHMARK(hpp_proto_deserialize_non_owning<non_owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_proto_deserialize_non_owning<non_owning::benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void google_set_message(benchmark::State &state) {
  for (auto _ : state) {
    Message message;
    set_message_google(message);
    benchmark::DoNotOptimize(message);
  }
}
BENCHMARK(google_set_message<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_set_message<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void google_set_message_arena(benchmark::State &state) {
  google::protobuf::Arena arena;
  for (auto _ : state) {
    arena.Reset();
    auto *message = google::protobuf::Arena::Create<Message>(&arena);
    set_message_google(*message);
    benchmark::DoNotOptimize(message);
  }
}
BENCHMARK(google_set_message_arena<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_set_message_arena<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_proto_set_message_owning(benchmark::State &state) {
  for (auto _ : state) {
    Message message;
    set_message_hpp(message);
    benchmark::DoNotOptimize(message);
  }
}
BENCHMARK(hpp_proto_set_message_owning<owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_proto_set_message_owning<owning::benchmarks::proto3::GoogleMessage1>);


template <typename Message>
void google_set_message_and_serialize(benchmark::State &state) {
  size_t total = 0;
  for (auto _ : state) {
    Message message;
    set_message_google(message);
    std::string buffer;
    auto r = message.SerializeToString(&buffer);
    total += buffer.size();
    benchmark::DoNotOptimize(r);
  }
  state.SetBytesProcessed(static_cast<int64_t>(total));
}
BENCHMARK(google_set_message_and_serialize<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_set_message_and_serialize<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void google_set_message_and_serialize_arena(benchmark::State &state) {
  google::protobuf::Arena arena;
  size_t total = 0;
  for (auto _ : state) {
    arena.Reset();
    auto *message = google::protobuf::Arena::Create<Message>(&arena);
    set_message_google(*message);
    std::string buffer;
    auto r = message->SerializeToString(&buffer);
    total += buffer.size();
    benchmark::DoNotOptimize(r);
  }
  state.SetBytesProcessed(static_cast<int64_t>(total));
}

BENCHMARK(google_set_message_and_serialize_arena<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_set_message_and_serialize_arena<benchmarks::proto3::GoogleMessage1>);


template <typename Message>
void hpp_proto_set_message_and_serialize_owning(benchmark::State &state) {
  size_t total = 0;
  for (auto _ : state) {
    Message message;
    set_message_hpp(message);
    std::vector<char> buffer;
    auto r = hpp::proto::write_proto(message, buffer);
    total += buffer.size();
    benchmark::DoNotOptimize(r);
  }
  state.SetBytesProcessed(static_cast<int64_t>(total));
}
BENCHMARK(hpp_proto_set_message_and_serialize_owning<owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_proto_set_message_and_serialize_owning<owning::benchmarks::proto3::GoogleMessage1>);


template <typename Message>
void hpp_proto_set_message_and_serialize_nonowning(benchmark::State &state) {
  size_t total = 0;
  for (auto _ : state) {
    Message message;
    set_message_hpp(message);
    std::vector<char> buffer;
    auto r = hpp::proto::write_proto(message, buffer);
    total += buffer.size();
    benchmark::DoNotOptimize(r);
  }
  state.SetBytesProcessed(static_cast<int64_t>(total));
}
BENCHMARK(hpp_proto_set_message_and_serialize_nonowning<non_owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_proto_set_message_and_serialize_nonowning<non_owning::benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_proto_set_message_nonowning(benchmark::State &state) {
  for (auto _ : state) {
    Message message;
    set_message_hpp(message);
    benchmark::DoNotOptimize(message);
  }
}

BENCHMARK(hpp_proto_set_message_nonowning<non_owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_proto_set_message_nonowning<non_owning::benchmarks::proto3::GoogleMessage1>);

BENCHMARK(google_deserialize<repeated_packed::TestMessage>);
BENCHMARK(google_deserialize_arena<repeated_packed::TestMessage>);
BENCHMARK(hpp_proto_deserialize_owning<owning::repeated_packed::TestMessage>);
BENCHMARK(hpp_proto_deserialize_non_owning<non_owning::repeated_packed::TestMessage>);

BENCHMARK_MAIN();
