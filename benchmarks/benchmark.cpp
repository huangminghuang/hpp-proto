#include <fstream>

#include <benchmark/benchmark.h>

#include "benchmark_messages_proto2.pb.h"
#include "non_owning/benchmark_messages_proto2.pb.hpp"
#include "owning/benchmark_messages_proto2.pb.hpp"

#include "benchmark_messages_proto3.pb.h"
#include "non_owning/benchmark_messages_proto3.pb.hpp"
#include "owning/benchmark_messages_proto3.pb.hpp"

std::string data_dir = DATA_DIR;

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

  void reset() {
    cur = mem;
  }
};

std::vector<char> read_data_file(std::string filename) {
  std::filebuf buf;
  if (buf.open(filename, std::ios::binary | std::ios::in) == nullptr) {
    std::cerr << "Open file " << filename << " for read failed\n";
    throw std::system_error {std::make_error_code(std::errc::no_such_file_or_directory) };
  }

  return {std::istreambuf_iterator<char>{&buf}, std::istreambuf_iterator<char>{}};
}

std::span<char> get_data() {
  static std::span<char> data;
  if (data.empty()) {
    static std::vector<char> storage = read_data_file(data_dir + "/google_message1.dat");
    data = std::span{storage};
  }
  return data;
}


template <typename Message>
void google_deserialize(benchmark::State &state) {
  auto data = get_data();
  for (auto _ : state) {
    Message message;
    benchmark::DoNotOptimize([&] { message.ParseFromArray(data.data(), static_cast<int>(data.size())); });
  }
}
BENCHMARK(google_deserialize<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_deserialize<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_deserialize_owning(benchmark::State &state) {
  auto data = get_data();
  for (auto _ : state) {
    Message message;
    benchmark::DoNotOptimize([&] { (void)hpp::proto::read_proto(message, data); });
  }
}
BENCHMARK(hpp_deserialize_owning<owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_deserialize_owning<owning::benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_deserialize_non_owning(benchmark::State &state) {
  auto data = get_data();
  monotonic_buffer_resource memory_resource(data.size());

  for (auto _ : state) {
    Message message;
    memory_resource.reset();
    benchmark::DoNotOptimize([&] { (void)hpp::proto::read_proto(message, data, hpp::proto::pb_context{memory_resource}); });
  }
}
BENCHMARK(hpp_deserialize_non_owning<non_owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_deserialize_non_owning<non_owning::benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void google_serialize(benchmark::State &state) {
  auto data = get_data();
  Message message;
  message.ParseFromArray(data.data(), static_cast<int>(data.size()));
  for (auto _ : state) {
    std::string buffer;
    benchmark::DoNotOptimize([&] { message.SerializeToString(&buffer); });
  }
}
BENCHMARK(google_serialize<benchmarks::proto2::GoogleMessage1>);
BENCHMARK(google_serialize<benchmarks::proto3::GoogleMessage1>);

template <typename Message>
void hpp_serialize_owning(benchmark::State &state) {
  auto data = get_data();
  Message message;
  (void)hpp::proto::read_proto(message, data);
  for (auto _ : state) {
    std::vector<char> buffer;
    benchmark::DoNotOptimize([&] { (void)hpp::proto::write_proto(message, buffer); });
  }
}
BENCHMARK(hpp_serialize_owning<owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_serialize_owning<owning::benchmarks::proto3::GoogleMessage1>);

template <typename Message>

void hpp_serialize_nonowning(benchmark::State &state) {
  auto data = get_data();
  Message message;
  monotonic_buffer_resource memory_resource(data.size());
  (void)hpp::proto::read_proto(message, data, hpp::proto::pb_context{memory_resource});

  for (auto _ : state) {
    std::vector<char> buffer;
    benchmark::DoNotOptimize([&] { (void)hpp::proto::write_proto(message, buffer); });
  }
}
BENCHMARK(hpp_serialize_nonowning<non_owning::benchmarks::proto2::GoogleMessage1>);
BENCHMARK(hpp_serialize_nonowning<non_owning::benchmarks::proto3::GoogleMessage1>);

BENCHMARK_MAIN();
