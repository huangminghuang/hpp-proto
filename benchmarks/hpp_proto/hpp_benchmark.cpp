
#include "benchmark_util.h"
#ifdef PROTO2
#include "benchmark_messages_proto2.pb.hpp"
using namespace benchmarks::proto2;
#else
#include "benchmark_messages_proto3.pb.hpp"
using namespace benchmarks::proto3;
#endif

#ifdef NON_OWNING
struct monotonic_buffer_resource {
  std::size_t size;
  void *mem = 0;
  void *cur = 0;
  monotonic_buffer_resource(std::size_t sz) : size(sz), mem(malloc(sz)), cur(mem) {}
  ~monotonic_buffer_resource() { free(mem); }
  void *allocate(std::size_t n, std::size_t alignment) {
    if (std::align(alignment, n, cur, size)) {
      size -= n;
      auto result = cur;
      cur = (char *)cur + n;
      return result;
    }
    throw std::bad_alloc{};
  }
};
#endif

const int repetitions = 1;

int main() {
  try {
    auto data = read_data_file(data_dir + "/google_message1.dat");

    benchmark(
        [&data]() -> bool {
          GoogleMessage1 message;
#ifdef NON_OWNING
          monotonic_buffer_resource memory_resource(data.size());
          return hpp::proto::read_proto(message, data, hpp::proto::pb_context{memory_resource}).success();
#else
          return hpp::proto::read_proto(message, data).success();
#endif
        },
        repetitions, "decoding message");

    GoogleMessage1 message;
#ifdef NON_OWNING
    monotonic_buffer_resource memory_resource(data.size());
    (void)hpp::proto::read_proto(message, data, hpp::proto::pb_context{memory_resource});
#else
    (void)hpp::proto::read_proto(message, data);
#endif

    benchmark(
        [&message]() -> bool {
          std::vector<char> data;
          return hpp::proto::write_proto(message, data).success();
        },
        repetitions, "encoding message");
  } catch (...) {
    return 1;
  }

  return 0;
}