
#include "benchmark_util.h"
#ifdef PROTO2
#include "benchmark_messages_proto2.pb.hpp"
using namespace benchmarks::proto2;
#else
#include "benchmark_messages_proto3.pb.hpp"
using namespace benchmarks::proto3;
#endif

const int repetitions = 1;

int main() {
  try {
    auto data = read_data_file(data_dir + "/google_message1.dat");

    GoogleMessage1 message;

    benchmark([&message, &data]() -> bool { return !hpp::proto::read_proto(message, data); }, repetitions,
              "decoding message");

    benchmark(
        [&message]() -> bool {
          std::vector<char> data;
          return !hpp::proto::write_proto(message, data);
        },
        repetitions, "encoding message");
  } catch (...) {
    return 1;
  }

  return 0;
}