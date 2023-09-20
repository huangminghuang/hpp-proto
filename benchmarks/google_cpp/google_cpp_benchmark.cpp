#include "benchmark_util.h"

#ifdef PROTO2
#include "benchmark_messages_proto2.pb.h"
using namespace benchmarks::proto2;
#else
#include "benchmark_messages_proto3.pb.h"
using namespace benchmarks::proto3;
#endif

const int repetitions = 1;

int main() {
  try {
    auto data = read_data_file(data_dir + "/google_message1.dat");

    GoogleMessage1 message;

    benchmark([&message, &data]() -> bool { return message.ParseFromArray(data.data(), static_cast<int>(data.size())); }, repetitions,
              "decoding message");
    benchmark(
        [&message]() -> bool {
          std::string data;
          return message.SerializeToString(&data);
        },
        repetitions, "encoding message");
    return 1;
  } catch (...) {
    return 1;
  }

  return 0;
}