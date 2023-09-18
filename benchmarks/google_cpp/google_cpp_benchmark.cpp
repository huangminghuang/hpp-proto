#include <filesystem>
#include <stdio.h>
#ifdef PROTO2
#include "benchmark_messages_proto2.pb.h"
using namespace benchmarks::proto2;
#else
#include "benchmark_messages_proto3.pb.h"
using namespace benchmarks::proto3;
#endif
#define xstr(a) str(a)
#define str(s) #s

bool benchmark(auto &&fun, uint32_t repetitions, const char *description) {
  auto start = std::chrono::steady_clock::now();
  for (int i = 0; i < repetitions; ++i)
    if (!fun()) {
      printf("Error for %s.", description);
      return false;
    }
  std::chrono::nanoseconds duration = std::chrono::steady_clock::now() - start;
  printf("The time for %s is %lld ns\n", description, duration.count());
  return true;
}

int repetitions = 1;

int main() {

  std::filesystem::path data_file(xstr(DATA_DIR) "/google_message1.dat");
  auto size = std::filesystem::file_size(data_file);
  std::vector<char> data(size);

  auto file = fopen(data_file.c_str(), "rb");
  if (!file) {
    puts("unable to open data file");
    return 1;
  }
  if (fread(data.data(), 1, size, file) != size) {
    puts("unable to read data file");
    return 1;
  }

  GoogleMessage1 message;

  if (!benchmark([&message, &data]() -> bool { return message.ParseFromArray(data.data(), data.size()); }, repetitions,
                 "decoding message"))
    return 1;

  if (!benchmark(
          [&message]() -> bool {
            std::string data;
            return message.SerializeToString(&data);
          },
          repetitions, "encoding message"))
    return 1;

  return 0;
}