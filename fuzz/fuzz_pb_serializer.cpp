#include <fuzzer/FuzzedDataProvider.h>
#include <google/protobuf/map_unittest.pb.hpp>
#include <google/protobuf/unittest.pb.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>

std::vector<std::vector<char>> split_input(FuzzedDataProvider &provider) {
  std::vector<std::vector<char>> result;
  while (result.size() < 9) {
    auto v = provider.ConsumeBytes<char>(provider.ConsumeIntegralInRange<int>(10, 128));
    if (v.empty()) {
      break;
    }
    result.push_back(std::move(v));
  };

  auto v = provider.ConsumeRemainingBytes<char>();
  if (!v.empty())
    result.push_back(std::move(v));
  return result;
}

using messages_t =
    std::tuple<proto3_unittest::TestAllTypes, protobuf_unittest::TestAllTypes, protobuf_unittest::TestMap>;

hpp::proto::status work(FuzzedDataProvider &provider, uint32_t choice, std::index_sequence<>) { return {}; }

template <std::size_t FirstIndex, std::size_t... Indices>
hpp::proto::status work(FuzzedDataProvider &provider, uint32_t choice, std::index_sequence<FirstIndex, Indices...>) {
  auto message_index = choice % std::tuple_size_v<messages_t>;
  auto deserialize_message = [&] {
    bool to_split = choice / std::tuple_size_v<messages_t>;
    typename std::tuple_element<FirstIndex, messages_t>::type message;
    if (to_split) {
      return hpp::proto::read_proto(message, split_input(provider));
    } else {
      return hpp::proto::read_proto(message, provider.ConsumeRemainingBytes<char>());
    }
  };

  return (message_index == FirstIndex) ? deserialize_message()
                                       : work(provider, choice, std::index_sequence<Indices...>{});
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);
  auto choice = provider.ConsumeIntegralInRange<unsigned>(0, std::tuple_size_v<messages_t> * 2 - 1);
  auto status = work(provider, choice, std::make_index_sequence<std::tuple_size_v<messages_t>>{});
  return status.ok() ? 0 : 1;
}