#include <boost/ut.hpp>
#include <hpp_proto/json_serializer.h>

struct bytes_example {
  hpp::proto::bytes field;
};

template <>
struct glz::meta<bytes_example> {
  using T = bytes_example;
  static constexpr auto value = object("field", hpp::proto::as_optional_ref<&T::field>());
};

struct uint64_example {
  uint64_t field = 0;
  bool operator==(const uint64_example &) const = default;
};

template <>
struct glz::meta<uint64_example> {
  using T = uint64_example;
  static constexpr auto value = object("field", glz::quoted<&uint64_example::field>());
};

struct optional_example {
  int32_t  field1 = {};
  uint64_t field2 = {};
  int32_t  field3 = {};
  double   field4 = {};
  bool operator==(const optional_example &) const = default;
};

template <>
struct glz::meta<optional_example> {
  using T = optional_example;
  static constexpr auto value = object(
      // clang-format off
      "field1", hpp::proto::as_optional_ref<&T::field1>(), 
      "field2", hpp::proto::as_optional_ref<&T::field2>(), 
      "field3", hpp::proto::as_optional_ref<&T::field3>(), 
      "field4", hpp::proto::as_optional_ref<&T::field4>());
  // clang-format on
};

// using namespace std::literals::string_view_literals;

namespace std {
std::ostream &operator<<(std::ostream &os, byte v) { return os << static_cast<char>(v); }
} // namespace std

void verify_bytes(std::string_view text, std::string_view json) {
  using namespace boost::ut;
  std::span<const std::byte> bs{reinterpret_cast<const std::byte *>(&text[0]), text.size()};
  bytes_example msg;
  msg.field.assign(bs.begin(), bs.end());
  expect(json == glz::write_json(msg));

  bytes_example msg2;
  expect((!glz::read_json(msg2, std::string(json.begin(), json.size()))) >> fatal);
  expect(msg.field == msg2.field);
}

namespace ut = boost::ut;

ut::suite test_bytes_json = [] {
  using namespace boost::ut::literals;
  "empty"_test = [] { verify_bytes("", R"({})"); };
  "one_padding_test"_test = [] { verify_bytes("light work.", R"({"field":"bGlnaHQgd29yay4="})"); };
  "two_padding_test"_test = [] { verify_bytes("light work", R"({"field":"bGlnaHQgd29yaw=="})"); };
  "no_padding_test"_test = [] { verify_bytes("light wor", R"({"field":"bGlnaHQgd29y"})"); };
};

template <typename T>
void verify(T &&msg, std::string_view json) {
  using namespace boost::ut;
  expect(json == glz::write_json(msg));

  T msg2;
  expect((!glz::read_json(msg2, std::string(json.begin(), json.size()))) >> fatal);
  expect(msg == msg2);
}

ut::suite test_uint64_json = [] { verify(uint64_example{.field = 123U}, R"({"field":"123"})"); };

ut::suite test_optional_json = [] {
  verify(optional_example{.field2 = 123U, .field3 = 456}, R"({"field2":"123","field3":456})");
};

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return result;
}