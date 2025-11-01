
#include "gpb_proto_json/gpb_proto_json.hpp"
#include "test_util.hpp"
#include <boost/ut.hpp>
#include <google/protobuf/unittest_proto3.glz.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>

#if defined(__GNUC__)
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wmissing-designated-field-initializers"
#else
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
#endif
// NOLINTBEGIN(clang-diagnostic-missing-designated-field-initializers)
template <typename T>
  requires requires { glz::meta<T>::value; }
std::ostream &operator<<(std::ostream &os, const T &v) {
  return os << hpp::proto::write_json(v).value();
}

using namespace std::literals::string_view_literals;
using namespace boost::ut;
template <hpp::proto::compile_time_string cts>
using bytes_literal = hpp::proto::bytes_literal<cts>;

template <typename Traits>
struct Proto3Tests {

  using TestAllTypes = proto3_unittest::TestAllTypes<Traits>;
  using ForeignMessage = proto3_unittest::ForeignMessage<Traits>;
  using TestUnpackedTypes = proto3_unittest::TestUnpackedTypes<Traits>;

  using bool_t = typename Traits::template repeated_t<bool>::value_type;
  using string_t = typename Traits::string_t;
  using bytes_t = typename Traits::bytes_t;

  // We selectively set/check a few representative fields rather than all fields
  // as this test is only expected to cover the basics of lite support.
  static void SetAllFields(TestAllTypes *m) {
    m->optional_int32 = 100;
    m->optional_string = "asdf";
    m->optional_bytes = "jkl;"_bytes;

    m->optional_nested_message.emplace().bb = 42;
    m->optional_foreign_message.emplace().c = 43;
    m->optional_nested_enum = TestAllTypes::NestedEnum::BAZ;
    m->optional_foreign_enum = proto3_unittest::ForeignEnum::FOREIGN_BAZ;
    m->optional_lazy_message.emplace().bb = 45;

    const static auto repeated_int32 = std::initializer_list<int32_t>{100};
    m->repeated_int32 = repeated_int32;
    const static auto repeated_string = std::initializer_list<string_t>{"asdf"};
    m->repeated_string = repeated_string;
    const static auto repeated_bytes = std::initializer_list<bytes_t>{"jkl;"_bytes};
    m->repeated_bytes = repeated_bytes;
    const static auto repeated_nested_message = std::initializer_list<typename TestAllTypes::NestedMessage>{{.bb = 46}};
    m->repeated_nested_message = repeated_nested_message;
    const static auto repeated_foreign_message = std::initializer_list<ForeignMessage>{ForeignMessage{.c = 47}};
    m->repeated_foreign_message = repeated_foreign_message;
    const static auto repeated_nested_enum =
        std::initializer_list<typename TestAllTypes::NestedEnum>{TestAllTypes::NestedEnum::BAZ};
    m->repeated_nested_enum = repeated_nested_enum;
    const static auto repeated_foreign_enum =
        std::initializer_list<proto3_unittest::ForeignEnum>{proto3_unittest::ForeignEnum::FOREIGN_BAZ};
    m->repeated_foreign_enum = repeated_foreign_enum;
    const static auto repeated_lazy_message = std::initializer_list<typename TestAllTypes::NestedMessage>{{.bb = 49}};
    m->repeated_lazy_message = repeated_lazy_message;

    m->oneof_field = 1U;
    m->oneof_field.template emplace<typename TestAllTypes::NestedMessage>().bb = 50;
    m->oneof_field = string_t{"test"}; // only this one remains set
  }

  static void SetUnpackedFields(TestUnpackedTypes *message) {
    const static auto repeated_int32 = std::initializer_list<int32_t>{601, 701};
    message->repeated_int32 = repeated_int32;
    const static auto repeated_int64 = std::initializer_list<int64_t>{602LL, 702LL};
    message->repeated_int64 = repeated_int64;
    const static auto repeated_uint32 = std::initializer_list<uint32_t>{603U, 703U};
    message->repeated_uint32 = repeated_uint32;
    const static auto repeated_uint64 = std::initializer_list<uint64_t>{604ULL, 704ULL};
    message->repeated_uint64 = repeated_uint64;
    const static auto repeated_sint32 = std::initializer_list<int32_t>{605, 705};
    message->repeated_sint32 = repeated_sint32;
    const static auto repeated_sint64 = std::initializer_list<int64_t>{606LL, 706LL};
    message->repeated_sint64 = repeated_sint64;

    const static auto repeated_fixed32 = std::initializer_list<uint32_t>{607U, 707U};
    message->repeated_fixed32 = repeated_fixed32;
    const static auto repeated_fixed64 = std::initializer_list<uint64_t>{608ULL, 708ULL};
    message->repeated_fixed64 = repeated_fixed64;
    const static auto repeated_sfixed32 = std::initializer_list<int32_t>{609, 709};
    message->repeated_sfixed32 = repeated_sfixed32;
    const static auto repeated_sfixed64 = std::initializer_list<int64_t>{610LL, 710LL};
    message->repeated_sfixed64 = repeated_sfixed64;
    const static auto repeated_float = std::initializer_list<float>{611.F, 711.F};
    message->repeated_float = repeated_float;
    const static auto repeated_double = std::initializer_list<double>{612., 712.};
    message->repeated_double = repeated_double;
    const static auto repeated_bool = std::initializer_list<bool_t>{true, false};
    message->repeated_bool = repeated_bool;
    const static auto repeated_nested_enum = std::initializer_list<typename TestAllTypes::NestedEnum>{
        TestAllTypes::NestedEnum::BAR, TestAllTypes::NestedEnum::BAZ};
    message->repeated_nested_enum = repeated_nested_enum;
  }

  static void ExpectAllFieldsSet(const TestAllTypes &m) {
    namespace ut = boost::ut;

    ut::expect(100 == m.optional_int32);
    ut::expect("asdf"sv == m.optional_string);
    ut::expect(std::ranges::equal("jkl;"_bytes, m.optional_bytes));

    ut::expect(m.optional_nested_message.has_value() && 42 == m.optional_nested_message->bb);
    ut::expect(m.optional_foreign_message.has_value() && 43 == m.optional_foreign_message->c);
    ut::expect(TestAllTypes::NestedEnum::BAZ == m.optional_nested_enum);
    ut::expect(proto3_unittest::ForeignEnum::FOREIGN_BAZ == m.optional_foreign_enum);
    ut::expect(m.optional_lazy_message.has_value() && 45 == m.optional_lazy_message->bb);

    ut::expect(1 == m.repeated_int32.size());
    ut::expect(100 == m.repeated_int32[0]);
    ut::expect(1 == m.repeated_string.size());
    ut::expect("asdf" == m.repeated_string[0]);
    ut::expect(1 == m.repeated_bytes.size());
    ut::expect(std::ranges::equal("jkl;"_bytes, m.repeated_bytes[0]));
    ut::expect(1 == m.repeated_nested_message.size());
    ut::expect(46 == m.repeated_nested_message[0].bb);
    ut::expect(1 == m.repeated_foreign_message.size());
    ut::expect(47 == m.repeated_foreign_message[0].c);
    ut::expect(1 == m.repeated_nested_enum.size());
    ut::expect(TestAllTypes::NestedEnum::BAZ == m.repeated_nested_enum[0]);
    ut::expect(1 == m.repeated_foreign_enum.size());
    ut::expect(proto3_unittest::ForeignEnum::FOREIGN_BAZ == m.repeated_foreign_enum[0]);
    ut::expect(1 == m.repeated_lazy_message.size());
    ut::expect(49 == m.repeated_lazy_message[0].bb);

    ut::expect("test"sv == std::get<string_t>(m.oneof_field));
  }

  static void ExpectUnpackedFieldsSet(TestUnpackedTypes &message) {
    namespace ut = boost::ut;

    ut::expect(std::ranges::equal(std::vector{601, 701}, message.repeated_int32));
    ut::expect(std::ranges::equal(std::vector{602LL, 702LL}, message.repeated_int64));
    ut::expect(std::ranges::equal(std::vector{603U, 703U}, message.repeated_uint32));
    ut::expect(std::ranges::equal(std::vector{604ULL, 704ULL}, message.repeated_uint64));
    ut::expect(std::ranges::equal(std::vector{605, 705}, message.repeated_sint32));
    ut::expect(std::ranges::equal(std::vector{606LL, 706LL}, message.repeated_sint64));
    ut::expect(std::ranges::equal(std::vector{607U, 707U}, message.repeated_fixed32));
    ut::expect(std::ranges::equal(std::vector{608ULL, 708ULL}, message.repeated_fixed64));
    ut::expect(std::ranges::equal(std::vector{609, 709}, message.repeated_sfixed32));
    ut::expect(std::ranges::equal(std::vector{610LL, 710LL}, message.repeated_sfixed64));
    ut::expect(std::ranges::equal(std::vector{611.F, 711.F}, message.repeated_float));
    ut::expect(std::ranges::equal(std::vector{612., 712.}, message.repeated_double));
    ut::expect(std::ranges::equal(std::array<bool_t, 2>{true, false}, message.repeated_bool));
    ut::expect(std::ranges::equal(std::vector{TestAllTypes::NestedEnum::BAR, TestAllTypes::NestedEnum::BAZ},
                                  message.repeated_nested_enum));
  }

  static void run() {
    auto unittest_proto3_descriptorset = read_file("unittest.desc.binpb");

    "protobuf"_test = [] {
      TestAllTypes original;
      SetAllFields(&original);

      TestAllTypes msg;

      std::pmr::monotonic_buffer_resource mr;
      std::vector<std::byte> data;

      expect(hpp::proto::write_proto(original, data).ok());
      expect(hpp::proto::read_proto(msg, data, hpp::proto::alloc_from{mr}).ok());

      ExpectAllFieldsSet(msg);
    };

    "unpacked_repeated"_test = [&] {
      TestUnpackedTypes original;
      SetUnpackedFields(&original);

      TestUnpackedTypes msg;

      std::pmr::monotonic_buffer_resource mr;
      std::vector<char> data;
      expect(hpp::proto::write_proto(original, data).ok());
      expect(hpp::proto::read_proto(msg, data, hpp::proto::alloc_from{mr}).ok());

      ExpectUnpackedFieldsSet(msg);

#if !defined(HPP_PROTO_DISABLE_GLAZE)
      auto r = glz::write_json(original);
      expect(r.has_value());
      auto original_json = gpb_based::proto_to_json(unittest_proto3_descriptorset, "proto3_unittest.TestUnpackedTypes",
                                                    {data.data(), data.size()});

      expect(fatal(!original_json.empty()));
      expect(eq(*r, original_json));
#endif
    };

#if !defined(HPP_PROTO_DISABLE_GLAZE)
    "glaze"_test = [&] {
      TestAllTypes original;
      SetAllFields(&original);

      std::pmr::monotonic_buffer_resource mr;
      std::vector<char> data;
      expect(hpp::proto::write_proto(original, data).ok());

      auto original_json = gpb_based::proto_to_json(unittest_proto3_descriptorset, "proto3_unittest.TestAllTypes",
                                                    {data.data(), data.size()});
      expect(fatal(!original_json.empty()));
      expect(hpp::proto::write_json(original).value() == original_json);

      TestAllTypes msg;
      expect(hpp::proto::read_json(msg, original_json, hpp::proto::alloc_from{mr}).ok());

      ExpectAllFieldsSet(msg);
    };
#endif
  }
};
// NOLINTEND(clang-diagnostic-missing-designated-field-initializers)

const boost::ut::suite proto3_test = [] {
  "proto3"_test = []<class Traits> { Proto3Tests<Traits>::run(); } |
                  std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}