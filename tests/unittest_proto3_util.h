#pragma once
#include <boost/ut.hpp>
#include <google/protobuf/unittest_proto3.glz.hpp>
#include <google/protobuf/unittest_proto3.pb.hpp>

// We selectively set/check a few representative fields rather than all fields
// as this test is only expected to cover the basics of lite support.
inline void SetAllFields(proto3_unittest::TestAllTypes *m) {
  m->optional_int32 = 100;
  m->optional_string = "asdf";
  m->optional_bytes = "jkl;"_bytes;
  m->optional_nested_message = proto3_unittest::TestAllTypes::NestedMessage { .bb = 42 };
  m->optional_foreign_message.emplace().c = 43;
  m->optional_nested_enum = proto3_unittest::TestAllTypes::NestedEnum::BAZ;
  m->optional_foreign_enum = proto3_unittest::ForeignEnum::FOREIGN_BAZ;
  m->optional_lazy_message = proto3_unittest::TestAllTypes::NestedMessage { .bb = 45 };

  m->repeated_int32.push_back(100);
  m->repeated_string.push_back("asdf");
  m->repeated_bytes.emplace_back("jkl;"_bytes);
  m->repeated_nested_message.emplace_back().bb = 46;
  m->repeated_foreign_message.emplace_back().c = 47;
  m->repeated_nested_enum.push_back(proto3_unittest::TestAllTypes::NestedEnum::BAZ);
  m->repeated_foreign_enum.push_back(proto3_unittest::ForeignEnum::FOREIGN_BAZ);
  m->repeated_lazy_message.emplace_back().bb = 49;

  m->oneof_field = 1U;
  m->oneof_field = proto3_unittest::TestAllTypes::NestedMessage { .bb = 50 };
  m->oneof_field = "test"; // only this one remains set
}

inline void SetUnpackedFields(proto3_unittest::TestUnpackedTypes *message) {
  message->repeated_int32.assign({601, 701});
  message->repeated_int64.assign({602LL, 702LL});
  message->repeated_uint32.assign({603U, 703U});
  message->repeated_uint64.assign({604ULL, 704ULL});
  message->repeated_sint32.assign({605, 705});
  message->repeated_sint64.assign({606LL, 706LL});
  message->repeated_fixed32.assign({607U, 707U});
  message->repeated_fixed64.assign({608ULL, 708ULL});
  message->repeated_sfixed32.assign({609, 709});
  message->repeated_sfixed64.assign({610LL, 710LL});
  message->repeated_float.assign({611.f, 711.f});
  message->repeated_double.assign({612., 712.});
  message->repeated_bool.assign({true, false});
  message->repeated_nested_enum.assign(
      {proto3_unittest::TestAllTypes::NestedEnum::BAR, proto3_unittest::TestAllTypes::NestedEnum::BAZ});
}

inline void ExpectAllFieldsSet(const proto3_unittest::TestAllTypes &m) {
  namespace ut = boost::ut;

  ut::expect(100 == m.optional_int32);
  ut::expect("asdf" == m.optional_string);
  ut::expect("jkl;"_bytes == m.optional_bytes);
  ut::expect(true == m.optional_nested_message.has_value());
  ut::expect(42 == m.optional_nested_message->bb);
  ut::expect(true == m.optional_foreign_message.has_value());
  ut::expect(43 == m.optional_foreign_message->c);
  ut::expect(proto3_unittest::TestAllTypes::NestedEnum::BAZ == m.optional_nested_enum);
  ut::expect(proto3_unittest::ForeignEnum::FOREIGN_BAZ == m.optional_foreign_enum);
  ut::expect(true == m.optional_lazy_message.has_value());
  ut::expect(45 == m.optional_lazy_message->bb);

  ut::expect(1 == m.repeated_int32.size());
  ut::expect(100 == m.repeated_int32[0]);
  ut::expect(1 == m.repeated_string.size());
  ut::expect("asdf" == m.repeated_string[0]);
  ut::expect(1 == m.repeated_bytes.size());
  ut::expect("jkl;"_bytes == m.repeated_bytes[0]);
  ut::expect(1 == m.repeated_nested_message.size());
  ut::expect(46 == m.repeated_nested_message[0].bb);
  ut::expect(1 == m.repeated_foreign_message.size());
  ut::expect(47 == m.repeated_foreign_message[0].c);
  ut::expect(1 == m.repeated_nested_enum.size());
  ut::expect(proto3_unittest::TestAllTypes::NestedEnum::BAZ == m.repeated_nested_enum[0]);
  ut::expect(1 == m.repeated_foreign_enum.size());
  ut::expect(proto3_unittest::ForeignEnum::FOREIGN_BAZ == m.repeated_foreign_enum[0]);
  ut::expect(1 == m.repeated_lazy_message.size());
  ut::expect(49 == m.repeated_lazy_message[0].bb);

  ut::expect("test" == std::get<std::string>(m.oneof_field));
}

void ExpectUnpackedFieldsSet(proto3_unittest::TestUnpackedTypes &message) {
  namespace ut = boost::ut;

  ut::expect(ut::eq(std::vector{601, 701}, message.repeated_int32));
  ut::expect(ut::eq(std::vector<int64_t>{602LL, 702LL}, message.repeated_int64));
  ut::expect(ut::eq(std::vector{603U, 703U}, message.repeated_uint32));
  ut::expect(ut::eq(std::vector<uint64_t>{604ULL, 704ULL}, message.repeated_uint64));
  ut::expect(ut::eq(std::vector{605, 705}, message.repeated_sint32));
  ut::expect(ut::eq(std::vector<int64_t>{606LL, 706LL}, message.repeated_sint64));
  ut::expect(ut::eq(std::vector{607U, 707U}, message.repeated_fixed32));
  ut::expect(ut::eq(std::vector<uint64_t>{608ULL, 708ULL}, message.repeated_fixed64));
  ut::expect(ut::eq(std::vector{609, 709}, message.repeated_sfixed32));
  ut::expect(ut::eq(std::vector<int64_t>{610LL, 710LL}, message.repeated_sfixed64));
  ut::expect(ut::eq(std::vector{611.f, 711.f}, message.repeated_float));
  ut::expect(ut::eq(std::vector{612., 712.}, message.repeated_double));
  ut::expect(ut::eq(std::vector<hpp::proto::boolean>{true, false}, message.repeated_bool));
  ut::expect(std::vector{proto3_unittest::TestAllTypes::NestedEnum::BAR,
                         proto3_unittest::TestAllTypes::NestedEnum::BAZ} == message.repeated_nested_enum);
}

