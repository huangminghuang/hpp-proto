// clang-format off
#include <unordered_map>
#include <map>
#include <string_view>
#include "basic_test_proto2.pb.hpp"

using namespace test;
// clang-format on

// Proto2 metadata tests assert generated tuple positions directly.
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,misc-const-correctness)

int main() {
  TestMessage message;
  using meta_type = decltype(pb_meta(message));
  static_assert(!hpp_proto::concepts::optional<decltype(message.field1)>);
  static_assert(hpp_proto::concepts::optional<decltype(message.explicit_field)>);
  static_assert(!hpp_proto::concepts::optional<decltype(message.legacy_required)>);

  static_assert(std::ranges::range<decltype(message.packed)>);
  static_assert(std::tuple_element_t<3, meta_type>::is_packed());

  static_assert(std::ranges::range<decltype(message.expanded)>);
  static_assert(!std::tuple_element_t<4, meta_type>::is_packed());

  static_assert(hpp_proto::concepts::optional<decltype(message.delimited)>);
  static_assert(std::tuple_element_t<5, meta_type>::is_delimited());

  static_assert(hpp_proto::concepts::optional<decltype(message.length_prefixed)>);
  static_assert(!std::tuple_element_t<6, meta_type>::is_delimited());

  using implicit_enum_meta = std::tuple_element_t<9, meta_type>;
  static_assert(!hpp_proto::concepts::optional<decltype(message.implicit_enum)>);
  static_assert(!implicit_enum_meta::explicit_presence());
  static_assert(!implicit_enum_meta::closed_enum());

  using explicit_enum_meta = std::tuple_element_t<10, meta_type>;
  static_assert(hpp_proto::concepts::optional<decltype(message.explicit_enum)>);
  static_assert(explicit_enum_meta::explicit_presence());
  static_assert(explicit_enum_meta::closed_enum());

  using repeated_enum_meta = std::tuple_element_t<11, meta_type>;
  static_assert(std::ranges::range<decltype(message.repeated_enum)>);
  static_assert(repeated_enum_meta::is_packed());
  static_assert(repeated_enum_meta::closed_enum());

  using oneof_enum_meta = std::tuple_element_t<12, meta_type>;
  static_assert(oneof_enum_meta::explicit_presence());
  static_assert(oneof_enum_meta::closed_enum());

  using extension_meta = std::tuple_element_t<0, closed_enum_extension::pb_meta>;
  static_assert(extension_meta::explicit_presence());
  static_assert(extension_meta::closed_enum());

  using namespace std::string_view_literals;
  if (!hpp_proto::read_binpb(message, "\x20\x02"sv).ok()) {
    return 1;
  }
  if (message.implicit_enum != static_cast<ClosedEnum>(2)) {
    return 2;
  }
  if (is_valid(message.implicit_enum)) {
    return 3;
  }

  TestMessage<> oneof_message;
  if (!hpp_proto::read_binpb(oneof_message, "\xa8\x03\x02"sv).ok()) {
    return 4;
  }
  if (oneof_message.oneof_enum.has_value() || !oneof_message.unknown_fields_.fields.contains(53)) {
    return 5;
  }

  TestMessage<> extension_message;
  if (!hpp_proto::read_binpb(extension_message, "\xc0\x0c\x02"sv).ok()) {
    return 6;
  }
  closed_enum_extension extension;
  if (const auto status = extension_message.get_extension(extension); status.ec != std::errc::value_too_large) {
    return 7;
  }
  if (extension.value != ClosedEnum::CLOSED_ENUM_UNSPECIFIED || !extension_message.has_extension(extension)) {
    return 8;
  }
}

// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,misc-const-correctness)
