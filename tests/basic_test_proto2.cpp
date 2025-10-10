// clang-format off
#include <unordered_map>
#include <map>
#include "basic_test_proto2.pb.hpp"
// clang-format on
int main() {
  TestMessage message;
  using meta_type = decltype(pb_meta(message));
  static_assert(!hpp::proto::concepts::optional<decltype(message.field1)>);
  static_assert(hpp::proto::concepts::optional<decltype(message.explicit_field)>);
  static_assert(!hpp::proto::concepts::optional<decltype(message.legacy_required)>);

  static_assert(std::ranges::range<decltype(message.packed)>);
  static_assert(std::tuple_element_t<3, meta_type>::is_packed());

  static_assert(std::ranges::range<decltype(message.expanded)>);
  static_assert(!std::tuple_element_t<4, meta_type>::is_packed());

  static_assert(hpp::proto::concepts::optional<decltype(message.delimited)>);
  static_assert(std::tuple_element_t<5, meta_type>::is_delimited());

  static_assert(hpp::proto::concepts::optional<decltype(message.length_prefixed)>);
  static_assert(!std::tuple_element_t<6, meta_type>::is_delimited());

}