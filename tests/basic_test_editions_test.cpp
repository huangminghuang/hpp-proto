#include <basic_test_editions.pb.hpp>
#include <editions_test.pb.hpp>

void test_basic_test_editions() {
  editions_upb_test::TestFeaturesMessage message;
  using meta_type = decltype(pb_meta(message));
  static_assert(!hpp::proto::concepts::optional<decltype(message.implicit)>);
  static_assert(hpp::proto::concepts::optional<decltype(message.explicit_)>);
  static_assert(!hpp::proto::concepts::optional<decltype(message.legacy_required)>);

  static_assert(std::ranges::range<decltype(message.packed)>);
  static_assert(std::tuple_element_t<3, meta_type>::is_packed);

  static_assert(std::ranges::range<decltype(message.expanded)>);
  static_assert(!std::tuple_element_t<4, meta_type>::is_packed);

  static_assert(hpp::proto::concepts::optional<decltype(message.delimited)>);
  static_assert(std::tuple_element_t<5, meta_type>::is_group);

  static_assert(hpp::proto::concepts::optional<decltype(message.length_prefixed)>);
  static_assert(!std::tuple_element_t<6, meta_type>::is_group);
}

void test_editions_test() {
  upb::test_2023::EditionsMessage message;
  using meta_type = decltype(pb_meta(message));
  static_assert(hpp::proto::concepts::optional<decltype(message.plain_field)>);
  static_assert(!hpp::proto::concepts::optional<decltype(message.implicit_presence_field)>);
  static_assert(!hpp::proto::concepts::optional<decltype(message.required_field)>);
  static_assert(hpp::proto::concepts::optional<decltype(message.delimited_field)>);
  static_assert(std::tuple_element_t<3, meta_type>::is_group);

  static_assert(hpp::proto::concepts::optional<decltype(message.closed_enum_field)>);
  static_assert(std::tuple_element_t<4, meta_type>::closed_enum);

  static_assert(!hpp::proto::concepts::optional<decltype(message.open_enum_field)>);
  static_assert(!std::tuple_element_t<5, meta_type>::closed_enum);

  static_assert(std::ranges::range<decltype(message.unpacked_field)>);
  static_assert(!std::tuple_element_t<6, meta_type>::is_packed);

  static_assert(std::ranges::range<decltype(message.packed_field)>);
  static_assert(std::tuple_element_t<7, meta_type>::is_packed);
}

int main() { return 0; }