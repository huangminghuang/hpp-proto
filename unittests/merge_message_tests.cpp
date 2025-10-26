#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/pb_serializer.hpp>

template <typename Traits = hpp::proto::default_traits>
struct ForeignMessage {
  std::int32_t c = {};
  std::int32_t d = {};
  typename Traits::bytes_t e;
  bool operator==(const ForeignMessage &) const = default;
};

template <typename Traits>
auto pb_meta(const ForeignMessage<Traits> &)
    -> std::tuple<
        hpp::proto::field_meta<1, &ForeignMessage<Traits>::c, hpp::proto::field_option::none, hpp::proto::vint64_t>,
        hpp::proto::field_meta<2, &ForeignMessage<Traits>::d, hpp::proto::field_option::none, hpp::proto::vint64_t>,
        hpp::proto::field_meta<15, &ForeignMessage<Traits>::e, hpp::proto::field_option::none>>;

template <typename Traits = hpp::proto::default_traits>
struct TestMessage {
  hpp::proto::optional<std::int32_t> optional_int32;
  hpp::proto::optional<std::int64_t> optional_int64;
  hpp::proto::optional<std::uint32_t> optional_uint32;
  hpp::proto::optional<std::uint64_t> optional_uint64;
  hpp::proto::optional<typename Traits::string_t> optional_string;
  hpp::proto::optional<typename Traits::bytes_t> optional_bytes;

  std::optional<ForeignMessage<Traits>> optional_foreign_message;
  Traits::template repeated_t<std::int32_t> repeated_int32;
  Traits::template repeated_t<std::int64_t> repeated_int64;
  Traits::template repeated_t<std::uint32_t> repeated_uint32;
  Traits::template repeated_t<std::uint64_t> repeated_uint64;

  hpp::proto::optional<std::int32_t, 41> default_int32;
  hpp::proto::optional<std::int64_t, 42LL> default_int64;
  hpp::proto::optional<std::uint32_t, 43U> default_uint32;
  hpp::proto::optional<std::uint64_t, 44ULL> default_uint64;

  Traits::template map_t<std::int32_t, std::int32_t> map_int32_int32;

  // NOLINTNEXTLINE(performance-enum-size)
  enum oneof_field_oneof_case : int { oneof_uint32 = 1, oneof_foreign_message = 2, oneof_string = 3, oneof_bytes = 4 };
  static constexpr std::array<std::uint32_t, 5> oneof_field_oneof_numbers{0U, 111U, 112U, 113U, 114U};
  std::variant<std::monostate, std::uint32_t, ForeignMessage<Traits>, std::string, hpp::proto::bytes> oneof_field;

  bool operator==(const TestMessage &) const = default;
};

template <typename Traits>
auto pb_meta(const TestMessage<Traits> &)
    -> std::tuple<
        hpp::proto::field_meta<1, &TestMessage<Traits>::optional_int32, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<2, &TestMessage<Traits>::optional_int64, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<3, &TestMessage<Traits>::optional_uint32, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vuint32_t>,
        hpp::proto::field_meta<4, &TestMessage<Traits>::optional_uint64, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vuint64_t>,
        hpp::proto::field_meta<14, &TestMessage<Traits>::optional_string, hpp::proto::field_option::explicit_presence>,
        hpp::proto::field_meta<15, &TestMessage<Traits>::optional_bytes, hpp::proto::field_option::explicit_presence>,
        hpp::proto::field_meta<19, &TestMessage<Traits>::optional_foreign_message,
                               hpp::proto::field_option::explicit_presence>,
        hpp::proto::field_meta<31, &TestMessage<Traits>::repeated_int32, hpp::proto::field_option::none,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<32, &TestMessage<Traits>::repeated_int64, hpp::proto::field_option::none,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<33, &TestMessage<Traits>::repeated_uint32, hpp::proto::field_option::none,
                               hpp::proto::vuint32_t>,
        hpp::proto::field_meta<34, &TestMessage<Traits>::repeated_uint64, hpp::proto::field_option::none,
                               hpp::proto::vuint64_t>,
        hpp::proto::field_meta<61, &TestMessage<Traits>::default_int32, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<62, &TestMessage<Traits>::default_int64, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<63, &TestMessage<Traits>::default_uint32, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vuint32_t>,
        hpp::proto::field_meta<64, &TestMessage<Traits>::default_uint64, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vuint64_t>,
        hpp::proto::field_meta<71, &TestMessage<Traits>::map_int32_int32, hpp::proto::field_option::none,
                               hpp::proto::map_entry<hpp::proto::vint64_t, hpp::proto::vint64_t,
                                                     hpp::proto::field_option::none, hpp::proto::field_option::none>>,
        hpp::proto::oneof_field_meta<
            &TestMessage<Traits>::oneof_field,
            hpp::proto::field_meta<111, 1, hpp::proto::field_option::explicit_presence, hpp::proto::vuint32_t>,
            hpp::proto::field_meta<112, 2, hpp::proto::field_option::explicit_presence>,
            hpp::proto::field_meta<113, 3, hpp::proto::field_option::explicit_presence>,
            hpp::proto::field_meta<114, 4, hpp::proto::field_option::explicit_presence>>>;

const boost::ut::suite merge_test_suite = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  static_assert(hpp::proto::concepts::repeated<hpp::proto::equality_comparable_span<const int>>);

  auto abc_bytes = std::initializer_list{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
  auto def_bytes = std::initializer_list{std::byte{'d'}, std::byte{'e'}, std::byte{'f'}};
  auto uvw_bytes = std::initializer_list{std::byte{'u'}, std::byte{'v'}, std::byte{'w'}};
  auto xyz_bytes = std::initializer_list{std::byte{'x'}, std::byte{'y'}, std::byte{'z'}};

  "merge"_test = [&]<class Traits> {
    auto verify_merge = [&](const auto &dest) {
      // Optional fields: source overwrites dest if source is specified
      expect(eq(1, dest.optional_int32.value()));  // only source: use source
      expect(eq(2, dest.optional_int64.value()));  // source and dest: use source
      expect(eq(4, dest.optional_uint32.value())); // only dest: use dest
      expect(eq(0, dest.optional_uint64.value())); // neither: use default
      expect(std::ranges::equal(abc_bytes, dest.optional_bytes.value()));

      // Optional fields with defaults
      expect(eq(13, dest.default_int32.value()));  // only source: use source
      expect(eq(14, dest.default_int64.value()));  // source and dest: use source
      expect(eq(16, dest.default_uint32.value())); // only dest: use dest
      expect(eq(44, dest.default_uint64.value())); // neither: use default

      // Nested message field
      expect(fatal(dest.optional_foreign_message.has_value()));
      expect(eq(1, dest.optional_foreign_message->c));
      expect(eq(2, dest.optional_foreign_message->d));
      expect(std::ranges::equal(uvw_bytes, dest.optional_foreign_message->e));

      // Repeated fields: concatenate source onto the end of dest
      expect(std::ranges::equal(std::initializer_list<int32_t>{5, 6}, dest.repeated_int32));
      expect(std::ranges::equal(std::initializer_list<int64_t>{9LL, 10LL, 7LL, 8LL}, dest.repeated_int64));
      expect(std::ranges::equal(std::initializer_list<uint32_t>{11U, 12U}, dest.repeated_uint32));
      expect(dest.repeated_uint64.empty());
    };

    TestMessage<Traits> dest;
    TestMessage<Traits> source;

    // Optional fields
    source.optional_int32 = 1; // only source
    source.optional_int64 = 2; // both source and dest
    source.optional_bytes = abc_bytes;

    // Optional fields with defaults
    source.default_int32 = 13; // only source
    source.default_int64 = 14; // both source and dest

    // Nested message field
    source.optional_foreign_message.emplace(ForeignMessage<Traits>{.c = 1, .d = 0, .e = uvw_bytes});

    auto list_5_6 = std::initializer_list{5, 6};
    auto list_7_8 = std::initializer_list{7LL, 8LL};
    auto list_9_10 = std::initializer_list{9LL, 10LL};
    auto list_11_12 = std::initializer_list{11U, 12U};

    // Repeated fields
    source.repeated_int32 = list_5_6;     // only source
    source.repeated_int64 = list_7_8; // both source and dest

    // Optional fields
    dest.optional_int64 = 3;
    dest.optional_uint32 = 4; // only dest
    dest.optional_bytes = def_bytes;
    // Optional fields with defaults
    dest.default_int64 = 15;
    dest.default_uint32 = 16; // only dest

    // Nested message field
    dest.optional_foreign_message.emplace(ForeignMessage<Traits>{.c = 0, .d = 2, .e = xyz_bytes});

    // Repeated fields
    dest.repeated_int64 = list_9_10;
    dest.repeated_uint32 = list_11_12; // only dest

    should("merge const reference") = [=]() mutable {
      std::pmr::monotonic_buffer_resource mr;
      hpp::proto::merge(dest, source, hpp::proto::alloc_from(mr));
      verify_merge(dest);
    };

    should("merge rvalue reference") = [=]() mutable {
      std::pmr::monotonic_buffer_resource mr;
      hpp::proto::merge(dest, std::move(source), hpp::proto::alloc_from(mr));
      verify_merge(dest);
    };
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};

  

  "map_merge"_test = []<class Traits> {
    {
      // only source
      TestMessage<Traits> dest;
      TestMessage<Traits> source;
      using map_value_type = decltype(source.map_int32_int32)::value_type;

      auto data = std::initializer_list<map_value_type>{{1, 1}, {2, 2}};
      source.map_int32_int32 = data;

      should("only source merge const reference") = [=]() mutable {
        std::pmr::monotonic_buffer_resource mr;
        hpp::proto::merge(dest, source, hpp::proto::alloc_from(mr));
        expect(std::ranges::equal(data, dest.map_int32_int32));
      };
      should("only source merge rvalue reference") = [=]() mutable {
        std::pmr::monotonic_buffer_resource mr;
        hpp::proto::merge(dest, std::move(source), hpp::proto::alloc_from(mr));
        expect(std::ranges::equal(data, dest.map_int32_int32));
      };
    }
    {
      // only dest
      TestMessage<Traits> dest;
      TestMessage<Traits> source;
      using map_value_type = decltype(source.map_int32_int32)::value_type;
      auto data = std::initializer_list<map_value_type>{{1, 1}, {2, 2}};
      dest.map_int32_int32 = data;

      should("only dest merge const reference") = [=]() mutable {
        std::pmr::monotonic_buffer_resource mr;
        hpp::proto::merge(dest, source, hpp::proto::alloc_from(mr));
        expect(std::ranges::equal(data, dest.map_int32_int32));
      };
      should("only dest merge rvalue reference") = [=]() mutable {
        std::pmr::monotonic_buffer_resource mr;
        hpp::proto::merge(dest, std::move(source), hpp::proto::alloc_from(mr));
        expect(std::ranges::equal(data, dest.map_int32_int32));
      };
    }
    {
      // both dest and source
      TestMessage<Traits> dest;
      TestMessage<Traits> source;
      using map_value_type = decltype(source.map_int32_int32)::value_type;
      auto dest_data = std::initializer_list<map_value_type>{{1, 1}, {2, 2}};
      auto src_data = std::initializer_list<map_value_type>{{2, 12}, {3, 13}};
      dest.map_int32_int32 = dest_data;
      source.map_int32_int32 = src_data;

      auto expected = hpp::proto::flat_map<int32_t, int32_t>{{1, 1}, {2, 12}, {3, 13}};

      should("both dest and source merge const reference") = [=]() mutable {
        std::pmr::monotonic_buffer_resource mr;
        hpp::proto::merge(dest, source, hpp::proto::alloc_from(mr));
        if constexpr (hpp::proto::concepts::flat_map<decltype(dest.map_int32_int32)>) {
          expect(expected == dest.map_int32_int32);
        } else {
          expect(expected == hpp::proto::flat_map<int32_t, int32_t>{dest.map_int32_int32.rbegin(), dest.map_int32_int32.rend()});
        }
      };
      should("both dest and source merge rvalue reference") = [=]() mutable {
        std::pmr::monotonic_buffer_resource mr;
        hpp::proto::merge(dest, std::move(source), hpp::proto::alloc_from(mr));
        if constexpr (hpp::proto::concepts::flat_map<decltype(dest.map_int32_int32)>) {
          expect(expected == dest.map_int32_int32);
        } else {
          expect(expected == hpp::proto::flat_map<int32_t, int32_t>{dest.map_int32_int32.rbegin(), dest.map_int32_int32.rend()});
        }
      };
    }
  } | std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};
  

  "oneof_merge"_test = []<class Traits> {
    using namespace std::string_literals;
    { // only source
      TestMessage<Traits> dest;
      TestMessage<Traits> source;
      source.oneof_field = 1U;

      std::pmr::monotonic_buffer_resource mr;
      hpp::proto::merge(dest, source, hpp::proto::alloc_from(mr));
      expect(fatal(eq(dest.oneof_field.index(), TestMessage<Traits>::oneof_uint32)));
      expect(eq(1U, std::get<uint32_t>(dest.oneof_field)));
    }
    { // only dest
      TestMessage<Traits> dest;
      TestMessage<Traits> source;
      dest.oneof_field = 1U;

      std::pmr::monotonic_buffer_resource mr;
      hpp::proto::merge(dest, source, hpp::proto::alloc_from(mr));
      expect(fatal(eq(dest.oneof_field.index(), TestMessage<Traits>::oneof_uint32)));
      expect(eq(1U, std::get<uint32_t>(dest.oneof_field)));
    }
    { // both source and dest, different types
      TestMessage<Traits> dest;
      TestMessage<Traits> source;
      dest.oneof_field = 1U;
      source.oneof_field = "abc";

      std::pmr::monotonic_buffer_resource mr;
      hpp::proto::merge(dest, source, hpp::proto::alloc_from(mr));
      expect(fatal(eq(dest.oneof_field.index(), TestMessage<Traits>::oneof_string)));
      expect(eq("abc"s, std::get<std::string>(dest.oneof_field)));
    }
    { // both source and dest, same types
      TestMessage<Traits> dest;
      TestMessage<Traits> source;
      dest.oneof_field.template emplace<TestMessage<Traits>::oneof_foreign_message>().c = 1;
      source.oneof_field.template emplace<TestMessage<Traits>::oneof_foreign_message>().d = 2;

      std::pmr::monotonic_buffer_resource mr;
      hpp::proto::merge(dest, source, hpp::proto::alloc_from(mr));
      expect(fatal(eq(dest.oneof_field.index(), TestMessage<Traits>::oneof_foreign_message)));
      expect(ForeignMessage<Traits>{.c = 1, .d = 2} == std::get<ForeignMessage<Traits>>(dest.oneof_field));
    }
  }| std::tuple<hpp::proto::default_traits, hpp::proto::non_owning_traits>{};
 
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}