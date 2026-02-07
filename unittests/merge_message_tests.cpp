#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/binpb.hpp>
#include <hpp_proto/merge.hpp>

template <typename Traits = hpp_proto::default_traits>
struct ForeignMessage {
  std::int32_t c = {};
  std::int32_t d = {};
  typename Traits::bytes_t e;
  bool operator==(const ForeignMessage &) const = default;
};

template <typename Traits>
auto pb_meta(const ForeignMessage<Traits> &)
    -> std::tuple<
        hpp_proto::field_meta<1, &ForeignMessage<Traits>::c, hpp_proto::field_option::none, hpp_proto::vint64_t>,
        hpp_proto::field_meta<2, &ForeignMessage<Traits>::d, hpp_proto::field_option::none, hpp_proto::vint64_t>,
        hpp_proto::field_meta<15, &ForeignMessage<Traits>::e, hpp_proto::field_option::none>>;

#if defined(__GNUC__) && (__GNUC__ < 14) && !defined(__clang__)
namespace std {
template <typename LFirst, typename LSecond, typename RFirst, typename RSecond>
bool operator==(const pair<LFirst, LSecond> &lhs, const pair<RFirst, RSecond> &rhs) {
  return lhs.first == rhs.first && lhs.second == rhs.second;
}
} // namespace std
#endif

template <typename Traits = hpp_proto::default_traits>
struct TestMessage {
  hpp_proto::optional<std::int32_t> optional_int32;
  hpp_proto::optional<std::int64_t> optional_int64;
  hpp_proto::optional<std::uint32_t> optional_uint32;
  hpp_proto::optional<std::uint64_t> optional_uint64;
  hpp_proto::optional<typename Traits::string_t> optional_string;
  hpp_proto::optional<typename Traits::bytes_t> optional_bytes;

  std::optional<ForeignMessage<Traits>> optional_foreign_message;
  Traits::template repeated_t<std::int32_t> repeated_int32;
  Traits::template repeated_t<std::int64_t> repeated_int64;
  Traits::template repeated_t<std::uint32_t> repeated_uint32;
  Traits::template repeated_t<std::uint64_t> repeated_uint64;

  hpp_proto::optional<std::int32_t, 41> default_int32;
  hpp_proto::optional<std::int64_t, 42LL> default_int64;
  hpp_proto::optional<std::uint32_t, 43U> default_uint32;
  hpp_proto::optional<std::uint64_t, 44ULL> default_uint64;

  Traits::template map_t<std::int32_t, std::int32_t> map_int32_int32;

  // NOLINTNEXTLINE(cppcoreguidelines-use-enum-class)
  enum oneof_field_oneof_case : std::uint8_t {
    oneof_uint32 = 1,
    oneof_foreign_message = 2,
    oneof_string = 3,
    oneof_bytes = 4
  };

  static constexpr std::array<std::uint32_t, 5> oneof_field_oneof_numbers{0U, 111U, 112U, 113U, 114U};
  std::variant<std::monostate, std::uint32_t, ForeignMessage<Traits>, typename Traits::string_t,
               typename Traits::bytes_t>
      oneof_field;

  bool operator==(const TestMessage &) const = default;
};

template <typename Traits>
auto pb_meta(const TestMessage<Traits> &)
    -> std::tuple<
        hpp_proto::field_meta<1, &TestMessage<Traits>::optional_int32, hpp_proto::field_option::explicit_presence,
                               hpp_proto::vint64_t>,
        hpp_proto::field_meta<2, &TestMessage<Traits>::optional_int64, hpp_proto::field_option::explicit_presence,
                               hpp_proto::vint64_t>,
        hpp_proto::field_meta<3, &TestMessage<Traits>::optional_uint32, hpp_proto::field_option::explicit_presence,
                               hpp_proto::vuint32_t>,
        hpp_proto::field_meta<4, &TestMessage<Traits>::optional_uint64, hpp_proto::field_option::explicit_presence,
                               hpp_proto::vuint64_t>,
        hpp_proto::field_meta<14, &TestMessage<Traits>::optional_string, hpp_proto::field_option::explicit_presence>,
        hpp_proto::field_meta<15, &TestMessage<Traits>::optional_bytes, hpp_proto::field_option::explicit_presence>,
        hpp_proto::field_meta<19, &TestMessage<Traits>::optional_foreign_message,
                               hpp_proto::field_option::explicit_presence>,
        hpp_proto::field_meta<31, &TestMessage<Traits>::repeated_int32, hpp_proto::field_option::none,
                               hpp_proto::vint64_t>,
        hpp_proto::field_meta<32, &TestMessage<Traits>::repeated_int64, hpp_proto::field_option::none,
                               hpp_proto::vint64_t>,
        hpp_proto::field_meta<33, &TestMessage<Traits>::repeated_uint32, hpp_proto::field_option::none,
                               hpp_proto::vuint32_t>,
        hpp_proto::field_meta<34, &TestMessage<Traits>::repeated_uint64, hpp_proto::field_option::none,
                               hpp_proto::vuint64_t>,
        hpp_proto::field_meta<61, &TestMessage<Traits>::default_int32, hpp_proto::field_option::explicit_presence,
                               hpp_proto::vint64_t>,
        hpp_proto::field_meta<62, &TestMessage<Traits>::default_int64, hpp_proto::field_option::explicit_presence,
                               hpp_proto::vint64_t>,
        hpp_proto::field_meta<63, &TestMessage<Traits>::default_uint32, hpp_proto::field_option::explicit_presence,
                               hpp_proto::vuint32_t>,
        hpp_proto::field_meta<64, &TestMessage<Traits>::default_uint64, hpp_proto::field_option::explicit_presence,
                               hpp_proto::vuint64_t>,
        hpp_proto::field_meta<71, &TestMessage<Traits>::map_int32_int32, hpp_proto::field_option::none,
                               hpp_proto::map_entry<hpp_proto::vint64_t, hpp_proto::vint64_t,
                                                     hpp_proto::field_option::none, hpp_proto::field_option::none>>,
        hpp_proto::oneof_field_meta<
            &TestMessage<Traits>::oneof_field,
            hpp_proto::field_meta<111, 1, hpp_proto::field_option::explicit_presence, hpp_proto::vuint32_t>,
            hpp_proto::field_meta<112, 2, hpp_proto::field_option::explicit_presence>,
            hpp_proto::field_meta<113, 3, hpp_proto::field_option::explicit_presence>,
            hpp_proto::field_meta<114, 4, hpp_proto::field_option::explicit_presence>>>;

template <typename Traits = hpp_proto::default_traits>
struct MoveRepeatedMessage {
  typename Traits::template repeated_t<typename Traits::string_t> values;
  bool operator==(const MoveRepeatedMessage &) const = default;
};

template <typename Traits>
auto pb_meta(const MoveRepeatedMessage<Traits> &)
    -> std::tuple<hpp_proto::field_meta<1, &MoveRepeatedMessage<Traits>::values, hpp_proto::field_option::none>>;

const boost::ut::suite merge_test_suite = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;
  using namespace std::string_view_literals;

  static_assert(hpp_proto::concepts::repeated<hpp_proto::equality_comparable_span<const int>>);

  auto abc_bytes = "abc"_bytes;
  auto def_bytes = "def"_bytes;
  auto uvw_bytes = "uvw"_bytes;
  auto xyz_bytes = "xyz"_bytes;

  "merge"_test =
      [&]<class TraitsPair> {
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

        using DestTraits = typename TraitsPair::first_type;
        using SourceTraits = typename TraitsPair::second_type;

        TestMessage<DestTraits> dest;
        TestMessage<SourceTraits> source;

        // Optional fields
        source.optional_int32 = 1; // only source
        source.optional_int64 = 2; // both source and dest
        source.optional_bytes = abc_bytes;

        // Optional fields with defaults
        source.default_int32 = 13; // only source
        source.default_int64 = 14; // both source and dest

        // Nested message field
        source.optional_foreign_message.emplace(ForeignMessage<SourceTraits>{.c = 1, .d = 0, .e = uvw_bytes});

        auto list_5_6 = std::initializer_list<int32_t>{5, 6};
        auto list_7_8 = std::initializer_list<std::int64_t>{7LL, 8LL};
        auto list_9_10 = std::initializer_list<std::int64_t>{9LL, 10LL};
        auto list_11_12 = std::initializer_list<uint32_t>{11U, 12U};

        // Repeated fields
        source.repeated_int32 = list_5_6; // only source
        source.repeated_int64 = list_7_8; // both source and dest

        // Optional fields
        dest.optional_int64 = 3;
        dest.optional_uint32 = 4; // only dest
        dest.optional_bytes = def_bytes;
        // Optional fields with defaults
        dest.default_int64 = 15;
        dest.default_uint32 = 16; // only dest

        // Nested message field
        dest.optional_foreign_message.emplace(ForeignMessage<DestTraits>{.c = 0, .d = 2, .e = xyz_bytes});

        // Repeated fields
        dest.repeated_int64 = list_9_10;
        dest.repeated_uint32 = list_11_12; // only dest

        should("merge const reference") = [=]() mutable {
          std::pmr::monotonic_buffer_resource mr;
          hpp_proto::merge(dest, source, hpp_proto::alloc_from(mr));
          verify_merge(dest);
        };

        should("merge rvalue reference") = [=]() mutable {
          std::pmr::monotonic_buffer_resource mr;
          hpp_proto::merge(dest, std::move(source), hpp_proto::alloc_from(mr));
          verify_merge(dest);
        };
      } |
      std::tuple<std::pair<hpp_proto::default_traits, hpp_proto::default_traits>,
                 std::pair<hpp_proto::non_owning_traits, hpp_proto::non_owning_traits>,
                 std::pair<hpp_proto::non_owning_traits, hpp_proto::default_traits>,
                 std::pair<hpp_proto::default_traits, hpp_proto::non_owning_traits>>{};

  "map_merge"_test =
      []<class TraitsPair> {
        using DestTraits = typename TraitsPair::first_type;
        using SourceTraits = typename TraitsPair::second_type;
        using namespace boost::ut::bdd;

        given("dest and source") = [] {
          when("only source contains map data") = [] {
            TestMessage<DestTraits> dest;
            TestMessage<SourceTraits> source;
            using source_map_value_type = decltype(source.map_int32_int32)::value_type;
            auto data = std::initializer_list<source_map_value_type>{{1, 1}, {2, 2}};
            source.map_int32_int32 = data;

            then("merge const reference should work") = [=]() mutable {
              std::pmr::monotonic_buffer_resource mr;
              hpp_proto::merge(dest, source, hpp_proto::alloc_from(mr));
              expect(std::ranges::equal(data, dest.map_int32_int32));
            };
            then("merge rvalue reference should work") = [=]() mutable {
              std::pmr::monotonic_buffer_resource mr;
              hpp_proto::merge(dest, std::move(source), hpp_proto::alloc_from(mr));
              expect(std::ranges::equal(data, dest.map_int32_int32));
            };
          };
          when("only dest contains map data") = [] {
            TestMessage<DestTraits> dest;
            TestMessage<SourceTraits> source;
            using source_map_value_type = decltype(source.map_int32_int32)::value_type;
            using dest_map_value_type = decltype(dest.map_int32_int32)::value_type;
            auto data = std::initializer_list<dest_map_value_type>{{1, 1}, {2, 2}};
            dest.map_int32_int32 = data;

            then("merge const reference should work") = [=]() mutable {
              std::pmr::monotonic_buffer_resource mr;
              hpp_proto::merge(dest, source, hpp_proto::alloc_from(mr));
              expect(std::ranges::equal(data, dest.map_int32_int32));
            };
            then("merge rvalue reference should work") = [=]() mutable {
              std::pmr::monotonic_buffer_resource mr;
              hpp_proto::merge(dest, std::move(source), hpp_proto::alloc_from(mr));
              expect(std::ranges::equal(data, dest.map_int32_int32));
            };
          };
          when("only both dest and source contain map data") = [] {
            TestMessage<DestTraits> dest;
            TestMessage<SourceTraits> source;
            using source_map_value_type = decltype(source.map_int32_int32)::value_type;
            using dest_map_value_type = decltype(dest.map_int32_int32)::value_type;
            auto dest_data = std::initializer_list<dest_map_value_type>{{1, 1}, {2, 2}};
            auto src_data = std::initializer_list<source_map_value_type>{{2, 12}, {3, 13}};
            dest.map_int32_int32 = dest_data;
            source.map_int32_int32 = src_data;

            auto expected = hpp_proto::flat_map<int32_t, int32_t>{{1, 1}, {2, 12}, {3, 13}};

            then("merge const reference should work") = [=]() mutable {
              std::pmr::monotonic_buffer_resource mr;
              hpp_proto::merge(dest, source, hpp_proto::alloc_from(mr));
              if constexpr (hpp_proto::concepts::flat_map<decltype(dest.map_int32_int32)>) {
                expect(expected == dest.map_int32_int32);
              } else {
                expect(expected == hpp_proto::flat_map<int32_t, int32_t>{dest.map_int32_int32.rbegin(),
                                                                          dest.map_int32_int32.rend()});
              }
            };
            then("merge rvalue reference should work") = [=]() mutable {
              std::pmr::monotonic_buffer_resource mr;
              hpp_proto::merge(dest, std::move(source), hpp_proto::alloc_from(mr));
              if constexpr (hpp_proto::concepts::flat_map<decltype(dest.map_int32_int32)>) {
                expect(expected == dest.map_int32_int32);
              } else {
                expect(expected == hpp_proto::flat_map<int32_t, int32_t>{dest.map_int32_int32.rbegin(),
                                                                          dest.map_int32_int32.rend()});
              }
            };
          };
        };
      } |
      std::tuple<std::pair<hpp_proto::default_traits, hpp_proto::default_traits>,
                 std::pair<hpp_proto::non_owning_traits, hpp_proto::non_owning_traits>,
                 std::pair<hpp_proto::non_owning_traits, hpp_proto::default_traits>,
                 std::pair<hpp_proto::default_traits, hpp_proto::non_owning_traits>>{};

  "oneof_merge"_test =
      []<class TraitsPair> {
        using DestTraits = typename TraitsPair::first_type;
        using SourceTraits = typename TraitsPair::second_type;
        using namespace std::string_literals;
        using namespace boost::ut::bdd;

        given("dest and source") = [] {
          when("only source contains oneof data") = [] {
            TestMessage<DestTraits> dest;
            TestMessage<SourceTraits> source;
            source.oneof_field = 1U;

            std::pmr::monotonic_buffer_resource mr;
            hpp_proto::merge(dest, source, hpp_proto::alloc_from(mr));
            expect(fatal(eq(dest.oneof_field.index(), TestMessage<DestTraits>::oneof_uint32)));
            expect(eq(1U, std::get<uint32_t>(dest.oneof_field)));
          };
          when("only dest contains oneof data") = [] {
            TestMessage<DestTraits> dest;
            TestMessage<SourceTraits> source;
            dest.oneof_field = 1U;

            std::pmr::monotonic_buffer_resource mr;
            hpp_proto::merge(dest, source, hpp_proto::alloc_from(mr));
            expect(fatal(eq(dest.oneof_field.index(), TestMessage<DestTraits>::oneof_uint32)));
            expect(eq(1U, std::get<uint32_t>(dest.oneof_field)));
          };
          when("both source and dest contain oneof data of different types") = [] {
            TestMessage<DestTraits> dest;
            TestMessage<SourceTraits> source;
            using namespace std::string_view_literals;
            dest.oneof_field = 1U;
            source.oneof_field.template emplace<typename SourceTraits::string_t>("abc"sv);

            std::pmr::monotonic_buffer_resource mr;
            hpp_proto::merge(dest, source, hpp_proto::alloc_from(mr));
            expect(fatal(eq(dest.oneof_field.index(), TestMessage<DestTraits>::oneof_string)));
            expect(eq("abc"sv, std::get<3>(dest.oneof_field)));
          };
          when("both source and dest contain oneof data of same types") = [] {
            TestMessage<DestTraits> dest;
            TestMessage<SourceTraits> source;
            dest.oneof_field.template emplace<TestMessage<DestTraits>::oneof_foreign_message>().c = 1;
            source.oneof_field.template emplace<TestMessage<SourceTraits>::oneof_foreign_message>().d = 2;

            std::pmr::monotonic_buffer_resource mr;
            hpp_proto::merge(dest, source, hpp_proto::alloc_from(mr));
            expect(fatal(eq(dest.oneof_field.index(), TestMessage<DestTraits>::oneof_foreign_message)));
            expect(ForeignMessage<DestTraits>{.c = 1, .d = 2} ==
                   std::get<ForeignMessage<DestTraits>>(dest.oneof_field));
          };
        };
      } |
      std::tuple<std::pair<hpp_proto::default_traits, hpp_proto::default_traits>,
                 std::pair<hpp_proto::non_owning_traits, hpp_proto::non_owning_traits>,
                 std::pair<hpp_proto::non_owning_traits, hpp_proto::default_traits>,
                 std::pair<hpp_proto::default_traits, hpp_proto::non_owning_traits>>{};

  "merge_repeated_move_optimization"_test = [] {
    MoveRepeatedMessage<> dest;
    MoveRepeatedMessage<> source;
    source.values = {"abc", "def"};

    hpp_proto::merge(dest, std::move(source));

    expect(eq(dest.values.size(), 2U));
    expect(dest.values[0] == "abc"sv);
    // Since dest was empty, it should have used the container move assignment.
    // NOLINTNEXTLINE(bugprone-use-after-move,hicpp-invalid-access-moved)
    expect(source.values.empty());
  };

  "merge_repeated_move_append"_test = [] {
    MoveRepeatedMessage<> dest;
    dest.values = {"123"};
    MoveRepeatedMessage<> source;
    source.values = {"abc", "def"};

    hpp_proto::merge(dest, std::move(source));

    expect(eq(dest.values.size(), 3U));
    expect(dest.values[1] == "abc"sv);
    // Since dest was not empty, it should have moved elements one by one.
    // std::string elements should be in a moved-from state (typically empty).
    // NOLINTBEGIN(bugprone-use-after-move,hicpp-invalid-access-moved)
    expect(source.values[0].empty());
    expect(source.values[1].empty());
    // NOLINTEND(bugprone-use-after-move,hicpp-invalid-access-moved)
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
