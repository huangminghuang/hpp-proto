#include "test_util.hpp"
#include <boost/ut.hpp>
#include <hpp_proto/pb_serializer.hpp>

struct ForeignMessage {
  std::int32_t c = {};
  std::int32_t d = {};
  hpp::proto::bytes e;
  bool operator==(const ForeignMessage &) const = default;
};
auto pb_meta(const ForeignMessage &)
    -> std::tuple<hpp::proto::field_meta<1, &ForeignMessage::c, hpp::proto::field_option::none, hpp::proto::vint64_t>,
                  hpp::proto::field_meta<2, &ForeignMessage::d, hpp::proto::field_option::none, hpp::proto::vint64_t>,
                  hpp::proto::field_meta<15, &ForeignMessage::e, hpp::proto::field_option::none>>;

struct TestMessage {
  hpp::proto::optional<std::int32_t> optional_int32;
  hpp::proto::optional<std::int64_t> optional_int64;
  hpp::proto::optional<std::uint32_t> optional_uint32;
  hpp::proto::optional<std::uint64_t> optional_uint64;
  hpp::proto::optional<std::string> optional_string;
  hpp::proto::optional<hpp::proto::bytes> optional_bytes;

  std::optional<ForeignMessage> optional_foreign_message;
  std::vector<std::int32_t> repeated_int32;
  std::vector<std::int64_t> repeated_int64;
  std::vector<std::uint32_t> repeated_uint32;
  std::vector<std::uint64_t> repeated_uint64;

  hpp::proto::optional<std::int32_t, 41> default_int32;
  hpp::proto::optional<std::int64_t, 42LL> default_int64;
  hpp::proto::optional<std::uint32_t, 43U> default_uint32;
  hpp::proto::optional<std::uint64_t, 44ULL> default_uint64;

  hpp::proto::flat_map<std::int32_t, std::int32_t> map_int32_int32;

  enum oneof_field_oneof_case : int { oneof_uint32 = 1, oneof_foreign_message = 2, oneof_string = 3, oneof_bytes = 4 };
  static constexpr std::array<std::uint32_t, 5> oneof_field_oneof_numbers{0U, 111U, 112U, 113U, 114U};
  std::variant<std::monostate, std::uint32_t, ForeignMessage, std::string, hpp::proto::bytes> oneof_field;

  bool operator==(const TestMessage &) const = default;
};

auto pb_meta(const TestMessage &)
    -> std::tuple<
        hpp::proto::field_meta<1, &TestMessage::optional_int32, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<2, &TestMessage::optional_int64, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<3, &TestMessage::optional_uint32, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vuint32_t>,
        hpp::proto::field_meta<4, &TestMessage::optional_uint64, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vuint64_t>,
        hpp::proto::field_meta<14, &TestMessage::optional_string, hpp::proto::field_option::explicit_presence>,
        hpp::proto::field_meta<15, &TestMessage::optional_bytes, hpp::proto::field_option::explicit_presence>,
        hpp::proto::field_meta<19, &TestMessage::optional_foreign_message, hpp::proto::field_option::explicit_presence>,
        hpp::proto::field_meta<31, &TestMessage::repeated_int32, hpp::proto::field_option::none, hpp::proto::vint64_t>,
        hpp::proto::field_meta<32, &TestMessage::repeated_int64, hpp::proto::field_option::none, hpp::proto::vint64_t>,
        hpp::proto::field_meta<33, &TestMessage::repeated_uint32, hpp::proto::field_option::none,
                               hpp::proto::vuint32_t>,
        hpp::proto::field_meta<34, &TestMessage::repeated_uint64, hpp::proto::field_option::none,
                               hpp::proto::vuint64_t>,
        hpp::proto::field_meta<61, &TestMessage::default_int32, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<62, &TestMessage::default_int64, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vint64_t>,
        hpp::proto::field_meta<63, &TestMessage::default_uint32, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vuint32_t>,
        hpp::proto::field_meta<64, &TestMessage::default_uint64, hpp::proto::field_option::explicit_presence,
                               hpp::proto::vuint64_t>,
        hpp::proto::field_meta<71, &TestMessage::map_int32_int32, hpp::proto::field_option::none,
                               hpp::proto::map_entry<hpp::proto::vint64_t, hpp::proto::vint64_t,
                                                     hpp::proto::field_option::none, hpp::proto::field_option::none>>,
        hpp::proto::oneof_field_meta<
            &TestMessage::oneof_field,
            hpp::proto::field_meta<111, 1, hpp::proto::field_option::explicit_presence, hpp::proto::vuint32_t>,
            hpp::proto::field_meta<112, 2, hpp::proto::field_option::explicit_presence>,
            hpp::proto::field_meta<113, 3, hpp::proto::field_option::explicit_presence>,
            hpp::proto::field_meta<114, 4, hpp::proto::field_option::explicit_presence>>>;

TestMessage get_source() {
  TestMessage source;
  // Optional fields
  source.optional_int32 = 1; // only source
  source.optional_int64 = 2; // both source and dest
  source.optional_bytes = "abc"_bytes;

  // Optional fields with defaults
  source.default_int32 = 13; // only source
  source.default_int64 = 14; // both source and dest

  // Nested message field
  source.optional_foreign_message.emplace(ForeignMessage{.c = 1, .d = 0, .e = "uvw"_bytes});

  // Repeated fields
  source.repeated_int32.assign({5, 6});     // only source
  source.repeated_int64.assign({7LL, 8LL}); // both source and dest

  // Map fields

  source.map_int32_int32[2] = 12; // both source and dest
  source.map_int32_int32[3] = 13; // only source
  return source;
}

TestMessage get_dest() {
  TestMessage dest;

  // Optional fields
  dest.optional_int64 = 3;
  dest.optional_uint32 = 4; // only dest
  dest.optional_bytes = "def"_bytes;

  // Optional fields with defaults
  dest.default_int64 = 15;
  dest.default_uint32 = 16; // only dest

  // Nested message field
  dest.optional_foreign_message.emplace(ForeignMessage{.c = 0, .d = 2, .e = "xyz"_bytes});

  // Repeated fields
  dest.repeated_int64.assign({9LL, 10LL});
  dest.repeated_uint32.assign({11U, 12U}); // only dest

  // Map fields
  dest.map_int32_int32[1] = 1; // only dest
  dest.map_int32_int32[2] = 2; // both source and dest

  return dest;
}

const boost::ut::suite merge_test_suite = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  "merge"_test = [] {
    TestMessage source = get_source();
    TestMessage dest = get_dest();

    auto verify_merge = [](const TestMessage &dest) {
      // Optional fields: source overwrites dest if source is specified
      expect(eq(1, dest.optional_int32.value()));  // only source: use source
      expect(eq(2, dest.optional_int64.value()));  // source and dest: use source
      expect(eq(4, dest.optional_uint32.value())); // only dest: use dest
      expect(eq(0, dest.optional_uint64.value())); // neither: use default
      expect(eq("abc"_bytes, dest.optional_bytes.value()));

      // Optional fields with defaults
      expect(eq(13, dest.default_int32.value()));  // only source: use source
      expect(eq(14, dest.default_int64.value()));  // source and dest: use source
      expect(eq(16, dest.default_uint32.value())); // only dest: use dest
      expect(eq(44, dest.default_uint64.value())); // neither: use default

      // Nested message field
      expect(fatal(dest.optional_foreign_message.has_value()));
      expect(eq(1, dest.optional_foreign_message->c));
      expect(eq(2, dest.optional_foreign_message->d));
      expect(eq("uvw"_bytes, dest.optional_foreign_message->e));

      // Repeated fields: concatenate source onto the end of dest
      expect(std::vector<int32_t>{5, 6} == dest.repeated_int32);
      expect(std::vector<int64_t>{9LL, 10LL, 7LL, 8LL} == dest.repeated_int64);
      expect(std::vector<uint32_t>{11U, 12U} == dest.repeated_uint32);
      expect(dest.repeated_uint64.empty());

      // Map fields
      expect(hpp::proto::flat_map<int32_t, int32_t>{{1, 1}, {2, 12}, {3, 13}} == dest.map_int32_int32);
    };

    hpp::proto::merge(dest, source);
    verify_merge(dest);

    dest = get_dest();
    hpp::proto::merge(dest, std::move(source));
    verify_merge(dest);
  };

  "oneof_merge"_test = [] {
    using namespace std::string_literals;
    {
      TestMessage dest;
      TestMessage source;
      source.oneof_field = 1U;

      hpp::proto::merge(dest, source);
      expect(fatal(eq(dest.oneof_field.index(), TestMessage::oneof_uint32)));
      expect(eq(1U, std::get<uint32_t>(dest.oneof_field)));
    }
    {
      TestMessage dest;
      TestMessage source;
      dest.oneof_field = 1U;

      hpp::proto::merge(dest, source);
      expect(fatal(eq(dest.oneof_field.index(), TestMessage::oneof_uint32)));
      expect(eq(1U, std::get<uint32_t>(dest.oneof_field)));
    }
    {
      TestMessage dest;
      TestMessage source;
      dest.oneof_field = 1U;
      source.oneof_field = "abc";
      hpp::proto::merge(dest, source);
      expect(fatal(eq(dest.oneof_field.index(), TestMessage::oneof_string)));
      expect(eq("abc"s, std::get<std::string>(dest.oneof_field)));
    }
    {
      TestMessage dest;
      TestMessage source;
      dest.oneof_field.emplace<TestMessage::oneof_foreign_message>().c = 1;
      source.oneof_field.emplace<TestMessage::oneof_foreign_message>().d = 2;
      hpp::proto::merge(dest, source);
      expect(fatal(eq(dest.oneof_field.index(), TestMessage::oneof_foreign_message)));
      expect(ForeignMessage{.c = 1, .d = 2} == std::get<ForeignMessage>(dest.oneof_field));
    }
  };
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}