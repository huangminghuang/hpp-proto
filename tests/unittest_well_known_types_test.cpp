#include "google/protobuf/unittest_well_known_types.glz.hpp"
#include "google/protobuf/unittest_well_known_types.pb.hpp"
#include "gpb_proto_json/gpb_proto_json.hpp"
#include "hpp_proto/dynamic_message/json.hpp"
#include "test_util.hpp"
#include <boost/ut.hpp>

using namespace boost::ut;

struct pmr_traits : hpp::proto::default_traits {
  using string_t = std::pmr::string;
  using bytes_t = std::pmr::vector<std::byte>;

  template <typename T>
  using repeated_t = std::pmr::vector<T>;

  template <typename Key, typename Value>
  using map_t = std::pmr::map<Key, Value>;

  struct unknown_fields_range_t {
    bool operator==(const unknown_fields_range_t &) const = default;
  };
};

template <typename Traits>
using test_type =
    std::variant<std::monostate, typename Traits::template map_t<typename Traits::string_t, typename Traits::bytes_t>>;

template <typename Traits>
struct std::is_trivially_destructible<google::protobuf::Struct<Traits>> : is_trivially_destructible<test_type<Traits>> {
};

template <typename Traits>
struct std::is_trivially_move_constructible<google::protobuf::Struct<Traits>>
    : is_trivially_move_constructible<test_type<Traits>> {};

template <typename Traits>
struct std::is_trivially_move_assignable<google::protobuf::Struct<Traits>>
    : is_trivially_move_assignable<test_type<Traits>> {};

template <typename Traits>
struct std::is_trivially_copy_constructible<google::protobuf::Struct<Traits>>
    : is_trivially_copy_constructible<test_type<Traits>> {};

template <typename Traits>
struct std::is_trivially_copy_assignable<google::protobuf::Struct<Traits>>
    : is_trivially_copy_assignable<test_type<Traits>> {};

template <typename Traits>
struct WellKnownTypesTests {
  using TestWellKnownTypes = proto2_unittest::TestWellKnownTypes<Traits>;

  static void SetAllFields([[maybe_unused]] TestWellKnownTypes *m) {}

  static void ExpectAllFieldsSet([[maybe_unused]] const TestWellKnownTypes &m) {}

  static void run() {
    auto unittest_descriptorset = read_file("unittest.desc.binpb");

    "glaze"_test = [&] {
      TestWellKnownTypes original;
      SetAllFields(&original);

      std::pmr::monotonic_buffer_resource mr;
      std::vector<char> data;
      expect(hpp::proto::write_binpb(original, data).ok());

      auto original_json = gpb_based::binpb_to_json(unittest_descriptorset, "proto2_unittest.TestWellKnownTypes",
                                                    {data.data(), data.size()});
      expect(fatal(!original_json.empty()));

      ::hpp::proto::dynamic_message_factory message_factory;
      expect(message_factory.init(unittest_descriptorset));
      expect(hpp::proto::write_json(original, message_factory).value() == original_json);

      TestWellKnownTypes msg;
      expect(hpp::proto::read_json(msg, original_json, message_factory, hpp::proto::alloc_from{mr}).ok());

      ExpectAllFieldsSet(msg);
    };
  }
};

const boost::ut::suite well_known_types_test = [] {
  "well_known_types"_test = []<class Traits> { WellKnownTypesTests<Traits>::run(); } |
                            std::tuple<hpp::proto::default_traits, pmr_traits, hpp::proto::non_owning_traits>{};
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
