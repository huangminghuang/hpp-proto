#include "google/protobuf/unittest_well_known_types.glz.hpp"
#include "google/protobuf/unittest_well_known_types.pb.hpp"
#include "gpb_proto_json/gpb_proto_json.hpp"
#include "hpp_proto/dynamic_message/json.hpp"
#include "test_util.hpp"
#include <boost/ut.hpp>

using namespace boost::ut;

template <typename Traits>
struct WellKnownTypesTests {
  using string_t = typename Traits::string_t;
  using bytes_t = typename Traits::bytes_t;
  using value_t = typename google::protobuf::Value<Traits>;
  using struct_t = typename google::protobuf::Struct<Traits>;
  using struct_fields_t = decltype(std::declval<struct_t>().fields);
  using any_t = typename google::protobuf::Any<Traits>;
  using field_mask_t = typename google::protobuf::FieldMask<Traits>;
  using duration_t = typename google::protobuf::Duration<Traits>;
  using timestamp_t = typename google::protobuf::Timestamp<Traits>;
  using TestWellKnownTypes = proto2_unittest::TestWellKnownTypes<Traits>;

  std::pmr::monotonic_buffer_resource pool;
  static std::initializer_list<string_t> field_mask_paths_init_list;

  static auto struct_fields_init()
    requires(!std::same_as<Traits, hpp::proto::non_owning_traits>)
  {
    struct_fields_t fields;
    fields.emplace(string_t{"abc"}, value_t{.kind = 1.0});
    return fields;
  }

  static auto struct_fields_init()
    requires(std::same_as<Traits, hpp::proto::non_owning_traits>)
  {
    static value_t v = value_t{.kind = 1.0};
    static auto init_list = std::initializer_list<typename struct_fields_t::value_type>{{string_t{"abc"}, &v}};
    return struct_fields_t{init_list};
  }

  void SetAllFields(TestWellKnownTypes *m) {
    expect(hpp::proto::pack_any(m->any_field.emplace(), field_mask_t{.paths = field_mask_paths_init_list},
                                hpp::proto::alloc_from{pool})
               .ok());

    m->api_field.emplace().name = string_t{"test_api"};
    m->duration_field.emplace() = {.seconds = 1000, .nanos = 100'000'000};
    m->empty_field.emplace();
    m->field_mask_field.emplace().paths = field_mask_paths_init_list;
    m->source_context_field.emplace();
    m->struct_field.emplace().fields = struct_fields_init();
    m->timestamp_field.emplace() = {.seconds = 2000, .nanos = 200000000};
    m->type_field.emplace().name = string_t{"test_type"};

    m->double_field.emplace().value = 3.14;
    m->float_field.emplace().value = 2.718F; // NOLINT
    m->int64_field.emplace().value = 40LL;
    m->uint64_field.emplace().value = 41;
    m->int32_field.emplace().value = 42;
    m->uint32_field.emplace().value = 43;
    m->bool_field.emplace().value = true;
    m->string_field.emplace().value = "abc";
    m->bytes_field.emplace().value = "def"_bytes;
    m->value_field.emplace().kind = string_t{"xyz"};
  }

  void ExpectAllFieldsSet([[maybe_unused]] const TestWellKnownTypes &m) {
    std::pmr::monotonic_buffer_resource mr;
    field_mask_t fm;
    expect(m.any_field.has_value() &&
           hpp::proto::unpack_any(m.any_field.value(), fm, ::hpp::proto::alloc_from(mr)).ok());
    expect(std::ranges::equal(field_mask_paths_init_list, fm.paths));

    expect(m.api_field.has_value() && m.api_field->name == string_t{"test_api"});
    expect(m.duration_field.has_value() && *m.duration_field == duration_t{.seconds = 1000, .nanos = 100000000});
    expect(m.empty_field.has_value());
    expect(m.field_mask_field.has_value() && std::ranges::equal(m.field_mask_field->paths, field_mask_paths_init_list));
    expect(m.struct_field.has_value() && m.struct_field->fields == struct_fields_init());
    expect(m.timestamp_field.has_value() && *m.timestamp_field == timestamp_t{.seconds = 2000, .nanos = 200000000});
    expect(m.type_field.has_value() && m.type_field->name == string_t{"test_type"});

    expect(m.double_field.has_value() && m.double_field->value == 3.14);
    expect(m.float_field.has_value() && m.float_field->value == 2.718F); // NOLINT
    expect(m.int64_field.has_value() && m.int64_field->value == 40LL);
    expect(m.uint64_field.has_value() && m.uint64_field->value == 41ULL);
    expect(m.int32_field.has_value() && m.int32_field->value == 42);
    expect(m.uint32_field.has_value() && m.uint32_field->value == 43);
    expect(m.bool_field.has_value() && m.bool_field->value);
    expect(m.string_field.has_value() && m.string_field->value == string_t{"abc"});
    expect(m.bytes_field.has_value() && m.bytes_field->value == "def"_bytes);
  }

  void run() {
    auto unittest_descriptorset = read_file("unittest.desc.binpb");

    "protobuf"_test = [&] {
      TestWellKnownTypes original;
      SetAllFields(&original);

      TestWellKnownTypes msg;

      std::pmr::monotonic_buffer_resource mr;
      std::vector<std::byte> data;

      expect(hpp::proto::write_binpb(original, data).ok());
      expect(hpp::proto::read_binpb(msg, data, hpp::proto::alloc_from{mr}).ok());

      ExpectAllFieldsSet(msg);
    };

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
      auto my_json = hpp::proto::write_json(original, message_factory).value();
      expect(eq(my_json, original_json));

      TestWellKnownTypes msg;
      expect(hpp::proto::read_json(msg, original_json, message_factory, hpp::proto::alloc_from{mr}).ok());

      ExpectAllFieldsSet(msg);
    };
  }
};

template <typename Traits>
std::initializer_list<typename Traits::string_t> WellKnownTypesTests<Traits>::field_mask_paths_init_list{
    string_t{"/usr/share"}, string_t{"/usr/local/share"}};

const boost::ut::suite well_known_types_test = [] {
  "TestWellKnownTypes"_test = []<class Traits> {
    WellKnownTypesTests<Traits> test;
    test.run();
  } | std::tuple<hpp::proto::default_traits, hpp::proto::pmr_traits, hpp::proto::non_owning_traits>{};
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
