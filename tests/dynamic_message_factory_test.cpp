#include "descriptor_test_corpus.hpp"
#include "test_util.hpp"
#include <array>
#include <boost/ut.hpp>
#include <concepts>
#include <exception>
#include <google/protobuf/descriptor.pb.hpp>
#include <hpp_proto/dynamic_message/binpb.hpp>
#include <hpp_proto/dynamic_message/factory_addons.hpp>
#include <hpp_proto/dynamic_message/json.hpp>
#include <limits>
#include <memory_resource>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace boost::ut;

struct owning_pmr_factory_addons {
  using traits_type = hpp_proto::pmr_traits;
  using string_t = std::pmr::string;
  template <typename T>
  using vector_t = std::pmr::vector<T>;
  template <typename K, typename V>
  using map_t = std::pmr::unordered_map<K, V>;

  template <typename Derived>
  struct field_descriptor {
    field_descriptor([[maybe_unused]] Derived &derived, [[maybe_unused]] const auto &options,
                     [[maybe_unused]] std::pmr::memory_resource *resource) {}
  };
  template <typename Derived>
  struct enum_descriptor {
    enum_descriptor([[maybe_unused]] Derived &derived, [[maybe_unused]] const auto &options,
                    [[maybe_unused]] std::pmr::memory_resource *resource) {}
  };
  template <typename Derived>
  struct oneof_descriptor {
    oneof_descriptor([[maybe_unused]] Derived &derived, [[maybe_unused]] const auto &options,
                     [[maybe_unused]] std::pmr::memory_resource *resource) {}
  };
  template <typename Derived>
  struct message_descriptor {
    message_descriptor([[maybe_unused]] Derived &derived, [[maybe_unused]] const auto &options,
                       [[maybe_unused]] std::pmr::memory_resource *resource) {}
  };
  template <typename Derived>
  struct file_descriptor {
    // NOLINTNEXTLINE(bugprone-crtp-constructor-accessibility)
    file_descriptor([[maybe_unused]] Derived &derived, [[maybe_unused]] std::pmr::memory_resource *resource) {}
  };
};

template <typename T>
concept factory_creatable_from =
    requires(T &&value) { hpp_proto::dynamic_message_factory::create(std::forward<T>(value)); };

using non_owning_file_descriptor_set = google::protobuf::FileDescriptorSet<hpp_proto::non_owning_traits>;
static_assert(!factory_creatable_from<non_owning_file_descriptor_set>);

template <typename Pool>
concept publicly_initializable_descriptor_pool =
    requires(Pool &pool, Pool::FileDescriptorSet &&fileset) { pool.init(std::move(fileset)); };

using owning_pmr_descriptor_pool = hpp_proto::descriptor_pool<owning_pmr_factory_addons>;
static_assert(!publicly_initializable_descriptor_pool<owning_pmr_descriptor_pool>);

template <typename AddOns>
class internal_descriptor_pool : public hpp_proto::descriptor_pool<AddOns> {
  using base_type = hpp_proto::descriptor_pool<AddOns>;

public:
  using base_type::base_type;

  [[nodiscard]] std::expected<void, hpp_proto::descriptor_pool_errc> init(base_type::FileDescriptorSet &&fileset) {
    return base_type::init(std::move(fileset));
  }
};

template <typename Traits = hpp_proto::default_traits>
struct test_feature_extension
    : hpp_proto::extension_base<test_feature_extension<Traits>, google::protobuf::FeatureSet> {
  static constexpr std::uint32_t field_number = 123;
  std::int32_t value = 0;
  using pb_meta = std::tuple<hpp_proto::field_meta<field_number, &test_feature_extension::value,
                                                   hpp_proto::field_option::none, hpp_proto::vint64_t>>;
};

struct test_feature_message {
  std::int32_t parent_value = 0;
  std::int32_t child_value = 0;
  using pb_meta = std::tuple<
      hpp_proto::field_meta<1, &test_feature_message::parent_value, hpp_proto::field_option::none, hpp_proto::vint64_t>,
      hpp_proto::field_meta<2, &test_feature_message::child_value, hpp_proto::field_option::none, hpp_proto::vint64_t>>;
};

template <typename Traits = hpp_proto::default_traits>
struct test_message_feature_extension
    : hpp_proto::extension_base<test_message_feature_extension<Traits>, google::protobuf::FeatureSet> {
  static constexpr std::uint32_t field_number = 124;
  test_feature_message value;
  using pb_meta = std::tuple<hpp_proto::field_meta<field_number, &test_message_feature_extension::value>>;
};

struct test_repeated_feature_message {
  std::vector<std::int32_t> values;
  using pb_meta = std::tuple<hpp_proto::field_meta<1, &test_repeated_feature_message::values,
                                                   hpp_proto::field_option::none, hpp_proto::vint64_t>>;
};

template <typename Traits = hpp_proto::default_traits>
struct test_repeated_message_feature_extension
    : hpp_proto::extension_base<test_repeated_message_feature_extension<Traits>, google::protobuf::FeatureSet> {
  static constexpr std::uint32_t field_number = 125;
  test_repeated_feature_message value;
  using pb_meta = std::tuple<hpp_proto::field_meta<field_number, &test_repeated_message_feature_extension::value>>;
};

class throwing_memory_resource final : public std::pmr::memory_resource {
private:
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  void *do_allocate([[maybe_unused]] std::size_t bytes, [[maybe_unused]] std::size_t alignment) override {
    throw std::bad_alloc{};
  }
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  void do_deallocate([[maybe_unused]] void *pointer, [[maybe_unused]] std::size_t bytes,
                     [[maybe_unused]] std::size_t alignment) override {}
  [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override {
    return this == &other;
  }
};

class tracking_memory_resource final : public std::pmr::memory_resource {
public:
  [[nodiscard]] std::size_t allocations() const noexcept { return allocations_; }

private:
  void *do_allocate(std::size_t bytes, std::size_t alignment) override {
    ++allocations_;
    return std::pmr::new_delete_resource()->allocate(bytes, alignment);
  }
  void do_deallocate(void *pointer, std::size_t bytes, std::size_t alignment) override {
    std::pmr::new_delete_resource()->deallocate(pointer, bytes, alignment);
  }
  [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override {
    return this == &other;
  }

  std::size_t allocations_ = 0;
};

class default_resource_scope {
public:
  explicit default_resource_scope(std::pmr::memory_resource *resource)
      : previous_(std::pmr::set_default_resource(resource)) {}
  ~default_resource_scope() { std::pmr::set_default_resource(previous_); }
  default_resource_scope(const default_resource_scope &) = delete;
  default_resource_scope(default_resource_scope &&) = delete;
  default_resource_scope &operator=(const default_resource_scope &) = delete;
  default_resource_scope &operator=(default_resource_scope &&) = delete;

private:
  std::pmr::memory_resource *previous_;
};

// Dynamic descriptor factory tests use protobuf boundary and validation fixture literals inline.
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,misc-const-correctness)

template <typename Exp>
decltype(auto) expect_ok(Exp &&exp) {
  if (!exp.has_value()) {
    expect(fatal(false)); // LCOV_EXCL_LINE: a passing test cannot exercise this assertion failure.
    std::terminate();     // LCOV_EXCL_LINE: keep unchecked expected access impossible after the failure.
  }
  return std::forward<Exp>(exp).value();
}

#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)
constexpr bool msvc_asan_bad_alloc_failpoint_unstable = true;
#else
constexpr bool msvc_asan_bad_alloc_failpoint_unstable = false;
#endif

const boost::ut::suite parse_default_value_tests = [] {
  "parse_default_value_success"_test = [] {
    expect(eq(*hpp_proto::dynamic_message_factory_addons::parse_default_value<int32_t>("123"), 123));
    expect(eq(*hpp_proto::dynamic_message_factory_addons::parse_default_value<uint64_t>(
                  std::to_string(std::numeric_limits<uint64_t>::max())),
              std::numeric_limits<uint64_t>::max()));
    expect(eq(*hpp_proto::dynamic_message_factory_addons::parse_default_value<float>("1.5"), 1.5F));
    expect(eq(*hpp_proto::dynamic_message_factory_addons::parse_default_value<double>("-2.5"), -2.5));
    expect(eq(*hpp_proto::dynamic_message_factory_addons::parse_default_value<int32_t>(""),
              0)); // empty defaults to zero-initialized
  };

  "parse_default_value_errors"_test = [] {
    expect(eq(hpp_proto::dynamic_message_factory_addons::parse_default_value<int32_t>("abc").error(),
              std::errc::invalid_argument));
    expect(eq(hpp_proto::dynamic_message_factory_addons::parse_default_value<int32_t>("999999999999").error(),
              std::errc::result_out_of_range));
    expect(eq(hpp_proto::dynamic_message_factory_addons::parse_default_value<double>("1e400").error(),
              std::errc::result_out_of_range));
  };
};

// Intentionally broad integration-style suite with many scenario builders/tests.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
const boost::ut::suite descriptor_pool_gap_tests = [] {
  using OwningFileDescriptorProto = descriptor_test_corpus::file_descriptor;
  using OwningFileDescriptorSet = descriptor_test_corpus::file_descriptor_set;
  using MessageProto = descriptor_test_corpus::message_descriptor;
  using FieldProto = descriptor_test_corpus::field_descriptor;
  using OneofProto = descriptor_test_corpus::oneof_descriptor;
  using EnumProto = descriptor_test_corpus::enum_descriptor;
  using EnumValueProto = descriptor_test_corpus::enum_value_descriptor;
  using enum google::protobuf::FieldDescriptorProto_::Label;
  using enum google::protobuf::FieldDescriptorProto_::Type;

  auto make_descriptor_set_binpb = [&](const OwningFileDescriptorSet &file_set) {
    std::string buffer;
    expect(hpp_proto::write_binpb(file_set, buffer).ok());
    return buffer;
  };

  auto make_descriptor_set_binpb_one = [&](const OwningFileDescriptorProto &proto) {
    OwningFileDescriptorSet file_set{.file = {proto}};
    return make_descriptor_set_binpb(file_set);
  };

  auto make_unsupported_edition_descriptor_set = [] {
    auto descriptor_set = descriptor_test_corpus::editions_2023();
    descriptor_test_corpus::only_file(descriptor_set).edition = static_cast<google::protobuf::Edition>(0x7fffffff);
    return descriptor_set;
  };

  auto make_large_descriptor_collection_fileset = [](std::size_t file_count) {
    std::vector<OwningFileDescriptorProto> files;
    files.reserve(file_count);
    for (std::size_t i = 0; i < file_count; ++i) {
      files.push_back(OwningFileDescriptorProto{
          .name = "bulk_" + std::to_string(i) + ".proto",
          .package = "bulk.pkg",
          .message_type =
              {
                  MessageProto{
                      .name = "M" + std::to_string(i),
                      .field =
                          {
                              FieldProto{
                                  .name = "f",
                                  .number = 1,
                                  .label = LABEL_OPTIONAL,
                                  .type = TYPE_INT32,
                              },
                          },
                  },
              },
      });
    }
    return files;
  };

  auto make_large_field_message_fileset = [](std::size_t field_count) {
    MessageProto root{.name = "Root"};
    root.field.reserve(field_count);
    for (std::size_t i = 0; i < field_count; ++i) {
      const auto field_number = i + 1U;
      const auto valid_field_number = field_number >= 19'000U ? field_number + 1'000U : field_number;
      root.field.push_back(FieldProto{
          .name = "field_" + std::to_string(i),
          .number = static_cast<int32_t>(valid_field_number),
          .label = LABEL_OPTIONAL,
          .type = TYPE_INT32,
          .json_name = "customField" + std::to_string(i),
      });
    }
    return OwningFileDescriptorProto{
        .name = "large_field_message.proto",
        .message_type = {std::move(root)},
    };
  };

  auto make_large_enum_default_fileset = [](std::size_t value_count, std::size_t field_count) {
    EnumProto enumeration{.name = "LargeEnum"};
    enumeration.value.reserve(value_count);
    for (std::size_t i = 0; i < value_count; ++i) {
      enumeration.value.push_back(EnumValueProto{
          .name = "VALUE_" + std::to_string(i),
          .number = static_cast<int32_t>(i),
      });
    }

    MessageProto root{.name = "Root", .enum_type = {std::move(enumeration)}};
    root.field.reserve(field_count);
    for (std::size_t i = 0; i < field_count; ++i) {
      root.field.push_back(FieldProto{
          .name = "field_" + std::to_string(i),
          .number = static_cast<int32_t>(i + 1),
          .label = LABEL_OPTIONAL,
          .type = TYPE_ENUM,
          .type_name = ".Root.LargeEnum",
          .default_value = "VALUE_" + std::to_string(value_count - 1),
      });
    }
    return OwningFileDescriptorProto{
        .name = "large_enum_default.proto",
        .message_type = {std::move(root)},
    };
  };

  auto make_long_dependency_chain_fileset = [](std::size_t file_count) {
    std::vector<OwningFileDescriptorProto> files;
    files.reserve(file_count);
    for (std::size_t i = 0; i < file_count; ++i) {
      OwningFileDescriptorProto file{.name = "chain_" + std::to_string(i) + ".proto"};
      if (i != 0) {
        file.dependency.push_back("chain_" + std::to_string(i - 1) + ".proto");
      }
      files.push_back(std::move(file));
    }
    return files;
  };

  auto make_deep_name_and_dependency_pressure_fileset = [] {
    std::vector<OwningFileDescriptorProto> files;
    constexpr int dep_count = 96;
    files.reserve(static_cast<std::size_t>(dep_count) + 1);

    for (int i = 0; i < dep_count; ++i) {
      files.push_back(OwningFileDescriptorProto{
          .name = "dep_" + std::to_string(i) + ".proto",
          .package = "deps.pkg",
          .message_type =
              {
                  MessageProto{
                      .name = "D" + std::to_string(i),
                  },
              },
      });
    }

    std::string long_package;
    for (int i = 0; i < 64; ++i) {
      if (!long_package.empty()) {
        long_package += '.';
      }
      long_package += "segment_" + std::to_string(i);
    }

    OwningFileDescriptorProto root{
        .name = "root_pressure.proto",
        .package = long_package,
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "child",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_MESSAGE,
                                .type_name = "." + long_package + ".Root.Inner",
                            },
                        },
                    .nested_type =
                        {
                            MessageProto{.name = "Inner"},
                        },
                },
            },
    };
    root.dependency.reserve(dep_count);
    for (int i = 0; i < dep_count; ++i) {
      root.dependency.push_back("dep_" + std::to_string(i) + ".proto");
    }
    files.push_back(std::move(root));
    return files;
  };

  auto make_interleaved_oneof_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "interleaved_oneof.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "a",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                                .oneof_index = 0,
                                .json_name = "a",
                            },
                            FieldProto{
                                .name = "x",
                                .number = 2,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                                .json_name = "x",
                            },
                            FieldProto{
                                .name = "b",
                                .number = 3,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                                .oneof_index = 0,
                                .json_name = "b",
                            },
                        },
                    .oneof_decl =
                        {
                            OneofProto{.name = "choice"},
                        },
                },
            },
    };
  };

  auto make_two_oneofs_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "two_oneofs.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "a1",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                                .oneof_index = 0,
                            },
                            FieldProto{
                                .name = "a2",
                                .number = 2,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                                .oneof_index = 0,
                            },
                            FieldProto{
                                .name = "b1",
                                .number = 3,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                                .oneof_index = 1,
                            },
                            FieldProto{
                                .name = "b2",
                                .number = 4,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                                .oneof_index = 1,
                            },
                        },
                    .oneof_decl =
                        {
                            OneofProto{.name = "choice_a"},
                            OneofProto{.name = "choice_b"},
                        },
                },
            },
    };
  };

  auto make_oneof_ordinal_overflow_fileset = [] {
    OwningFileDescriptorProto file{
        .name = "oneof_ordinal_overflow.proto",
    };
    MessageProto message{
        .name = "Root",
        .oneof_decl =
            {
                OneofProto{.name = "choice"},
            },
    };
    const auto limit = static_cast<std::size_t>(std::numeric_limits<uint16_t>::max());
    message.field.reserve(limit);
    int32_t field_number = 1;
    while (message.field.size() < limit) {
      if (field_number == 19'000) {
        field_number = 20'000;
      }
      message.field.push_back(FieldProto{
          .name = "f" + std::to_string(field_number),
          .number = field_number,
          .label = LABEL_OPTIONAL,
          .type = TYPE_INT32,
          .oneof_index = 0,
      });
      ++field_number;
    }
    file.message_type.push_back(std::move(message));
    return file;
  };

  auto expect_valid_descriptor_set = [&](const OwningFileDescriptorSet &descriptor_set) {
    expect(hpp_proto::dynamic_message_factory::create(make_descriptor_set_binpb(descriptor_set)).has_value());
  };

  auto expect_schema_validation_error = [&](const OwningFileDescriptorSet &descriptor_set) {
    auto factory = hpp_proto::dynamic_message_factory::create(make_descriptor_set_binpb(descriptor_set));
    expect(fatal(!factory.has_value()));
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::schema_validation_error));
  };

  "scalar_field_descriptor_seed_is_valid"_test = [&] {
    expect_valid_descriptor_set(descriptor_test_corpus::scalar_field());
  };

  "referenced_types_descriptor_seed_is_valid"_test = [&] {
    expect_valid_descriptor_set(descriptor_test_corpus::referenced_types());
  };

  "oneof_descriptor_seed_is_valid"_test = [&] { expect_valid_descriptor_set(descriptor_test_corpus::oneof()); };

  "extensions_descriptor_seed_is_valid"_test = [&] {
    expect_valid_descriptor_set(descriptor_test_corpus::extensions());
  };

  "dependency_graph_descriptor_seed_is_valid"_test = [&] {
    expect_valid_descriptor_set(descriptor_test_corpus::dependency_graph());
  };

  "editions_descriptor_seed_is_valid"_test = [&] {
    expect_valid_descriptor_set(descriptor_test_corpus::editions_2023());
  };

  "unsupported_edition_sets_error"_test = [&] {
    expect_schema_validation_error(make_unsupported_edition_descriptor_set());
  };

  "edition_file_feature_overrides_are_merged_into_runtime_descriptors"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::editions_2023();
    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(make_descriptor_set_binpb(descriptor_set)));

    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = expect_ok(factory.get_message("descriptor_corpus.editions.Root", memory_resource));

    const auto *numbers = msg.field_descriptor_by_name("numbers");
    const auto *scalar = msg.field_descriptor_by_name("scalar");
    const auto *child = msg.field_descriptor_by_name("child");
    const auto *legacy_required_scalar = msg.field_descriptor_by_name("legacy_required_scalar");

    expect(numbers != nullptr);
    expect(scalar != nullptr);
    expect(child != nullptr);
    expect(legacy_required_scalar != nullptr);

    // File-level editions feature overrides should change descriptor behavior from 2023 defaults:
    // PACKED -> EXPANDED, EXPLICIT presence -> IMPLICIT, LENGTH_PREFIXED -> DELIMITED.
    expect(!numbers->is_packed());
    expect(!scalar->explicit_presence());
    expect(child->is_delimited());
    expect(!numbers->resolved_info().is_packed());
    expect(numbers->resolved_info().presence() == hpp_proto::field_presence_t::REPEATED);
    expect(!scalar->resolved_info().explicit_presence());
    expect(scalar->resolved_info().presence() == hpp_proto::field_presence_t::IMPLICIT);
    expect(child->resolved_info().is_delimited());
    expect(legacy_required_scalar->resolved_info().presence() == hpp_proto::field_presence_t::REQUIRED);
    expect(legacy_required_scalar->resolved_info().explicit_presence());

    const std::string encoded_default{"\x20\x00", 2};
    expect(hpp_proto::read_binpb(msg, encoded_default).ok());
    expect(expect_ok(msg.field_by_name("legacy_required_scalar")).has_value());
    std::string roundtrip;
    expect(hpp_proto::write_binpb(msg.cref(), roundtrip).ok());
    expect(eq(roundtrip, encoded_default));
  };

  "edition_file_feature_extensions_are_merged_once"_test = [&] {
    constexpr auto field_number = test_repeated_message_feature_extension<>::field_number;
    auto descriptor_set = descriptor_test_corpus::editions_2023();
    auto &proto = descriptor_test_corpus::only_file(descriptor_set);
    proto.options->features->unknown_fields_.fields.emplace(
        field_number, std::vector<std::byte>{std::byte{0xea}, std::byte{0x07}, std::byte{0x04}, std::byte{0x08},
                                             std::byte{0x07}, std::byte{0x08}, std::byte{0x0b}});

    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(make_descriptor_set_binpb(descriptor_set)));
    std::pmr::monotonic_buffer_resource memory_resource;
    auto message = expect_ok(factory.get_message("descriptor_corpus.editions.Root", memory_resource));
    test_repeated_message_feature_extension<> extension;

    expect(message.descriptor().parent_file()->options().features->get_extension(extension).ok());
    expect(fatal(eq(extension.value.values.size(), std::size_t{2})));
    expect(eq(extension.value.values[0], std::int32_t{7}));
    expect(eq(extension.value.values[1], std::int32_t{11}));
  };

  "missing_message_type_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::referenced_types();
    descriptor_test_corpus::root_field(descriptor_set).type_name = ".descriptor_corpus.Missing";
    expect_schema_validation_error(descriptor_set);
  };

  "missing_enum_type_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::referenced_types();
    descriptor_test_corpus::root_field(descriptor_set, 1).type_name = ".descriptor_corpus.MissingEnum";
    expect_schema_validation_error(descriptor_set);
  };

  "empty_field_type_name_sets_error"_test = [&] {
    for (const auto field_index : {std::size_t{0}, std::size_t{1}}) {
      auto descriptor_set = descriptor_test_corpus::referenced_types();
      descriptor_test_corpus::root_field(descriptor_set, field_index).type_name.clear();
      expect_schema_validation_error(descriptor_set);
    }
  };

  "invalid_field_type_returns_schema_validation_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    // Deliberately construct an invalid descriptor enum value.
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    descriptor_test_corpus::root_field(descriptor_set).type = static_cast<FieldProto::Type>(19);
    expect_schema_validation_error(descriptor_set);
  };

  "invalid_field_label_returns_schema_validation_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    // Deliberately construct an invalid descriptor enum value.
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    descriptor_test_corpus::root_field(descriptor_set).label = static_cast<FieldProto::Label>(4);
    expect_schema_validation_error(descriptor_set);
  };

  "invalid_file_extension_type_returns_schema_validation_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::extensions();
    auto &extension = descriptor_test_corpus::only_file(descriptor_set).extension.front();
    // Deliberately construct an invalid descriptor enum value.
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    extension.type = static_cast<FieldProto::Type>(19);
    expect_schema_validation_error(descriptor_set);
  };

  "invalid_message_extension_label_returns_schema_validation_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::extensions();
    auto &extension = descriptor_test_corpus::only_file(descriptor_set).message_type[1].extension.front();
    // Deliberately construct an invalid descriptor enum value.
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    extension.label = static_cast<FieldProto::Label>(4);
    expect_schema_validation_error(descriptor_set);
  };

  "duplicate_field_number_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    auto &root = descriptor_test_corpus::root_message(descriptor_set);
    root.field.push_back(FieldProto{
        .name = "other",
        .number = root.field.front().number,
        .label = LABEL_OPTIONAL,
        .type = TYPE_STRING,
        .json_name = "other",
    });
    expect_schema_validation_error(descriptor_set);
  };

  "json_name_proto_name_conflict_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    auto &root = descriptor_test_corpus::root_message(descriptor_set);
    root.field.push_back(FieldProto{
        .name = "other",
        .number = 2,
        .label = LABEL_OPTIONAL,
        .type = TYPE_STRING,
        .json_name = "otherValue",
    });
    expect_valid_descriptor_set(descriptor_set);
    root.field.front().json_name = "other";
    expect_schema_validation_error(descriptor_set);
  };

  "empty_json_name_is_allowed"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    descriptor_test_corpus::root_field(descriptor_set).json_name.clear();
    expect_valid_descriptor_set(descriptor_set);
  };

  "field_number_boundaries_are_validated"_test = [&] {
    struct field_number_case {
      std::int32_t number;
      bool valid;
    };
    constexpr std::array cases{
        field_number_case{.number = 0, .valid = false},           field_number_case{.number = 1, .valid = true},
        field_number_case{.number = 18'999, .valid = true},       field_number_case{.number = 19'000, .valid = false},
        field_number_case{.number = 19'999, .valid = false},      field_number_case{.number = 20'000, .valid = true},
        field_number_case{.number = 536'870'912, .valid = false},
    };

    for (const auto &test_case : cases) {
      auto descriptor_set = descriptor_test_corpus::scalar_field();
      descriptor_test_corpus::root_field(descriptor_set).number = test_case.number;
      if (test_case.valid) {
        expect_valid_descriptor_set(descriptor_set);
      } else {
        expect_schema_validation_error(descriptor_set);
      }
    }
  };

  "field_number_536870911_is_valid_max"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    descriptor_test_corpus::root_field(descriptor_set).number = 536'870'911;
    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(make_descriptor_set_binpb(descriptor_set)));

    std::pmr::monotonic_buffer_resource write_resource;
    auto message = expect_ok(factory.get_message("descriptor_corpus.Root", write_resource));
    expect(expect_ok(message.field_by_name("value")).set(std::int32_t{1}).has_value());

    std::string encoded;
    expect(hpp_proto::write_binpb(message.cref(), encoded).ok());
    const std::string expected{"\xf8\xff\xff\xff\x0f\x01", 6};
    expect(eq(encoded, expected));

    std::pmr::monotonic_buffer_resource read_resource;
    auto decoded = expect_ok(factory.get_message("descriptor_corpus.Root", read_resource));
    expect(hpp_proto::read_binpb(decoded, encoded).ok());
    expect(eq(expect_ok(decoded.field_value_by_name<std::int32_t>("value")), std::int32_t{1}));
  };

  "large_descriptor_collection_factory_init_succeeds"_test = [&] {
    auto files = make_large_descriptor_collection_fileset(256);
    OwningFileDescriptorSet file_set;
    file_set.file = std::move(files);
    expect_valid_descriptor_set(file_set);
  };

  "large_field_message_factory_init_succeeds"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_large_field_message_fileset(4096));
    expect(hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "large_enum_defaults_factory_init_succeeds"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_large_enum_default_fileset(4096, 4096));
    expect(hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "trusted_serialized_descriptors_are_not_size_limited"_test = [&] {
    constexpr std::size_t previous_serialized_limit = std::size_t{16} * 1024U * 1024U;
    auto file = OwningFileDescriptorProto{
        .name = "large_trusted_descriptor.proto",
        .package = std::string(previous_serialized_limit, 'a'),
    };

    std::string file_descriptor;
    expect(hpp_proto::write_binpb(file, file_descriptor).ok());
    expect(gt(file_descriptor.size(), previous_serialized_limit));
    hpp_proto::distinct_file_descriptor_pb_array descriptors = {hpp_proto::file_descriptor_pb{file_descriptor}};
    expect(hpp_proto::dynamic_message_factory::create(descriptors).has_value());

    auto descriptor_set = make_descriptor_set_binpb_one(file);
    expect(gt(descriptor_set.size(), previous_serialized_limit));
    expect(hpp_proto::dynamic_message_factory::create(descriptor_set).has_value());
  };

  "long_dependency_chain_factory_init_succeeds"_test = [&] {
    OwningFileDescriptorSet file_set;
    file_set.file = make_long_dependency_chain_fileset(8192);
    expect_valid_descriptor_set(file_set);
  };

  "deep_name_and_dependency_pressure_factory_init_succeeds"_test = [&] {
    OwningFileDescriptorSet file_set;
    file_set.file = make_deep_name_and_dependency_pressure_fileset();
    expect_valid_descriptor_set(file_set);
  };

  "factory_create_truncation_and_length_mismatch_binpb_returns_descriptor_deserialization_error"_test = [&] {
    auto valid_desc_binpb = make_descriptor_set_binpb_one(make_two_oneofs_fileset());
    expect(valid_desc_binpb.size() > 2U);

    std::array<std::string, 4> malformed_cases = {
        valid_desc_binpb.substr(0, valid_desc_binpb.size() - 1),
        valid_desc_binpb.substr(0, 2),
        std::string{"\x0A\x05\x08\x96\x01", 5},
        std::string{"\x0A\x80\x80\x80\x80\x80\x80\x80\x80\x80\x02", 11},
    };

    for (const auto &malformed : malformed_cases) {
      auto factory = hpp_proto::dynamic_message_factory::create(malformed);
      expect(!factory.has_value());
      expect(eq(factory.error(), hpp_proto::dynamic_message_errc::descriptor_deserialization_error));
    }
  };

  "invalid_oneof_index_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::oneof();
    descriptor_test_corpus::root_field(descriptor_set).oneof_index = 1;
    expect_schema_validation_error(descriptor_set);
  };

  "repeated_oneof_field_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::oneof();
    descriptor_test_corpus::root_field(descriptor_set).label = LABEL_REPEATED;
    expect_schema_validation_error(descriptor_set);
  };

  "empty_oneof_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::oneof();
    descriptor_test_corpus::root_message(descriptor_set).field.clear();
    expect_schema_validation_error(descriptor_set);
  };

  "missing_extendee_type_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::extensions();
    descriptor_test_corpus::only_file(descriptor_set).extension.front().extendee = ".descriptor_corpus.MissingExtendee";
    expect_schema_validation_error(descriptor_set);
  };

  "invalid_extension_field_number_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::extensions();
    descriptor_test_corpus::only_file(descriptor_set).extension.front().number = 19'000;
    expect_schema_validation_error(descriptor_set);
  };

  "invalid_message_extension_field_number_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::extensions();
    descriptor_test_corpus::only_file(descriptor_set).message_type[1].extension.front().number = 19'000;
    expect_schema_validation_error(descriptor_set);
  };

  "missing_file_dependency_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::dependency_graph();
    descriptor_set.file.back().dependency.front() = "missing.proto";
    expect_schema_validation_error(descriptor_set);
  };

  "empty_file_name_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    descriptor_test_corpus::only_file(descriptor_set).name.clear();
    expect_schema_validation_error(descriptor_set);
  };

  "empty_message_name_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    descriptor_test_corpus::root_message(descriptor_set).name.clear();
    expect_schema_validation_error(descriptor_set);
  };

  "empty_nested_message_name_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::referenced_types();
    descriptor_test_corpus::root_message(descriptor_set).nested_type.front().name.clear();
    expect_schema_validation_error(descriptor_set);
  };

  "invalid_deeply_nested_message_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::referenced_types();
    auto &nested = descriptor_test_corpus::root_message(descriptor_set).nested_type.front();
    nested.nested_type.push_back(MessageProto{.name = ""});
    expect_schema_validation_error(descriptor_set);
  };

  "empty_enum_name_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    descriptor_test_corpus::only_file(descriptor_set)
        .enum_type.push_back(EnumProto{.name = "", .value = {EnumValueProto{.name = "ZERO", .number = 0}}});
    expect_schema_validation_error(descriptor_set);
  };

  "empty_nested_enum_name_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::scalar_field();
    descriptor_test_corpus::root_message(descriptor_set)
        .enum_type.push_back(EnumProto{.name = "", .value = {EnumValueProto{.name = "ZERO", .number = 0}}});
    expect_schema_validation_error(descriptor_set);
  };

  "duplicate_file_name_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::dependency_graph();
    descriptor_set.file.pop_back();
    descriptor_set.file[1].dependency.clear();
    expect_valid_descriptor_set(descriptor_set);
    descriptor_set.file[1].name = descriptor_set.file[0].name;
    expect_schema_validation_error(descriptor_set);
  };

  "duplicate_message_full_name_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::dependency_graph();
    descriptor_set.file[1].message_type.front().name = descriptor_set.file[0].message_type.front().name;
    expect_schema_validation_error(descriptor_set);
  };

  "duplicate_enum_full_name_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::dependency_graph();
    descriptor_set.file[1].enum_type.front().name = descriptor_set.file[0].enum_type.front().name;
    expect_schema_validation_error(descriptor_set);
  };

  "direct_dependency_cycle_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::dependency_graph();
    descriptor_set.file[0].dependency.push_back(descriptor_set.file[1].name);
    expect_schema_validation_error(descriptor_set);
  };

  "transitive_dependency_cycle_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::dependency_graph();
    descriptor_set.file[0].dependency.push_back(descriptor_set.file[2].name);
    expect_schema_validation_error(descriptor_set);
  };

  "duplicate_nested_enum_full_name_sets_error"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::referenced_types();
    auto &enums = descriptor_test_corpus::root_message(descriptor_set).enum_type;
    enums.push_back(enums.front());
    expect_schema_validation_error(descriptor_set);
  };

  "invalid_enum_default_name_factory_init_fails"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::referenced_types();
    descriptor_test_corpus::root_field(descriptor_set, 1).default_value = "DOES_NOT_EXIST";
    expect_schema_validation_error(descriptor_set);
  };

  "required_enum_uses_first_value_as_implicit_default"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::referenced_types();
    auto &enum_field = descriptor_test_corpus::root_field(descriptor_set, 1);
    enum_field.label = LABEL_REQUIRED;
    enum_field.default_value.clear();
    auto &values = descriptor_test_corpus::only_file(descriptor_set).enum_type.front().value;
    values[0] = EnumValueProto{.name = "FIRST", .number = 7};
    values[1] = EnumValueProto{.name = "SECOND", .number = 8};

    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(make_descriptor_set_binpb(descriptor_set)));
    std::pmr::monotonic_buffer_resource memory_resource;
    auto message = expect_ok(factory.get_message("descriptor_corpus.Root", memory_resource));
    auto field = expect_ok(message.field_by_name("choice"));
    auto typed_field = expect_ok(field.to<hpp_proto::enum_field_mref>());
    expect(eq(typed_field.default_value().number(), std::int32_t{7}));
    expect(eq(typed_field.value().number(), std::int32_t{7}));
    expect(typed_field.descriptor().resolved_info().presence() == hpp_proto::field_presence_t::REQUIRED);

    const std::string encoded_default{"\x10\x07", 2};
    expect(hpp_proto::read_binpb(message, encoded_default).ok());
    expect(typed_field.has_value());
    std::string roundtrip;
    expect(hpp_proto::write_binpb(message.cref(), roundtrip).ok());
    expect(eq(roundtrip, encoded_default));
  };

  "invalid_numeric_defaults_return_schema_validation_error"_test = [&] {
    struct invalid_default_case {
      FieldProto::Type type;
      std::string_view default_value;
    };
    constexpr std::array cases{
        invalid_default_case{.type = TYPE_INT32, .default_value = "not-an-integer"},
        invalid_default_case{.type = TYPE_INT32, .default_value = "999999999999"},
        invalid_default_case{.type = TYPE_DOUBLE, .default_value = "1e400"},
    };

    for (const auto &test_case : cases) {
      auto descriptor_set = descriptor_test_corpus::scalar_field();
      auto &field = descriptor_test_corpus::root_field(descriptor_set);
      field.type = test_case.type;
      field.default_value = test_case.default_value;
      expect_schema_validation_error(descriptor_set);
    }
  };

  "empty_enum_factory_init_fails"_test = [&] {
    auto descriptor_set = descriptor_test_corpus::referenced_types();
    descriptor_test_corpus::only_file(descriptor_set).enum_type.front().value.clear();
    expect_schema_validation_error(descriptor_set);
  };

  "pmr_default_resource_restored_on_error"_test = [&] {
    auto *old_resource = std::pmr::get_default_resource();
    auto invalid_descriptor_set = make_unsupported_edition_descriptor_set();
    auto desc_binpb = make_descriptor_set_binpb(invalid_descriptor_set);
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());

    auto *current_resource = std::pmr::get_default_resource();
    if (current_resource != old_resource) {
      std::pmr::set_default_resource(old_resource);
    }
    expect(current_resource == old_resource);
  };

  "factory_creation_does_not_use_global_default_resource"_test = [&] {
    throwing_memory_resource throwing_resource;

    auto descriptor_set = make_descriptor_set_binpb_one(make_two_oneofs_fileset());
    std::pmr::monotonic_buffer_resource parse_resource;
    auto fileset = expect_ok(hpp_proto::read_binpb<google::protobuf::FileDescriptorSet<hpp_proto::non_owning_traits>>(
        descriptor_set, hpp_proto::alloc_from(parse_resource)));
    std::string file_descriptor;
    expect(hpp_proto::write_binpb(fileset.file.front(), file_descriptor).ok());
    hpp_proto::distinct_file_descriptor_pb_array descriptors = {hpp_proto::file_descriptor_pb{file_descriptor}};

    std::pmr::unsynchronized_pool_resource upstream;
    const auto allocator = hpp_proto::dynamic_message_factory::allocator_type{&upstream};
    default_resource_scope guard{&throwing_resource};
    expect(hpp_proto::dynamic_message_factory::create(descriptor_set, allocator).has_value());
    expect(hpp_proto::dynamic_message_factory::create(descriptors, allocator).has_value());
  };

  "owning_pmr_descriptor_pool_merges_feature_extensions_without_global_allocations"_test = [&] {
    auto make_option = [] {
      return google::protobuf::UninterpretedOption<>{
          .name = {{.name_part = "allocator_sensitive_option_name", .is_extension = false}},
          .identifier_value = "allocator_sensitive_option_value",
      };
    };
    auto make_extension = [](std::byte payload) {
      std::vector<std::byte> result = {std::byte{0xda}, std::byte{0x07}, std::byte{0x40}};
      result.resize(result.size() + 64U, payload);
      return result;
    };
    auto proto = make_two_oneofs_fileset();
    proto.options.emplace().uninterpreted_option.push_back(make_option());
    proto.options->unknown_fields_.fields.emplace(123U, make_extension(std::byte{0x5a}));
    proto.options->features.emplace().unknown_fields_.fields.emplace(123U, make_extension(std::byte{0x5a}));
    auto &message = proto.message_type.front();
    message.options.emplace().uninterpreted_option.push_back(make_option());
    message.options->features.emplace().unknown_fields_.fields.emplace(123U, make_extension(std::byte{0x6b}));
    message.field.front().options.emplace().uninterpreted_option.push_back(make_option());
    message.oneof_decl.front().options.emplace().uninterpreted_option.push_back(make_option());
    message.enum_type.push_back(EnumProto{
        .name = "AllocatorSensitiveEnum",
        .value = {{.name = "ZERO", .number = 0}},
        .options = google::protobuf::EnumOptions<>{.uninterpreted_option = {make_option()}},
    });
    auto descriptor_set = make_descriptor_set_binpb_one(proto);
    std::pmr::monotonic_buffer_resource resource;
    using pool_type = internal_descriptor_pool<owning_pmr_factory_addons>;
    auto fileset =
        expect_ok(hpp_proto::read_binpb<pool_type::FileDescriptorSet>(descriptor_set, hpp_proto::alloc_from(resource)));

    tracking_memory_resource tracking_resource;
    default_resource_scope guard{&tracking_resource};
    pool_type pool{&resource};
    expect(pool.init(std::move(fileset)).has_value());
    const auto &feature_extensions = pool.files().front().options().features->unknown_fields_.fields;
    expect(eq(feature_extensions.size(), std::size_t{1}));
    expect(feature_extensions.contains(123U));
    const auto &merged_feature_extensions = pool.messages().front().options().features->unknown_fields_.fields;
    expect(eq(merged_feature_extensions.size(), std::size_t{1}));
    expect(merged_feature_extensions.contains(123U));
    const auto &merged_extension = merged_feature_extensions.at(123U);
    expect(eq(merged_extension.size(), std::size_t{134}));
    expect(eq(merged_extension[3], std::byte{0x5a}));
    expect(eq(merged_extension[70], std::byte{0x6b}));
    expect(eq(tracking_resource.allocations(), std::size_t{0}));
  };

  "non_owning_feature_extension_lookup_merges_parent_and_child"_test = [&] {
    auto proto = make_two_oneofs_fileset();
    proto.options.emplace().features.emplace().unknown_fields_.fields.emplace(
        123U, std::vector<std::byte>{std::byte{0xd8}, std::byte{0x07}, std::byte{0x01}});
    proto.message_type.front().options.emplace().features.emplace().unknown_fields_.fields.emplace(
        123U, std::vector<std::byte>{std::byte{0xd8}, std::byte{0x07}, std::byte{0x02}});

    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(make_descriptor_set_binpb_one(proto)));
    std::pmr::monotonic_buffer_resource message_resource;
    auto message = expect_ok(factory.get_message("Root", message_resource));
    test_feature_extension<> extension;
    expect(message.descriptor().options().features->get_extension(extension).ok());
    expect(eq(extension.value, std::int32_t{2}));
  };

  "non_owning_message_feature_extension_merges_parent_and_child_subfields"_test = [&] {
    constexpr auto field_number = test_message_feature_extension<>::field_number;
    auto proto = make_two_oneofs_fileset();
    proto.options.emplace().features.emplace().unknown_fields_.fields.emplace(
        field_number,
        std::vector<std::byte>{std::byte{0xe2}, std::byte{0x07}, std::byte{0x02}, std::byte{0x08}, std::byte{0x01}});
    proto.message_type.front().options.emplace().features.emplace().unknown_fields_.fields.emplace(
        field_number,
        std::vector<std::byte>{std::byte{0xe2}, std::byte{0x07}, std::byte{0x02}, std::byte{0x10}, std::byte{0x02}});

    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(make_descriptor_set_binpb_one(proto)));
    std::pmr::monotonic_buffer_resource message_resource;
    auto message = expect_ok(factory.get_message("Root", message_resource));
    test_message_feature_extension<> extension;
    expect(message.descriptor().options().features->get_extension(extension).ok());
    expect(eq(extension.value.parent_value, std::int32_t{1}));
    expect(eq(extension.value.child_value, std::int32_t{2}));
  };

  "factory_create_succeeds_after_failed_create"_test = [&] {
    auto invalid_descriptor_set = descriptor_test_corpus::oneof();
    descriptor_test_corpus::root_field(invalid_descriptor_set).oneof_index = 1;
    auto invalid_desc_binpb = make_descriptor_set_binpb(invalid_descriptor_set);
    expect(!hpp_proto::dynamic_message_factory::create(invalid_desc_binpb).has_value());

    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(read_file("unittest.desc.binpb")));

    std::pmr::monotonic_buffer_resource mr2;
    auto msg = factory.get_message("proto3_unittest.TestAllTypes", mr2);
    expect(msg.has_value());
  };

  "interleaved_oneof_fields_factory_init_fails"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_interleaved_oneof_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "active_oneof_index_second_oneof_points_to_active_field"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_two_oneofs_fileset());
    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(desc_binpb));

    std::pmr::monotonic_buffer_resource msg_mr;
    auto msg = expect_ok(factory.get_message("Root", msg_mr));
    auto b2 = expect_ok(msg.field_by_name("b2"));
    expect(b2.set(22).has_value());

    auto b1 = expect_ok(msg.field_by_name("b1"));
    expect(!b1.has_value());
    expect(b2.has_value());
    expect(eq(b1.cref().active_oneof_index(), std::int32_t{3}));
    expect(b1.descriptor().resolved_info().presence() == hpp_proto::field_presence_t::ONEOF);
    expect(eq(b1.descriptor().resolved_info().storage_slot(), b2.descriptor().resolved_info().storage_slot()));
    expect(b1.descriptor().resolved_info().selection_ordinal() != b2.descriptor().resolved_info().selection_ordinal());
  };

  "oneof_ordinal_overflow_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_oneof_ordinal_overflow_fileset());
    auto factory = hpp_proto::dynamic_message_factory::create(desc_binpb);
    expect(fatal(!factory.has_value()));
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::schema_validation_error));
  };

  "factory_create_malformed_binpb_returns_descriptor_deserialization_error"_test = [&] {
    std::string malformed_binpb(1, static_cast<char>(0x80));
    auto factory = hpp_proto::dynamic_message_factory::create(malformed_binpb);
    expect(!factory.has_value());
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::descriptor_deserialization_error));
  };

  "factory_create_invalid_distinct_descs_returns_schema_validation_error"_test = [&] {
    auto invalid_descriptor_set = make_unsupported_edition_descriptor_set();
    auto desc_binpb = make_descriptor_set_binpb(invalid_descriptor_set);
    std::pmr::monotonic_buffer_resource mr;
    auto fileset = expect_ok(hpp_proto::read_binpb<google::protobuf::FileDescriptorSet<hpp_proto::non_owning_traits>>(
        desc_binpb, hpp_proto::alloc_from(mr)));
    expect(!fileset.file.empty());

    std::string file_desc_pb;
    expect(hpp_proto::write_binpb(fileset.file.front(), file_desc_pb).ok());

    hpp_proto::distinct_file_descriptor_pb_array descs = {
        hpp_proto::file_descriptor_pb{file_desc_pb},
    };
    auto factory = hpp_proto::dynamic_message_factory::create(descs);
    expect(!factory.has_value());
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::schema_validation_error));
  };

  "factory_create_malformed_distinct_descs_returns_descriptor_deserialization_error"_test = [&] {
    std::string malformed_desc(1, static_cast<char>(0x80));
    hpp_proto::distinct_file_descriptor_pb_array descs = {
        hpp_proto::file_descriptor_pb{malformed_desc},
    };
    auto factory = hpp_proto::dynamic_message_factory::create(descs);
    expect(!factory.has_value());
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::descriptor_deserialization_error));
  };

  "moved_from_factory_returns_unknown_message_name"_test = [&] {
    auto src = expect_ok(hpp_proto::dynamic_message_factory::create(read_file("unittest.desc.binpb")));
    auto dst = std::move(src);
    std::pmr::monotonic_buffer_resource mr;

    // Intentional: verify moved-from factory has no resolvable message type.
    // NOLINTNEXTLINE(bugprone-use-after-move,hicpp-invalid-access-moved,clang-analyzer-cplusplus.Move)
    auto moved_from_msg = src.get_message("proto3_unittest.TestAllTypes", mr);
    expect(!moved_from_msg.has_value());
    expect(eq(moved_from_msg.error(), hpp_proto::dynamic_message_errc::unknown_message_name));

    auto moved_to_msg = dst.get_message("proto3_unittest.TestAllTypes", mr);
    expect(moved_to_msg.has_value());
  };

  "factory_impl_allocator_deallocates_symmetrically"_test = [&] {
    struct tracking_memory_resource final : std::pmr::memory_resource {
      std::pmr::memory_resource *upstream = std::pmr::new_delete_resource();
      std::size_t allocations = 0;
      std::size_t deallocations = 0;
      std::size_t outstanding_bytes = 0;

    private:
      void *do_allocate(std::size_t bytes, std::size_t alignment) override {
        ++allocations;
        outstanding_bytes += bytes;
        return upstream->allocate(bytes, alignment);
      }

      void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override {
        ++deallocations;
        outstanding_bytes -= bytes;
        upstream->deallocate(p, bytes, alignment);
      }

      [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override {
        return this == &other;
      }
    };

    tracking_memory_resource tracking_mr{};
    {
      auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(
          read_file("unittest.desc.binpb"), hpp_proto::dynamic_message_factory::allocator_type{&tracking_mr}));
      expect(gt(tracking_mr.allocations, std::size_t{0}));
      std::pmr::monotonic_buffer_resource msg_mr;
      expect(factory.get_message("proto3_unittest.TestAllTypes", msg_mr).has_value());
    }
    expect(eq(tracking_mr.allocations, tracking_mr.deallocations));
    expect(eq(tracking_mr.outstanding_bytes, std::size_t{0}));
  };

  struct failpoint_memory_resource final : std::pmr::memory_resource {
    std::pmr::memory_resource *upstream = std::pmr::new_delete_resource();
    std::size_t allocation_count = 0;
    std::size_t deallocation_count = 0;
    std::size_t fail_on_allocation = 0; // 1-based index, 0 disables failpoint

    explicit failpoint_memory_resource(std::size_t fail_on_allocation) : fail_on_allocation(fail_on_allocation) {}

  private:
    void *do_allocate(std::size_t bytes, std::size_t alignment) override {
      ++allocation_count;
      if (fail_on_allocation != 0 && allocation_count == fail_on_allocation) {
        throw std::bad_alloc{};
      }
      return upstream->allocate(bytes, alignment);
    }

    void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override {
      ++deallocation_count;
      upstream->deallocate(p, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override {
      return this == &other;
    }
  };

  // Sentinel: immediate allocator failure must propagate std::bad_alloc.
  "factory_create_propagates_bad_alloc_from_allocator"_test = [&] {
    if constexpr (msvc_asan_bad_alloc_failpoint_unstable) {
      expect(true);
      return;
    }
    failpoint_memory_resource failpoint_mr{1};
    const auto allocator = hpp_proto::dynamic_message_factory::allocator_type{&failpoint_mr};
    bool threw_bad_alloc = false;
    try {
      [[maybe_unused]] auto result =
          hpp_proto::dynamic_message_factory::create(read_file("unittest.desc.binpb"), allocator);
    } catch (const std::bad_alloc &) {
      threw_bad_alloc = true;
    } catch (...) {
      threw_bad_alloc = false;
    }
    expect(threw_bad_alloc);
  };

  // Verifies OOM contract on decode path:
  // 1) std::bad_alloc is propagated at a deterministic failpoint index.
  // 2) Repeating the same failpoint index yields the same failure.
  // 3) A later healthy create still succeeds (no leaked invalid state).
  "factory_create_failpoint_bad_alloc_during_descriptor_decode_is_deterministic"_test = [&] {
    if constexpr (msvc_asan_bad_alloc_failpoint_unstable) {
      expect(true);
      return;
    }
    auto descriptor_binpb = read_file("unittest.desc.binpb");

    auto throws_bad_alloc_for_index = [&](std::size_t fail_index) {
      failpoint_memory_resource failpoint_mr{fail_index};
      auto allocator = hpp_proto::dynamic_message_factory::allocator_type{&failpoint_mr};
      try {
        [[maybe_unused]] auto factory = hpp_proto::dynamic_message_factory::create(descriptor_binpb, allocator);
        return false;
      } catch (const std::bad_alloc &) {
        return true;
      } catch (...) {
        return false;
      }
    };

    std::size_t decode_fail_index = 0;
    for (std::size_t index = 2; index <= 128; ++index) {
      if (throws_bad_alloc_for_index(index)) {
        decode_fail_index = index;
        break;
      }
    }

    expect(gt(decode_fail_index, std::size_t{1}));
    expect(throws_bad_alloc_for_index(decode_fail_index));
    expect(throws_bad_alloc_for_index(decode_fail_index));

    auto healthy_factory = expect_ok(hpp_proto::dynamic_message_factory::create(descriptor_binpb));
    std::pmr::monotonic_buffer_resource msg_mr;
    expect(healthy_factory.get_message("proto3_unittest.TestAllTypes", msg_mr).has_value());
  };

  // Regression test across multiple failpoint indices:
  // 1) Different allocation-failure indices consistently throw std::bad_alloc.
  // 2) Each failed attempt is followed by a healthy create that still succeeds.
  // 3) Confirms no cross-run poisoning from prior OOM failures.
  "factory_create_failpoint_multiple_indices_do_not_poison_later_success"_test = [&] {
    if constexpr (msvc_asan_bad_alloc_failpoint_unstable) {
      expect(true);
      return;
    }
    auto descriptor_binpb = read_file("unittest.desc.binpb");

    std::vector<std::size_t> failing_indices;
    failing_indices.reserve(3);
    for (std::size_t index = 1; index <= 256 && failing_indices.size() < 3; ++index) {
      failpoint_memory_resource failpoint_mr{index};
      auto allocator = hpp_proto::dynamic_message_factory::allocator_type{&failpoint_mr};
      try {
        [[maybe_unused]] auto factory = hpp_proto::dynamic_message_factory::create(descriptor_binpb, allocator);
      } catch (const std::bad_alloc &) {
        failing_indices.push_back(index);
      }
    }

    expect(eq(failing_indices.size(), std::size_t{3}));
    for (const auto fail_index : failing_indices) {
      failpoint_memory_resource failpoint_mr{fail_index};
      auto allocator = hpp_proto::dynamic_message_factory::allocator_type{&failpoint_mr};
      bool threw_bad_alloc = false;
      try {
        [[maybe_unused]] auto result = hpp_proto::dynamic_message_factory::create(descriptor_binpb, allocator);
      } catch (const std::bad_alloc &) {
        threw_bad_alloc = true;
      } catch (...) {
        threw_bad_alloc = false;
      }
      expect(threw_bad_alloc);

      auto recovered_factory = expect_ok(hpp_proto::dynamic_message_factory::create(descriptor_binpb));
      std::pmr::monotonic_buffer_resource msg_mr;
      auto recovered_msg = recovered_factory.get_message("proto3_unittest.TestAllTypes", msg_mr);
      expect(recovered_msg.has_value());
    }
  };

  "unknown_message_name_returns_error"_test = [&] {
    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(read_file("unittest.desc.binpb")));
    std::pmr::monotonic_buffer_resource mr;

    auto missing = factory.get_message("proto3_unittest.DoesNotExist", mr);
    expect(!missing.has_value());
    expect(eq(missing.error(), hpp_proto::dynamic_message_errc::unknown_message_name));
  };
};

// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,misc-const-correctness)
