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
  using OwningFileDescriptorProto = google::protobuf::FileDescriptorProto<>;
  using OwningFileDescriptorSet = google::protobuf::FileDescriptorSet<>;
  using MessageProto = google::protobuf::DescriptorProto<>;
  using FieldProto = google::protobuf::FieldDescriptorProto<>;
  using OneofProto = google::protobuf::OneofDescriptorProto<>;
  using EnumProto = google::protobuf::EnumDescriptorProto<>;
  using EnumValueProto = google::protobuf::EnumValueDescriptorProto<>;
  using enum google::protobuf::FieldDescriptorProto<>::Label;
  using enum google::protobuf::FieldDescriptorProto<>::Type;

  auto make_descriptor_set_binpb_one = [&](const OwningFileDescriptorProto &proto) {
    std::string buffer;
    OwningFileDescriptorSet file_set{.file = {proto}};
    expect(hpp_proto::write_binpb(file_set, buffer).ok());
    return buffer;
  };

  auto make_descriptor_set_binpb_many = [&](std::initializer_list<OwningFileDescriptorProto> protos) {
    OwningFileDescriptorSet file_set;
    file_set.file.reserve(protos.size());
    for (const auto &proto : protos) {
      file_set.file.push_back(proto);
    }
    std::string buffer;
    expect(hpp_proto::write_binpb(file_set, buffer).ok());
    return buffer;
  };

  auto make_invalid_edition_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_edition.proto",
        .syntax = "editions",
        .edition = static_cast<google::protobuf::Edition>(0x7fffffff),
    };
  };

  auto make_valid_edition_with_file_feature_overrides_fileset = [] {
    using enum google::protobuf::FeatureSet<>::FieldPresence;
    using enum google::protobuf::FeatureSet<>::MessageEncoding;
    using enum google::protobuf::FeatureSet<>::RepeatedFieldEncoding;

    return OwningFileDescriptorProto{
        .name = "edition_features.proto",
        .package = "edition_features",
        .message_type =
            {
                MessageProto{
                    .name = "Child",
                },
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "numbers",
                                .number = 1,
                                .label = LABEL_REPEATED,
                                .type = TYPE_INT32,
                            },
                            FieldProto{
                                .name = "scalar",
                                .number = 2,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                            },
                            FieldProto{
                                .name = "child",
                                .number = 3,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_MESSAGE,
                                .type_name = ".edition_features.Child",
                            },
                            FieldProto{
                                .name = "legacy_required_scalar",
                                .number = 4,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                                .options =
                                    google::protobuf::FieldOptions<>{
                                        .features = google::protobuf::FeatureSet<>{.field_presence = LEGACY_REQUIRED}},
                            },
                        },
                },
            },
        .options =
            google::protobuf::FileOptions<>{
                .features =
                    google::protobuf::FeatureSet<>{
                        .field_presence = IMPLICIT,
                        .repeated_field_encoding = EXPANDED,
                        .message_encoding = DELIMITED,
                    },
            },
        .syntax = "editions",
        .edition = google::protobuf::Edition::EDITION_2023,
    };
  };

  auto make_missing_type_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "missing_type.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "missing",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_MESSAGE,
                                .type_name = ".MissingType",
                            },
                        },
                },
            },
    };
  };

  auto make_missing_enum_type_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "missing_enum_type.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "missing_enum",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_ENUM,
                                .type_name = ".MissingEnum",
                            },
                        },
                },
            },
    };
  };

  auto make_invalid_field_type_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_field_type.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "invalid_type",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                // Deliberately construct an invalid descriptor enum value.
                                // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
                                .type = static_cast<FieldProto::Type>(19),
                            },
                        },
                },
            },
    };
  };

  auto make_invalid_field_label_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_field_label.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "invalid_label",
                                .number = 1,
                                // Deliberately construct an invalid descriptor enum value.
                                // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
                                .label = static_cast<FieldProto::Label>(4),
                                .type = TYPE_INT32,
                            },
                        },
                },
            },
    };
  };

  auto make_invalid_file_extension_type_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_file_extension_type.proto",
        .message_type = {MessageProto{.name = "Root"}},
        .extension =
            {
                FieldProto{
                    .name = "invalid_type_extension",
                    .number = 100,
                    .label = LABEL_OPTIONAL,
                    // Deliberately construct an invalid descriptor enum value.
                    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
                    .type = static_cast<FieldProto::Type>(19),
                    .extendee = ".Root",
                },
            },
    };
  };

  auto make_invalid_message_extension_label_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_message_extension_label.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .extension =
                        {
                            FieldProto{
                                .name = "invalid_label_extension",
                                .number = 100,
                                // Deliberately construct an invalid descriptor enum value.
                                // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
                                .label = static_cast<FieldProto::Label>(4),
                                .type = TYPE_INT32,
                                .extendee = ".Root",
                            },
                        },
                },
            },
    };
  };

  auto make_duplicate_field_number_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "duplicate_field_number.proto",
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
                            },
                            FieldProto{
                                .name = "b",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_STRING,
                            },
                        },
                },
            },
    };
  };

  auto make_json_name_proto_name_conflict_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "json_name_proto_name_conflict.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "alpha",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_STRING,
                                .json_name = "beta",
                            },
                            FieldProto{
                                .name = "beta",
                                .number = 2,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_STRING,
                                .json_name = "beta2",
                            },
                        },
                },
            },
    };
  };

  auto make_empty_json_name_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "empty_json_name.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "alpha_value",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_STRING,
                                .json_name = "",
                            },
                            FieldProto{
                                .name = "beta_value",
                                .number = 2,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_STRING,
                                .json_name = "betaValue",
                            },
                        },
                },
            },
    };
  };

  auto make_invalid_field_number_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_field_number.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "bad_zero",
                                .number = 0,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                            },
                        },
                },
            },
    };
  };

  auto make_reserved_field_number_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "reserved_field_number.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "bad_reserved",
                                .number = 19000,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                            },
                        },
                },
            },
    };
  };

  auto make_too_large_field_number_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "too_large_field_number.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "bad_large",
                                .number = 536870912,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                            },
                        },
                },
            },
    };
  };

  auto make_field_number_fileset = [](int32_t field_number) {
    return OwningFileDescriptorProto{
        .name = "field_number_boundary.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "boundary",
                                .number = field_number,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                            },
                        },
                },
            },
    };
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

  auto make_invalid_oneof_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_oneof.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "bad_oneof",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                                .oneof_index = 0,
                            },
                        },
                },
            },
    };
  };

  auto make_repeated_oneof_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "repeated_oneof.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "bad_repeated_oneof",
                                .number = 1,
                                .label = LABEL_REPEATED,
                                .type = TYPE_INT32,
                                .oneof_index = 0,
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

  auto make_empty_oneof_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "empty_oneof.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .oneof_decl =
                        {
                            OneofProto{.name = "empty"},
                        },
                },
            },
    };
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

  auto make_missing_extendee_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "missing_extendee.proto",
        .extension =
            {
                FieldProto{
                    .name = "bad_ext",
                    .number = 100,
                    .label = LABEL_OPTIONAL,
                    .type = TYPE_INT32,
                    .extendee = ".MissingExtendee",
                },
            },
    };
  };

  auto make_invalid_extension_field_number_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_extension_field_number.proto",
        .extension =
            {
                FieldProto{
                    .name = "bad_ext_num",
                    .number = 19000,
                    .label = LABEL_OPTIONAL,
                    .type = TYPE_INT32,
                    .extendee = ".MissingExtendee",
                },
            },
    };
  };

  auto make_invalid_message_extension_field_number_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_message_extension_field_number.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .extension =
                        {
                            FieldProto{
                                .name = "bad_ext_num",
                                .number = 19000,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_INT32,
                            },
                        },
                },
            },
    };
  };

  auto make_invalid_enum_default_name_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_enum_default_name.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "enum_field",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_ENUM,
                                .type_name = ".Root.E",
                                .default_value = "DOES_NOT_EXIST",
                            },
                        },
                    .enum_type =
                        {
                            EnumProto{
                                .name = "E",
                                .value =
                                    {
                                        EnumValueProto{.name = "ZERO", .number = 0},
                                    },
                            },
                        },
                },
            },
    };
  };

  auto make_required_enum_default_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "required_enum_default.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "required_enum",
                                .number = 1,
                                .label = LABEL_REQUIRED,
                                .type = TYPE_ENUM,
                                .type_name = ".Root.E",
                            },
                        },
                    .enum_type =
                        {
                            EnumProto{
                                .name = "E",
                                .value =
                                    {
                                        EnumValueProto{.name = "FIRST", .number = 7},
                                        EnumValueProto{.name = "SECOND", .number = 8},
                                    },
                            },
                        },
                },
            },
    };
  };

  auto make_invalid_numeric_default_fileset = [](auto type, std::string_view default_value) {
    return OwningFileDescriptorProto{
        .name = "invalid_numeric_default.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "value",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = type,
                                .default_value = std::string{default_value},
                            },
                        },
                },
            },
    };
  };

  auto make_empty_enum_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "empty_enum.proto",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .field =
                        {
                            FieldProto{
                                .name = "enum_field",
                                .number = 1,
                                .label = LABEL_OPTIONAL,
                                .type = TYPE_ENUM,
                                .type_name = ".Root.E",
                            },
                        },
                    .enum_type =
                        {
                            EnumProto{.name = "E"},
                        },
                },
            },
    };
  };

  auto make_missing_dependency_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "has_missing_dependency.proto",
        .dependency = {"missing_dependency.proto"},
    };
  };

  auto make_empty_file_name_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "",
        .package = "pkg",
        .message_type = {MessageProto{.name = "Root"}},
    };
  };

  auto make_empty_message_name_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "empty_message_name.proto",
        .package = "pkg",
        .message_type = {MessageProto{.name = ""}},
    };
  };

  auto make_empty_nested_message_name_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "empty_nested_message_name.proto",
        .package = "pkg",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .nested_type = {MessageProto{.name = ""}},
                },
            },
    };
  };

  auto make_invalid_deeply_nested_message_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "invalid_deeply_nested_message.proto",
        .package = "pkg",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .nested_type =
                        {
                            MessageProto{
                                .name = "Child",
                                .nested_type = {MessageProto{.name = ""}},
                            },
                        },
                },
            },
    };
  };

  auto make_empty_enum_name_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "empty_enum_name.proto",
        .package = "pkg",
        .enum_type = {EnumProto{.name = "", .value = {EnumValueProto{.name = "ZERO", .number = 0}}}},
    };
  };

  auto make_empty_nested_enum_name_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "empty_nested_enum_name.proto",
        .package = "pkg",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .enum_type = {EnumProto{.name = "", .value = {EnumValueProto{.name = "ZERO", .number = 0}}}},
                },
            },
    };
  };

  auto make_duplicate_nested_enum_full_name_fileset = [] {
    return OwningFileDescriptorProto{
        .name = "duplicate_nested_enum_full_name.proto",
        .package = "pkg",
        .message_type =
            {
                MessageProto{
                    .name = "Root",
                    .enum_type =
                        {
                            EnumProto{.name = "DupEnum", .value = {EnumValueProto{.name = "ZERO", .number = 0}}},
                            EnumProto{.name = "DupEnum", .value = {EnumValueProto{.name = "ZERO", .number = 0}}},
                        },
                },
            },
    };
  };

  auto make_duplicate_file_name_fileset = [] {
    return std::array{
        OwningFileDescriptorProto{
            .name = "dup_file.proto",
            .package = "pkg_a",
            .message_type = {MessageProto{.name = "A"}},
        },
        OwningFileDescriptorProto{
            .name = "dup_file.proto",
            .package = "pkg_b",
            .message_type = {MessageProto{.name = "B"}},
        },
    };
  };

  auto make_duplicate_message_full_name_fileset = [] {
    return std::array{
        OwningFileDescriptorProto{
            .name = "first.proto",
            .package = "pkg",
            .message_type = {MessageProto{.name = "Dup"}},
        },
        OwningFileDescriptorProto{
            .name = "second.proto",
            .package = "pkg",
            .message_type = {MessageProto{.name = "Dup"}},
        },
    };
  };

  auto make_duplicate_enum_full_name_fileset = [] {
    return std::array{
        OwningFileDescriptorProto{
            .name = "first_enum.proto",
            .package = "pkg",
            .enum_type = {EnumProto{.name = "DupEnum", .value = {EnumValueProto{.name = "ZERO", .number = 0}}}},
        },
        OwningFileDescriptorProto{
            .name = "second_enum.proto",
            .package = "pkg",
            .enum_type = {EnumProto{.name = "DupEnum", .value = {EnumValueProto{.name = "ZERO", .number = 0}}}},
        },
    };
  };

  auto make_direct_dependency_cycle_fileset = [] {
    return std::array{
        OwningFileDescriptorProto{
            .name = "dep_a.proto",
            .package = "dep",
            .dependency = {"dep_b.proto"},
            .message_type = {MessageProto{.name = "A"}},
        },
        OwningFileDescriptorProto{
            .name = "dep_b.proto",
            .package = "dep",
            .dependency = {"dep_a.proto"},
            .message_type = {MessageProto{.name = "B"}},
        },
    };
  };

  auto make_transitive_dependency_cycle_fileset = [] {
    return std::array{
        OwningFileDescriptorProto{
            .name = "dep_a.proto",
            .package = "dep",
            .dependency = {"dep_b.proto"},
            .message_type = {MessageProto{.name = "A"}},
        },
        OwningFileDescriptorProto{
            .name = "dep_b.proto",
            .package = "dep",
            .dependency = {"dep_c.proto"},
            .message_type = {MessageProto{.name = "B"}},
        },
        OwningFileDescriptorProto{
            .name = "dep_c.proto",
            .package = "dep",
            .dependency = {"dep_a.proto"},
            .message_type = {MessageProto{.name = "C"}},
        },
    };
  };

  "unsupported_edition_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_edition_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "edition_file_feature_overrides_are_merged_into_runtime_descriptors"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_valid_edition_with_file_feature_overrides_fileset());
    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(desc_binpb));

    std::pmr::monotonic_buffer_resource memory_resource;
    auto msg = expect_ok(factory.get_message("edition_features.Root", memory_resource));

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
    auto proto = make_valid_edition_with_file_feature_overrides_fileset();
    proto.options->features->unknown_fields_.fields.emplace(
        field_number, std::vector<std::byte>{std::byte{0xea}, std::byte{0x07}, std::byte{0x04}, std::byte{0x08},
                                             std::byte{0x07}, std::byte{0x08}, std::byte{0x0b}});

    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(make_descriptor_set_binpb_one(proto)));
    std::pmr::monotonic_buffer_resource memory_resource;
    auto message = expect_ok(factory.get_message("edition_features.Root", memory_resource));
    test_repeated_message_feature_extension<> extension;

    expect(message.descriptor().parent_file()->options().features->get_extension(extension).ok());
    expect(fatal(eq(extension.value.values.size(), std::size_t{2})));
    expect(eq(extension.value.values[0], std::int32_t{7}));
    expect(eq(extension.value.values[1], std::int32_t{11}));
  };

  "missing_message_type_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_missing_type_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "missing_enum_type_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_missing_enum_type_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "invalid_field_type_returns_schema_validation_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_field_type_fileset());
    auto factory = hpp_proto::dynamic_message_factory::create(desc_binpb);
    expect(fatal(!factory.has_value()));
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::schema_validation_error));
  };

  "invalid_field_label_returns_schema_validation_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_field_label_fileset());
    auto factory = hpp_proto::dynamic_message_factory::create(desc_binpb);
    expect(fatal(!factory.has_value()));
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::schema_validation_error));
  };

  "invalid_file_extension_type_returns_schema_validation_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_file_extension_type_fileset());
    auto factory = hpp_proto::dynamic_message_factory::create(desc_binpb);
    expect(fatal(!factory.has_value()));
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::schema_validation_error));
  };

  "invalid_message_extension_label_returns_schema_validation_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_message_extension_label_fileset());
    auto factory = hpp_proto::dynamic_message_factory::create(desc_binpb);
    expect(fatal(!factory.has_value()));
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::schema_validation_error));
  };

  "duplicate_field_number_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_duplicate_field_number_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "json_name_proto_name_conflict_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_json_name_proto_name_conflict_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "empty_json_name_is_allowed"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_empty_json_name_fileset());
    expect(hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "invalid_field_number_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_field_number_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "reserved_field_number_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_reserved_field_number_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "too_large_field_number_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_too_large_field_number_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "field_number_1_is_valid"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_field_number_fileset(1));
    expect(hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "field_number_18999_is_valid"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_field_number_fileset(18999));
    expect(hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "field_number_19999_is_invalid_reserved_range"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_field_number_fileset(19999));
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "field_number_20000_is_valid"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_field_number_fileset(20000));
    expect(hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "field_number_536870911_is_valid_max"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_field_number_fileset(536870911));
    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(desc_binpb));

    std::pmr::monotonic_buffer_resource write_resource;
    auto message = expect_ok(factory.get_message("Root", write_resource));
    expect(expect_ok(message.field_by_name("boundary")).set(std::int32_t{1}).has_value());

    std::string encoded;
    expect(hpp_proto::write_binpb(message.cref(), encoded).ok());
    const std::string expected{"\xf8\xff\xff\xff\x0f\x01", 6};
    expect(eq(encoded, expected));

    std::pmr::monotonic_buffer_resource read_resource;
    auto decoded = expect_ok(factory.get_message("Root", read_resource));
    expect(hpp_proto::read_binpb(decoded, encoded).ok());
    expect(eq(expect_ok(decoded.field_value_by_name<std::int32_t>("boundary")), std::int32_t{1}));
  };

  "large_descriptor_collection_factory_init_succeeds"_test = [&] {
    auto files = make_large_descriptor_collection_fileset(256);
    OwningFileDescriptorSet file_set;
    file_set.file = std::move(files);
    std::string desc_binpb;
    expect(hpp_proto::write_binpb(file_set, desc_binpb).ok());
    expect(hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
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
    std::string desc_binpb;
    expect(hpp_proto::write_binpb(file_set, desc_binpb).ok());
    expect(hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "deep_name_and_dependency_pressure_factory_init_succeeds"_test = [&] {
    OwningFileDescriptorSet file_set;
    file_set.file = make_deep_name_and_dependency_pressure_fileset();
    std::string desc_binpb;
    expect(hpp_proto::write_binpb(file_set, desc_binpb).ok());
    expect(hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "factory_create_truncation_and_length_mismatch_binpb_returns_descriptor_deserialization_error"_test = [&] {
    auto valid_desc_binpb = make_descriptor_set_binpb_one(make_two_oneofs_fileset());
    expect(valid_desc_binpb.size() > 2U);

    std::array<std::string, 4> malformed_cases = {
        valid_desc_binpb.substr(0, valid_desc_binpb.size() - 1),         // truncated valid payload
        valid_desc_binpb.substr(0, 2),                                   // very short truncation
        std::string{"\x0A\x05\x08\x96\x01", 5},                          // declared length exceeds available bytes
        std::string{"\x0A\x80\x80\x80\x80\x80\x80\x80\x80\x80\x02", 11}, // malformed/overlong length varint
    };

    for (const auto &malformed : malformed_cases) {
      auto factory = hpp_proto::dynamic_message_factory::create(malformed);
      expect(!factory.has_value());
      expect(eq(factory.error(), hpp_proto::dynamic_message_errc::descriptor_deserialization_error));
    }
  };

  "invalid_oneof_index_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_oneof_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "repeated_oneof_field_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_repeated_oneof_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "empty_oneof_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_empty_oneof_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "missing_extendee_type_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_missing_extendee_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "invalid_extension_field_number_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_extension_field_number_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "invalid_message_extension_field_number_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_message_extension_field_number_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "missing_file_dependency_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_missing_dependency_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "empty_file_name_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_empty_file_name_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "empty_message_name_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_empty_message_name_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "empty_nested_message_name_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_empty_nested_message_name_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "invalid_deeply_nested_message_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_deeply_nested_message_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "empty_enum_name_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_empty_enum_name_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "empty_nested_enum_name_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_empty_nested_enum_name_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "duplicate_file_name_sets_error"_test = [&] {
    auto files = make_duplicate_file_name_fileset();
    auto desc_binpb = make_descriptor_set_binpb_many({files[0], files[1]});
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "duplicate_message_full_name_sets_error"_test = [&] {
    auto files = make_duplicate_message_full_name_fileset();
    auto desc_binpb = make_descriptor_set_binpb_many({files[0], files[1]});
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "duplicate_enum_full_name_sets_error"_test = [&] {
    auto files = make_duplicate_enum_full_name_fileset();
    auto desc_binpb = make_descriptor_set_binpb_many({files[0], files[1]});
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "direct_dependency_cycle_sets_error"_test = [&] {
    auto files = make_direct_dependency_cycle_fileset();
    auto desc_binpb = make_descriptor_set_binpb_many({files[0], files[1]});
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "transitive_dependency_cycle_sets_error"_test = [&] {
    auto files = make_transitive_dependency_cycle_fileset();
    auto desc_binpb = make_descriptor_set_binpb_many({files[0], files[1], files[2]});
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "duplicate_nested_enum_full_name_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_duplicate_nested_enum_full_name_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "invalid_enum_default_name_factory_init_fails"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_enum_default_name_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "required_enum_uses_first_value_as_implicit_default"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_required_enum_default_fileset());
    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(desc_binpb));

    std::pmr::monotonic_buffer_resource memory_resource;
    auto message = expect_ok(factory.get_message("Root", memory_resource));
    auto field = expect_ok(message.field_by_name("required_enum"));
    auto typed_field = expect_ok(field.to<hpp_proto::enum_field_mref>());
    expect(eq(typed_field.default_value().number(), std::int32_t{7}));
    expect(eq(typed_field.value().number(), std::int32_t{7}));
    expect(typed_field.descriptor().resolved_info().presence() == hpp_proto::field_presence_t::REQUIRED);

    const std::string encoded_default{"\x08\x07", 2};
    expect(hpp_proto::read_binpb(message, encoded_default).ok());
    expect(typed_field.has_value());
    std::string roundtrip;
    expect(hpp_proto::write_binpb(message.cref(), roundtrip).ok());
    expect(eq(roundtrip, encoded_default));
  };

  "invalid_numeric_defaults_return_schema_validation_error"_test = [&] {
    auto expect_schema_error = [&](auto type, std::string_view default_value) {
      auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_numeric_default_fileset(type, default_value));
      auto factory = hpp_proto::dynamic_message_factory::create(desc_binpb);
      expect(fatal(!factory.has_value()));
      expect(eq(factory.error(), hpp_proto::dynamic_message_errc::schema_validation_error));
    };

    expect_schema_error(TYPE_INT32, "not-an-integer");
    expect_schema_error(TYPE_INT32, "999999999999");
    expect_schema_error(TYPE_DOUBLE, "1e400");
  };

  "empty_enum_factory_init_fails"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_empty_enum_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "pmr_default_resource_restored_on_error"_test = [&] {
    auto *old_resource = std::pmr::get_default_resource();
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_edition_fileset());
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
    auto invalid_desc_binpb = make_descriptor_set_binpb_one(make_invalid_oneof_fileset());
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
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_edition_fileset());
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
