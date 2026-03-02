#include "test_util.hpp"
#include <array>
#include <boost/ut.hpp>
#include <google/protobuf/descriptor.pb.hpp>
#include <hpp_proto/dynamic_message/binpb.hpp>
#include <hpp_proto/dynamic_message/factory_addons.hpp>
#include <hpp_proto/dynamic_message/json.hpp>
#include <limits>
#include <memory_resource>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace boost::ut;

template <typename Exp>
decltype(auto) expect_ok(Exp &&exp) {
  expect(fatal(exp.has_value()));
  return std::forward<Exp>(exp).value(); // NOLINT
}

const boost::ut::suite parse_default_value_tests = [] {
  "parse_default_value_success"_test = [] {
    expect(eq(hpp_proto::dynamic_message_factory_addons::parse_default_value<int32_t>("123"), 123));
    expect(eq(hpp_proto::dynamic_message_factory_addons::parse_default_value<uint64_t>(
                  std::to_string(std::numeric_limits<uint64_t>::max())),
              std::numeric_limits<uint64_t>::max()));
    expect(eq(hpp_proto::dynamic_message_factory_addons::parse_default_value<float>("1.5"), 1.5F));
    expect(eq(hpp_proto::dynamic_message_factory_addons::parse_default_value<double>("-2.5"), -2.5));
    expect(eq(hpp_proto::dynamic_message_factory_addons::parse_default_value<int32_t>(""),
              0)); // empty defaults to zero-initialized
  };

  "parse_default_value_errors"_test = [] {
    expect(throws<std::invalid_argument>(
        [] { (void)hpp_proto::dynamic_message_factory_addons::parse_default_value<int32_t>("abc"); }));
    expect(throws<std::out_of_range>(
        [] { (void)hpp_proto::dynamic_message_factory_addons::parse_default_value<int32_t>("999999999999"); }));
    expect(throws<std::out_of_range>(
        [] { (void)hpp_proto::dynamic_message_factory_addons::parse_default_value<double>("1e400"); }));
  };
};

const boost::ut::suite descriptor_pool_gap_tests = [] {
  using OwningFileDescriptorProto = google::protobuf::FileDescriptorProto<>;
  using OwningFileDescriptorSet = google::protobuf::FileDescriptorSet<>;
  using MessageProto = google::protobuf::DescriptorProto<>;
  using FieldProto = google::protobuf::FieldDescriptorProto<>;
  using OneofProto = google::protobuf::OneofDescriptorProto<>;
  using EnumProto = google::protobuf::EnumDescriptorProto<>;
  using EnumValueProto = google::protobuf::EnumValueDescriptorProto<>;
  using enum google::protobuf::FieldDescriptorProto_::Label;
  using enum google::protobuf::FieldDescriptorProto_::Type;

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
    const auto limit = static_cast<int32_t>(std::numeric_limits<uint16_t>::max());
    message.field.reserve(static_cast<std::size_t>(limit));
    for (int32_t i = 1; i <= limit; ++i) {
      message.field.push_back(FieldProto{
          .name = "f" + std::to_string(i),
          .number = i,
          .label = LABEL_OPTIONAL,
          .type = TYPE_INT32,
          .oneof_index = 0,
      });
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

  "unsupported_edition_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_edition_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "missing_message_type_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_missing_type_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "duplicate_field_number_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_duplicate_field_number_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
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

  "duplicate_nested_enum_full_name_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_duplicate_nested_enum_full_name_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "invalid_enum_default_name_factory_init_fails"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_enum_default_name_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
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
  };

  "oneof_ordinal_overflow_sets_error"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_oneof_ordinal_overflow_fileset());
    expect(!hpp_proto::dynamic_message_factory::create(desc_binpb).has_value());
  };

  "factory_create_from_non_owning_fileset_overload_succeeds"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_two_oneofs_fileset());
    std::pmr::monotonic_buffer_resource mr;
    auto fileset = expect_ok(hpp_proto::read_binpb<google::protobuf::FileDescriptorSet<hpp_proto::non_owning_traits>>(
        desc_binpb, hpp_proto::alloc_from(mr)));

    auto factory = hpp_proto::dynamic_message_factory::create(std::move(fileset));
    expect(factory.has_value());
  };

  "factory_create_invalid_binpb_returns_bad_message"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_edition_fileset());
    auto factory = hpp_proto::dynamic_message_factory::create(desc_binpb);
    expect(!factory.has_value());
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::bad_message));
  };

  "factory_create_invalid_fileset_returns_bad_message"_test = [&] {
    auto desc_binpb = make_descriptor_set_binpb_one(make_invalid_edition_fileset());
    std::pmr::monotonic_buffer_resource mr;
    auto fileset = expect_ok(hpp_proto::read_binpb<google::protobuf::FileDescriptorSet<hpp_proto::non_owning_traits>>(
        desc_binpb, hpp_proto::alloc_from(mr)));

    auto factory = hpp_proto::dynamic_message_factory::create(std::move(fileset));
    expect(!factory.has_value());
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::bad_message));
  };

  "factory_create_invalid_distinct_descs_returns_bad_message"_test = [&] {
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
    expect(eq(factory.error(), hpp_proto::dynamic_message_errc::bad_message));
  };

  "moved_from_factory_returns_unknown_message_name"_test = [&] {
    auto src = expect_ok(hpp_proto::dynamic_message_factory::create(read_file("unittest.desc.binpb")));
    auto dst = std::move(src);
    std::pmr::monotonic_buffer_resource mr;

    auto moved_from_msg = src.get_message("proto3_unittest.TestAllTypes", mr);
    expect(!moved_from_msg.has_value());
    expect(eq(moved_from_msg.error(), hpp_proto::dynamic_message_errc::unknown_message_name));

    auto moved_to_msg = dst.get_message("proto3_unittest.TestAllTypes", mr);
    expect(moved_to_msg.has_value());
  };
  //   #endif

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
          read_file("unittest.desc.binpb"), hpp_proto::dynamic_message_factory::impl_allocator_type{&tracking_mr}));
      expect(gt(tracking_mr.allocations, std::size_t{0}));
      std::pmr::monotonic_buffer_resource msg_mr;
      expect(factory.get_message("proto3_unittest.TestAllTypes", msg_mr).has_value());
    }
    expect(eq(tracking_mr.allocations, tracking_mr.deallocations));
    expect(eq(tracking_mr.outstanding_bytes, std::size_t{0}));
  };

  "unknown_message_name_returns_error"_test = [&] {
    auto factory = expect_ok(hpp_proto::dynamic_message_factory::create(read_file("unittest.desc.binpb")));
    std::pmr::monotonic_buffer_resource mr;

    auto missing = factory.get_message("proto3_unittest.DoesNotExist", mr);
    expect(!missing.has_value());
    expect(eq(missing.error(), hpp_proto::dynamic_message_errc::unknown_message_name));
  };
};
