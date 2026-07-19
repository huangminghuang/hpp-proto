#pragma once

#include <cassert>
#include <cstddef>
#include <google/protobuf/descriptor.pb.hpp>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-designated-field-initializers"
#endif

namespace descriptor_test_corpus {

// Descriptor seeds intentionally use partial designated initialization and literal schema numbers.
// NOLINTBEGIN(clang-diagnostic-missing-designated-field-initializers,
// cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

using file_descriptor = google::protobuf::FileDescriptorProto<>;
using file_descriptor_set = google::protobuf::FileDescriptorSet<>;
using message_descriptor = google::protobuf::DescriptorProto<>;
using field_descriptor = google::protobuf::FieldDescriptorProto<>;
using oneof_descriptor = google::protobuf::OneofDescriptorProto<>;
using enum_descriptor = google::protobuf::EnumDescriptorProto<>;
using enum_value_descriptor = google::protobuf::EnumValueDescriptorProto<>;

using enum google::protobuf::FieldDescriptorProto_::Label;
using enum google::protobuf::FieldDescriptorProto_::Type;

[[nodiscard]] inline file_descriptor_set scalar_field() {
  return file_descriptor_set{
      .file =
          {
              file_descriptor{
                  .name = "corpus_scalar.proto",
                  .package = "descriptor_corpus",
                  .message_type =
                      {
                          message_descriptor{
                              .name = "Root",
                              .field =
                                  {
                                      field_descriptor{
                                          .name = "value",
                                          .number = 1,
                                          .label = LABEL_OPTIONAL,
                                          .type = TYPE_INT32,
                                          .json_name = "value",
                                      },
                                  },
                          },
                      },
                  .syntax = "proto2",
              },
          },
  };
}

[[nodiscard]] inline file_descriptor_set referenced_types() {
  return file_descriptor_set{
      .file =
          {
              file_descriptor{
                  .name = "corpus_types.proto",
                  .package = "descriptor_corpus",
                  .message_type =
                      {
                          message_descriptor{.name = "Child"},
                          message_descriptor{
                              .name = "Root",
                              .field =
                                  {
                                      field_descriptor{
                                          .name = "child",
                                          .number = 1,
                                          .label = LABEL_OPTIONAL,
                                          .type = TYPE_MESSAGE,
                                          .type_name = ".descriptor_corpus.Child",
                                          .json_name = "child",
                                      },
                                      field_descriptor{
                                          .name = "choice",
                                          .number = 2,
                                          .label = LABEL_OPTIONAL,
                                          .type = TYPE_ENUM,
                                          .type_name = ".descriptor_corpus.Choice",
                                          .default_value = "CHOICE_ZERO",
                                          .json_name = "choice",
                                      },
                                  },
                              .nested_type = {message_descriptor{.name = "Nested"}},
                              .enum_type =
                                  {
                                      enum_descriptor{
                                          .name = "NestedChoice",
                                          .value =
                                              {
                                                  enum_value_descriptor{.name = "NESTED_ZERO", .number = 0},
                                              },
                                      },
                                  },
                          },
                      },
                  .enum_type =
                      {
                          enum_descriptor{
                              .name = "Choice",
                              .value =
                                  {
                                      enum_value_descriptor{.name = "CHOICE_ZERO", .number = 0},
                                      enum_value_descriptor{.name = "CHOICE_ONE", .number = 1},
                                  },
                          },
                      },
                  .syntax = "proto2",
              },
          },
  };
}

[[nodiscard]] inline file_descriptor_set oneof() {
  return file_descriptor_set{
      .file =
          {
              file_descriptor{
                  .name = "corpus_oneof.proto",
                  .package = "descriptor_corpus",
                  .message_type =
                      {
                          message_descriptor{
                              .name = "Root",
                              .field =
                                  {
                                      field_descriptor{
                                          .name = "first",
                                          .number = 1,
                                          .label = LABEL_OPTIONAL,
                                          .type = TYPE_INT32,
                                          .oneof_index = 0,
                                          .json_name = "first",
                                      },
                                      field_descriptor{
                                          .name = "second",
                                          .number = 2,
                                          .label = LABEL_OPTIONAL,
                                          .type = TYPE_STRING,
                                          .oneof_index = 0,
                                          .json_name = "second",
                                      },
                                  },
                              .oneof_decl = {oneof_descriptor{.name = "choice"}},
                          },
                      },
                  .syntax = "proto2",
              },
          },
  };
}

[[nodiscard]] inline file_descriptor_set extensions() {
  return file_descriptor_set{
      .file =
          {
              file_descriptor{
                  .name = "corpus_extensions.proto",
                  .package = "descriptor_corpus",
                  .message_type =
                      {
                          message_descriptor{
                              .name = "Root",
                              .extension_range =
                                  {
                                      message_descriptor::ExtensionRange{.start = 100, .end = 200},
                                  },
                          },
                          message_descriptor{
                              .name = "ExtensionScope",
                              .extension =
                                  {
                                      field_descriptor{
                                          .name = "message_extension",
                                          .number = 101,
                                          .label = LABEL_OPTIONAL,
                                          .type = TYPE_INT32,
                                          .extendee = ".descriptor_corpus.Root",
                                          .json_name = "messageExtension",
                                      },
                                  },
                          },
                      },
                  .extension =
                      {
                          field_descriptor{
                              .name = "file_extension",
                              .number = 100,
                              .label = LABEL_OPTIONAL,
                              .type = TYPE_INT32,
                              .extendee = ".descriptor_corpus.Root",
                              .json_name = "fileExtension",
                          },
                      },
                  .syntax = "proto2",
              },
          },
  };
}

[[nodiscard]] inline file_descriptor_set dependency_graph() {
  return file_descriptor_set{
      .file =
          {
              file_descriptor{
                  .name = "corpus_a.proto",
                  .package = "descriptor_corpus.graph",
                  .message_type = {message_descriptor{.name = "A"}},
                  .enum_type =
                      {
                          enum_descriptor{
                              .name = "EA",
                              .value = {enum_value_descriptor{.name = "EA_ZERO", .number = 0}},
                          },
                      },
                  .syntax = "proto2",
              },
              file_descriptor{
                  .name = "corpus_b.proto",
                  .package = "descriptor_corpus.graph",
                  .dependency = {"corpus_a.proto"},
                  .message_type = {message_descriptor{.name = "B"}},
                  .enum_type =
                      {
                          enum_descriptor{
                              .name = "EB",
                              .value = {enum_value_descriptor{.name = "EB_ZERO", .number = 0}},
                          },
                      },
                  .syntax = "proto2",
              },
              file_descriptor{
                  .name = "corpus_c.proto",
                  .package = "descriptor_corpus.graph",
                  .dependency = {"corpus_b.proto"},
                  .message_type = {message_descriptor{.name = "C"}},
                  .enum_type =
                      {
                          enum_descriptor{
                              .name = "EC",
                              .value = {enum_value_descriptor{.name = "EC_ZERO", .number = 0}},
                          },
                      },
                  .syntax = "proto2",
              },
          },
  };
}

[[nodiscard]] inline file_descriptor_set editions_2023() {
  using enum google::protobuf::FeatureSet_::FieldPresence;
  using enum google::protobuf::FeatureSet_::MessageEncoding;
  using enum google::protobuf::FeatureSet_::RepeatedFieldEncoding;

  return file_descriptor_set{
      .file =
          {
              file_descriptor{
                  .name = "corpus_editions.proto",
                  .package = "descriptor_corpus.editions",
                  .message_type =
                      {
                          message_descriptor{.name = "Child"},
                          message_descriptor{
                              .name = "Root",
                              .field =
                                  {
                                      field_descriptor{
                                          .name = "numbers",
                                          .number = 1,
                                          .label = LABEL_REPEATED,
                                          .type = TYPE_INT32,
                                      },
                                      field_descriptor{
                                          .name = "scalar",
                                          .number = 2,
                                          .label = LABEL_OPTIONAL,
                                          .type = TYPE_INT32,
                                      },
                                      field_descriptor{
                                          .name = "child",
                                          .number = 3,
                                          .label = LABEL_OPTIONAL,
                                          .type = TYPE_MESSAGE,
                                          .type_name = ".descriptor_corpus.editions.Child",
                                      },
                                      field_descriptor{
                                          .name = "legacy_required_scalar",
                                          .number = 4,
                                          .label = LABEL_OPTIONAL,
                                          .type = TYPE_INT32,
                                          .options =
                                              google::protobuf::FieldOptions<>{
                                                  .features = google::protobuf::FeatureSet<>{.field_presence =
                                                                                                 LEGACY_REQUIRED}},
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
              },
          },
  };
}

[[nodiscard]] inline file_descriptor &only_file(file_descriptor_set &descriptor_set) {
  assert(descriptor_set.file.size() == 1U);
  return descriptor_set.file.front();
}

[[nodiscard]] inline const file_descriptor &only_file(const file_descriptor_set &descriptor_set) {
  assert(descriptor_set.file.size() == 1U);
  return descriptor_set.file.front();
}

[[nodiscard]] inline message_descriptor &root_message(file_descriptor_set &descriptor_set) {
  auto &file = only_file(descriptor_set);
  assert(!file.message_type.empty());
  return file.message_type.back();
}

[[nodiscard]] inline const message_descriptor &root_message(const file_descriptor_set &descriptor_set) {
  const auto &file = only_file(descriptor_set);
  assert(!file.message_type.empty());
  return file.message_type.back();
}

[[nodiscard]] inline field_descriptor &root_field(file_descriptor_set &descriptor_set, std::size_t index = 0U) {
  auto &message = root_message(descriptor_set);
  assert(index < message.field.size());
  return message.field[index];
}

[[nodiscard]] inline const field_descriptor &root_field(const file_descriptor_set &descriptor_set,
                                                        std::size_t index = 0U) {
  const auto &message = root_message(descriptor_set);
  assert(index < message.field.size());
  return message.field[index];
}

// NOLINTEND(clang-diagnostic-missing-designated-field-initializers,
// cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

} // namespace descriptor_test_corpus

#ifdef __clang__
#pragma clang diagnostic pop
#endif
