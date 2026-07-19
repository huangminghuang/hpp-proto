// MIT License
//
// Copyright (c) Huang-Ming Huang
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "hpp_generator.hpp"
#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <google/protobuf/compiler/plugin.pb.hpp>
#include <hpp_proto/descriptor_pool.hpp>
#include <hpp_proto/hpp_options.pb.hpp>
#include <iostream>
#include <iterator>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {
namespace cpp = ::hpp_proto::protoc::cpp;
constexpr std::size_t proto_suffix_length = std::string_view{"proto"}.size();

class generation_diagnostics {
public:
  void record(std::string message) {
    if (message_.empty()) {
      message_ = std::move(message);
    }
  }

  [[nodiscard]] bool has_error() const noexcept { return !message_.empty(); }
  [[nodiscard]] const std::string &message() const noexcept { return message_; }

private:
  std::string message_;
};

struct generation_context {
  const ::hpp_proto::protoc::generator_options &options;
  generation_diagnostics diagnostics;
};

cpp::identifier cpp_identifier(std::string_view name, generation_diagnostics &diagnostics) {
  auto result = cpp::identifier::from_proto(name);
  if (result.has_value()) {
    return std::move(*result);
  }
  diagnostics.record(result.error().message);
  return cpp::identifier::from_protobuf_namespace("invalid_cpp_identifier").value();
}

bool is_generator_namespace_helper(const cpp::identifier &name) {
  return name.view() == "message_type_url" || name.view() == "pb_meta" || name.view() == "is_valid";
}

cpp::identifier namespace_declaration_identifier(std::string_view name, generation_diagnostics &diagnostics) {
  auto identifier = cpp_identifier(name, diagnostics);
  if (is_generator_namespace_helper(identifier)) {
    diagnostics.record(
        std::format("protobuf service '{}' collides with the generated C++ namespace API '{}'; rename the service",
                    name, identifier.view()));
  }
  return identifier;
}

cpp::identifier service_method_identifier(std::string_view name, generation_diagnostics &diagnostics) {
  auto identifier = cpp_identifier(name, diagnostics);
  const auto spelling = identifier.view();
  if (spelling == "method_name" || spelling == "client_streaming" || spelling == "server_streaming" ||
      spelling == "rpc_type" || spelling == "ordinal" || spelling == "request_t" || spelling == "response_t") {
    diagnostics.record(std::format(
        "protobuf RPC method '{}' collides with the generated C++ method metadata API '{}'; rename the method", name,
        spelling));
  }
  return identifier;
}

cpp::qualified_name cpp_qualified_name(std::string_view dotted_name, generation_diagnostics &diagnostics) {
  auto result = cpp::qualified_name::from_dotted(dotted_name);
  if (result.has_value()) {
    return std::move(*result);
  }
  diagnostics.record(result.error().message);
  return {};
}

cpp::qualified_name cpp_qualified_name(const cpp::qualified_name &namespace_prefix, std::string_view proto_name,
                                       generation_diagnostics &diagnostics) {
  auto result = cpp::qualified_name::from_proto(namespace_prefix, proto_name);
  if (result.has_value()) {
    return std::move(*result);
  }
  diagnostics.record(result.error().message);
  return {};
}

template <typename FileDescriptor>
cpp::file_descriptor_name cpp_file_descriptor_name(FileDescriptor &descriptor, generation_diagnostics &diagnostics) {
  ::hpp_proto::hpp_file_opts opts;
  std::optional<std::string_view> override;
  if (descriptor.options().get_extension(opts).ok() && opts.value.file_descriptor_name.has_value()) {
    override = opts.value.file_descriptor_name.value();
  }

  auto result = cpp::file_descriptor_name::from_proto_file(descriptor.proto().name, override);
  if (result.has_value()) {
    return std::move(*result);
  }

  diagnostics.record(
      std::format("{}: {}. Rename the .proto file or directory, or set "
                  "(hpp_proto.hpp_file_opts).file_descriptor_name to a unique C++ identifier.",
                  descriptor.proto().name, result.error().message));
  return cpp::file_descriptor_name::from_proto_file("invalid.proto").value();
}

template <typename Range>
std::string join_to_string(const Range &range, std::string_view separator) {
  std::string result;
  auto it = std::begin(range);
  auto end = std::end(range);
  if (it == end) {
    return result;
  }
  result += std::format("{}", *it);
  ++it;
  for (; it != end; ++it) {
    result += separator;
    result += std::format("{}", *it);
  }
  return result;
}

template <typename Range>
cpp::source_fragment join_source_fragments(const Range &range, const cpp::source_fragment &separator) {
  cpp::source_fragment result;
  auto it = std::begin(range);
  const auto end = std::end(range);
  if (it == end) {
    return result;
  }
  result.append(*it);
  ++it;
  for (; it != end; ++it) {
    result.append(separator).append(*it);
  }
  return result;
}

std::size_t shared_scope_position(std::string_view s1, std::string_view s2) {
  std::size_t pos = static_cast<std::size_t>(std::ranges::mismatch(s1, s2).in1 - s1.begin());
  if (pos == s1.size() && pos == s2.size()) {
    return pos;
  }
  if (pos > 0) {
    if (s1.size() > s2.size()) {
      std::swap(s1, s2);
    }
    if (pos == s1.size() && s2[pos] == '.') {
      return pos;
    }
    pos = s1.find_last_of('.', pos - 1);
    if (pos != std::string_view::npos) {
      return pos;
    }
  }
  return 0;
}

std::string_view get_common_ancestor(std::string_view s1, std::string_view s2) {
  return s1.substr(0, shared_scope_position(s1, s2));
}

} // namespace
struct hpp_addons {
  struct context_type {
    generation_context *generation = nullptr;
  };

  using traits_type = ::hpp_proto::default_traits;
  using FieldDescriptorProto = google::protobuf::FieldDescriptorProto<traits_type>;
  using FieldOptions = google::protobuf::FieldOptions<traits_type>;
  using FeatureSet = google::protobuf::FeatureSet<traits_type>;
  using OneofDescriptorProto = google::protobuf::OneofDescriptorProto<traits_type>;
  using OneofOptions = google::protobuf::OneofOptions<traits_type>;
  using EnumDescriptorProto = google::protobuf::EnumDescriptorProto<traits_type>;
  using EnumValueOptions = google::protobuf::EnumValueOptions<traits_type>;
  using EnumOptions = google::protobuf::EnumOptions<traits_type>;
  using DescriptorProto = google::protobuf::DescriptorProto<traits_type>;
  using MessageOptions = google::protobuf::MessageOptions<traits_type>;
  using FileDescriptorProto = google::protobuf::FileDescriptorProto<traits_type>;
  using FileOptions = google::protobuf::FileOptions<traits_type>;
  using FileDescriptorSet = google::protobuf::FileDescriptorSet<traits_type>;

  using string_t = std::string;
  template <typename T>
  using vector_t = std::vector<T>;

  template <typename T, typename U>
  using map_t = std::unordered_map<T, U>;

  template <typename Derived>
  struct field_descriptor {
    cpp::identifier cpp_name;
    cpp::source_fragment cpp_field_type;
    cpp::source_fragment qualified_cpp_field_type;
    cpp::source_fragment cpp_meta_type{"void"};
    cpp::source_fragment default_value;
    cpp::source_fragment default_value_template_arg;

    bool is_recursive = false;
    bool is_cpp_optional = false;
    bool is_closed_enum = false;
    bool is_foreign = false;
    bool has_dependent_nested_type = false;

    field_descriptor(const Derived &self, context_type &context, [[maybe_unused]] const auto &inherited_options,
                     [[maybe_unused]] std::pmr::memory_resource *resource)
        : cpp_name(cpp_identifier(self.proto().name, context.generation->diagnostics)) {
      set_cpp_type(self.proto());
      set_default_value(self.proto(), context.generation->diagnostics);
    }

    void set_cpp_type(const FieldDescriptorProto &proto) {
      using enum google::protobuf::FieldDescriptorProto<>::Type;
      auto assign_type = [this](cpp::source_fragment type, cpp::source_fragment meta_type) {
        cpp_field_type = std::move(type);
        qualified_cpp_field_type = cpp_field_type;
        cpp_meta_type = std::move(meta_type);
      };
      auto set_type = [&assign_type](const auto &type) {
        assign_type(cpp::source_fragment{type}, cpp::source_fragment{"void"});
      };
      auto set_type_with_meta = [&assign_type](const auto &type, const auto &meta_type) {
        assign_type(cpp::source_fragment{type}, cpp::source_fragment{meta_type});
      };
      switch (proto.type) {
      case TYPE_DOUBLE:
        set_type("double");
        break;
      case TYPE_FLOAT:
        set_type("float");
        break;
      case TYPE_INT64:
        set_type_with_meta("std::int64_t", "::hpp_proto::vint64_t");
        break;
      case TYPE_UINT64:
        set_type_with_meta("std::uint64_t", "::hpp_proto::vuint64_t");
        break;
      case TYPE_INT32:
        set_type_with_meta("std::int32_t", "::hpp_proto::vint64_t");
        break;
      case TYPE_FIXED64:
        set_type("std::uint64_t");
        break;
      case TYPE_FIXED32:
        set_type("std::uint32_t");
        break;
      case TYPE_BOOL:
        set_type_with_meta("bool", "bool");
        break;
      case TYPE_STRING:
        set_type("Traits::string_t");
        break;
      case TYPE_GROUP:
      case TYPE_MESSAGE:
      case TYPE_ENUM:
        break;
      case TYPE_BYTES:
        set_type("Traits::bytes_t");
        break;
      case TYPE_UINT32:
        set_type_with_meta("std::uint32_t", "::hpp_proto::vuint32_t");
        break;
      case TYPE_SFIXED32:
        set_type("std::int32_t");
        break;
      case TYPE_SFIXED64:
        set_type("std::int64_t");
        break;
      case TYPE_SINT32:
        set_type_with_meta("std::int32_t", "::hpp_proto::vsint32_t");
        break;
      case TYPE_SINT64:
        set_type_with_meta("std::int64_t", "::hpp_proto::vsint64_t");
        break;
      }
    }

    void set_default_value(const FieldDescriptorProto &proto, generation_diagnostics &diagnostics) {
      using enum google::protobuf::FieldDescriptorProto<>::Type;
      using enum google::protobuf::FieldDescriptorProto<>::Label;

      if (!proto.default_value.empty()) {
        if (proto.type == TYPE_STRING) {
          set_string_default_value(proto);
        } else if (proto.type == TYPE_BYTES) {
          set_bytes_default_value(proto);
        } else if (proto.type == TYPE_ENUM) {
          // set_enum_default_value(proto);
        } else if (proto.type == TYPE_DOUBLE || proto.type == TYPE_FLOAT) {
          set_numeric_default_value(cpp::numeric_literal::floating(proto.default_value, proto.type == TYPE_FLOAT),
                                    diagnostics);
        } else if (proto.type == TYPE_BOOL) {
          set_numeric_default_value(cpp::numeric_literal::boolean(proto.default_value), diagnostics);
        } else if (proto.type == TYPE_UINT32 || proto.type == TYPE_FIXED32) {
          set_numeric_default_value(
              cpp::numeric_literal::unsigned_integer(proto.default_value, cpp::integer_width::bits32), diagnostics);
        } else if (proto.type == TYPE_UINT64 || proto.type == TYPE_FIXED64) {
          set_numeric_default_value(
              cpp::numeric_literal::unsigned_integer(proto.default_value, cpp::integer_width::bits64), diagnostics);
        } else if (proto.type == TYPE_INT64 || proto.type == TYPE_SFIXED64 || proto.type == TYPE_SINT64) {
          set_numeric_default_value(
              cpp::numeric_literal::signed_integer(proto.default_value, cpp::integer_width::bits64), diagnostics);
        } else {
          set_numeric_default_value(
              cpp::numeric_literal::signed_integer(proto.default_value, cpp::integer_width::bits32), diagnostics);
        }
      }
    }

    void set_bytes_default_value(const FieldDescriptorProto &proto) {
      if (!proto.default_value.empty()) {
        default_value_template_arg =
            cpp::format("::hpp_proto::bytes_literal<{}>{{}}", cpp::string_literal_bytes{proto.default_value});
        default_value = default_value_template_arg;
      }
    }

    void set_string_default_value(const FieldDescriptorProto &proto) {
      if (!proto.default_value.empty()) {
        const cpp::string_literal_bytes literal{proto.default_value};
        default_value = cpp::format("{}", literal);
        default_value_template_arg = cpp::format("::hpp_proto::string_literal<{}>{{}}", literal);
      }
    }

    void set_enum_default_value(const FieldDescriptorProto &proto, generation_diagnostics &diagnostics) {
      const auto value = cpp_identifier(proto.default_value, diagnostics);
      default_value = cpp::format("{}::{}", cpp_field_type, value);
      default_value_template_arg = cpp::format("{}::{}", qualified_cpp_field_type, value);
    }

    void set_numeric_default_value(std::expected<cpp::numeric_literal, cpp::lexical_error> literal,
                                   generation_diagnostics &diagnostics) {
      if (!literal.has_value()) {
        diagnostics.record(literal.error().message);
        return;
      }
      default_value = cpp::format("{}", *literal);
      default_value_template_arg = default_value;
    }

    [[nodiscard]] std::string_view qualified_parent_name() const {
      auto self = static_cast<const Derived *>(this);
      if (self->parent_message()) {
        return self->parent_message()->full_name();
      }
      return {};
    }
  };

  template <typename Derived>
  struct enum_descriptor {
    cpp::identifier cpp_name;
    std::vector<int> sorted_values;
    cpp::qualified_name qualified_name;
    bool continuous = true;

    explicit enum_descriptor(Derived &self, context_type &context, [[maybe_unused]] const auto &inherited_options,
                             [[maybe_unused]] std::pmr::memory_resource *resource)
        : cpp_name(cpp_identifier(self.proto().name, context.generation->diagnostics)) {
      sorted_values.resize(self.proto().value.size());
      std::ranges::transform(self.proto().value, sorted_values.begin(), [](auto &desc) { return desc.number; });
      std::ranges::sort(sorted_values);
      for (unsigned i = 1; i < sorted_values.size(); ++i) {
        if (sorted_values[i] - sorted_values[i - 1] > 1) {
          continuous = false;
          break;
        }
      }
    }
  };

  template <typename Derived>
  struct oneof_descriptor {
    cpp::identifier cpp_name;
    cpp::identifier case_name;
    cpp::identifier number_table_name;

    explicit oneof_descriptor(Derived &self, context_type &context, [[maybe_unused]] const auto &inherited_options,
                              [[maybe_unused]] std::pmr::memory_resource *resource)
        : cpp_name(cpp_identifier(self.proto().name, context.generation->diagnostics)),
          case_name(cpp_name.append_word(cpp_identifier("oneof_case", context.generation->diagnostics))),
          number_table_name(cpp_name.append_word(cpp_identifier("oneof_numbers", context.generation->diagnostics))) {}
  };

  template <typename Derived>
  struct message_descriptor {
    std::string pb_name;
    cpp::identifier cpp_name;
    cpp::identifier nested_scope_name;
    std::vector<void *> used_by_fields;
    std::set<Derived *> dependencies;
    std::set<Derived *> forward_messages;
    cpp::source_fragment qualified_name;
    cpp::source_fragment no_namespace_qualified_name;
    bool has_recursive_map_field = false;
    bool has_non_map_nested_message = false;

    explicit message_descriptor(Derived &self, context_type &context, [[maybe_unused]] const auto &inherited_options,
                                [[maybe_unused]] std::pmr::memory_resource *resource)
        : pb_name(self.proto().name), cpp_name(cpp_identifier(self.proto().name, context.generation->diagnostics)),
          nested_scope_name(
              cpp_name.disambiguated_with(cpp_identifier("nested", context.generation->diagnostics))),
          has_non_map_nested_message(std::ranges::any_of(self.proto().nested_type, [](const DescriptorProto &submsg) {
            return !submsg.options.has_value() || !submsg.options->map_entry;
          })) {}
  };

  template <typename Derived>
  struct file_descriptor {
    std::vector<cpp::qualified_name> dependency_names;

    std::string syntax;
    cpp::qualified_name cpp_namespace;
    cpp::file_descriptor_name descriptor_name;
    cpp::qualified_name namespace_prefix;

    // NOLINTNEXTLINE(bugprone-crtp-constructor-accessibility)
    explicit file_descriptor(Derived &self, context_type &context,
                             [[maybe_unused]] std::pmr::memory_resource *resource)
        : syntax(self.proto().syntax.empty() ? std::string{"proto2"} : self.proto().syntax),
          descriptor_name(cpp_file_descriptor_name(self, context.generation->diagnostics)) {
      ::hpp_proto::hpp_file_opts opts;
      if (self.options().get_extension(opts).ok()) {
        if (opts.value.namespace_prefix.has_value()) {
          namespace_prefix =
              cpp_qualified_name(opts.value.namespace_prefix.value(), context.generation->diagnostics);
        } else if (context.generation->options.namespace_prefix.has_value()) {
          namespace_prefix = *context.generation->options.namespace_prefix;
        }
        cpp_namespace =
            cpp_qualified_name(namespace_prefix, "." + self.proto().package, context.generation->diagnostics);
      }
    }

    // NOLINTBEGIN(misc-no-recursion)
    const std::vector<cpp::qualified_name> &get_dependency_names() {
      if (dependency_names.empty()) {
        auto it = std::back_inserter(dependency_names);
        auto &self = static_cast<Derived &>(*this);
        for (auto &dep : self.dependencies()) {
          auto &names = dep.get_dependency_names();
          std::copy(names.begin(), names.end(), it);
        }
        std::ranges::sort(dependency_names);
        auto to_erase = std::ranges::unique(dependency_names.begin(), dependency_names.end());
        dependency_names.erase(to_erase.begin(), to_erase.end());
        dependency_names.push_back(descriptor_name.qualified_descriptor_name());
      }
      return dependency_names;
    }
    // NOLINTEND(misc-no-recursion)
  };
};

using hpp_gen_descriptor_pool = ::hpp_proto::descriptor_pool<hpp_addons>;
using traits_type = hpp_gen_descriptor_pool::traits_type;
using CodeGeneratorResponse = google::protobuf::compiler::CodeGeneratorResponse<traits_type>;

const static hpp_proto::flat_map<std::string, cpp::source_fragment> well_known_codecs = {
    {"google.protobuf.Duration", cpp::source_fragment{"duration_codec"}},
    {"google.protobuf.Timestamp", cpp::source_fragment{"timestamp_codec"}},
    {"google.protobuf.FieldMask", cpp::source_fragment{"field_mask_codec"}}};

struct code_generator {
  generation_context &context;
  std::size_t indent_num = 0;
  mutable std::string indent_spaces = std::string(128, ' ');
  CodeGeneratorResponse::File &file;
  std::back_insert_iterator<std::string> target;

  using message_descriptor_t = hpp_gen_descriptor_pool::message_descriptor_t;
  using enum_descriptor_t = hpp_gen_descriptor_pool::enum_descriptor_t;
  using oneof_descriptor_t = hpp_gen_descriptor_pool::oneof_descriptor_t;
  using field_descriptor_t = hpp_gen_descriptor_pool::field_descriptor_t;
  using file_descriptor_t = hpp_gen_descriptor_pool::file_descriptor_t;
  using FieldDescriptorProto = google::protobuf::FieldDescriptorProto<traits_type>;

  static message_descriptor_t *parent_message_of(auto *desc) { return desc->parent_message(); }

  static cpp::source_fragment type_as_template_arg(const cpp::source_fragment &type) {
    if (type.starts_with("Traits::")) {
      return cpp::format("typename {}", type);
    }
    return type;
  }

  explicit code_generator(std::vector<CodeGeneratorResponse::File> &files, generation_context &generation)
      : context(generation), file(files.emplace_back()), target(file.content) {}

  ~code_generator() = default;
  code_generator(const code_generator &) = delete;
  code_generator(code_generator &&) = delete;
  code_generator &operator=(const code_generator &) = delete;
  code_generator &operator=(code_generator &&) = delete;

  [[nodiscard]] std::string_view indent() const {
    if (indent_num > indent_spaces.size()) {
      indent_spaces.resize(indent_num);
    }
    return std::string_view{indent_spaces.data(), indent_num};
  }

  [[nodiscard]] cpp::source_fragment source_indent() const { return cpp::source_fragment::spaces(indent_num); }

  [[nodiscard]] std::optional<cpp::include_path> generated_include(std::string_view proto_file,
                                                                   std::string_view suffix) const {
    auto result =
        cpp::include_path::from_proto_file(proto_file, context.options.directory_prefix, suffix);
    if (!result.has_value()) {
      context.diagnostics.record(result.error().message);
      return std::nullopt;
    }
    return std::move(*result);
  }

  // NOLINTBEGIN(misc-no-recursion)
  static void mark_field_recursive(message_descriptor_t &descriptor, std::string_view dep) {
    for (auto &f : descriptor.fields()) {
      if (f.cpp_field_type.view() == dep) {
        f.is_recursive = true;
      }
    }
    for (auto &m : descriptor.messages()) {
      mark_field_recursive(m, dep);
    }
  }
  // NOLINTEND(misc-no-recursion)

  static message_descriptor_t *resolve_repeated_dependency_cycle(std::vector<message_descriptor_t *> &unresolved,
                                                                 message_descriptor_t *depended) {
    std::map<message_descriptor_t *, bool> used_by_messages;
    for (auto *f : depended->used_by_fields) {
      auto *field = static_cast<field_descriptor_t *>(f);
      auto *message = parent_message_of(field);
      if (message->parent_file() != depended->parent_file()) {
        continue;
      }
      if (std::ranges::find(unresolved, message) != unresolved.end()) {
        used_by_messages[message] |=
            (field->proto().label != hpp_gen_descriptor_pool::FieldDescriptorProto::Label::LABEL_REPEATED);
        field->is_recursive = true;
      }
    }

    for (auto [m, no_non_repeated_usage] : used_by_messages) {
      if (!no_non_repeated_usage && !m->is_map_entry()) {
        m->dependencies.erase(depended);
        m->forward_messages.insert(depended);
        return m;
      }
    }
    return nullptr;
  }

  static message_descriptor_t *resolve_map_dependency_cycle(std::vector<message_descriptor_t *> &unresolved,
                                                            message_descriptor_t *depended) {
    std::map<message_descriptor_t *, bool> used_by_messages;
    for (auto *f : depended->used_by_fields) {
      auto *field = static_cast<field_descriptor_t *>(f);
      auto *message = parent_message_of(field);
      if (message->parent_file() != depended->parent_file()) {
        continue;
      }
      if (std::ranges::find(unresolved, message) != unresolved.end() || message->is_map_entry()) {
        used_by_messages[message] |= !(message->is_map_entry());
        field->is_recursive = true;
      }
    }

    for (auto [m, no_non_map_usage] : used_by_messages) {
      if (!no_non_map_usage) {
        auto *owner = m->parent_message();
        // Only break this map edge when its owner is still unresolved (i.e.
        // genuinely part of the stalled cycle). Returning an already-resolved owner
        // makes no progress in order_messages' main loop (it is push_back'd onto
        // resolved_messages but never removed from unresolved_messages), which can
        // spin forever. Minimal repro:
        //   message A { B b = 1; }
        //   message B { A a = 1; }
        //   message Container { map<string, A> by_name = 1; }
        // The A<->B cycle stalls the sort; Container resolves early (its map value
        // is indirect, so it has no hard dependency); resolve_map_dependency_cycle
        // then keeps returning the already-resolved Container.
        if (std::ranges::find(unresolved, owner) == unresolved.end()) {
          continue;
        }
        owner->has_recursive_map_field = true;
        owner->dependencies.erase(depended);
        owner->forward_messages.insert(depended);
        return owner;
      }
    }
    return nullptr;
  }

  static message_descriptor_t *resolve_container_dependency_cycle(std::vector<message_descriptor_t *> &unresolved) {
    // First, find the dependency which used the by repeated field
    for (auto *depended : unresolved) {
      if (auto *resolved = resolve_repeated_dependency_cycle(unresolved, depended)) {
        return resolved;
      }
    }
    // find the dependency which used the by map field
    for (auto *depended : unresolved) {
      if (auto *resolved = resolve_map_dependency_cycle(unresolved, depended)) {
        return resolved;
      }
    }
    return nullptr;
  }

  static void resolve_dependency_cycle(message_descriptor_t &descriptor) {
    auto *dep = *descriptor.dependencies.begin();
    descriptor.forward_messages.insert(descriptor.dependencies.extract(descriptor.dependencies.begin()));
    mark_field_recursive(descriptor, dep->cpp_name.view());
  }

  static std::vector<message_descriptor_t *> order_messages(auto messages_view) {
    std::vector<message_descriptor_t *> resolved_messages;
    std::vector<message_descriptor_t *> unresolved_messages;
    resolved_messages.reserve(messages_view.size());
    unresolved_messages.reserve(messages_view.size());

    for (auto &m : messages_view) {
      if (m.dependencies.empty()) {
        resolved_messages.push_back(&m);
      } else {
        unresolved_messages.push_back(&m);
      }
    }

    while (!unresolved_messages.empty()) {
      for (auto &pm : std::ranges::reverse_view{unresolved_messages}) {
        auto &message_deps = pm->dependencies;
        const std::set<message_descriptor_t *> sorted_resolved_messages{resolved_messages.begin(),
                                                                        resolved_messages.end()};
        if (std::ranges::includes(sorted_resolved_messages, message_deps)) {
          resolved_messages.push_back(pm);
          pm = nullptr; // set the reference to nullptr so that it can be removed from the unresolved_messages in
                        // subsequent statement
        }
      }

      auto to_remove = std::ranges::remove(unresolved_messages.begin(), unresolved_messages.end(), nullptr);
      if (!to_remove.empty()) {
        unresolved_messages.erase(to_remove.begin(), to_remove.end());
      } else {
        auto *to_be_resolved = resolve_container_dependency_cycle(unresolved_messages);
        if (to_be_resolved != nullptr) {
          resolved_messages.push_back(to_be_resolved);
          auto to_remove = std::ranges::remove(unresolved_messages, to_be_resolved);
          unresolved_messages.erase(to_remove.begin(), to_remove.end());
        } else {
          std::ranges::sort(unresolved_messages, [](auto lhs, auto rhs) { return lhs->cpp_name < rhs->cpp_name; });
          auto *x = *(unresolved_messages.rbegin());
          resolve_dependency_cycle(*x);
        }
      }
    }
    return resolved_messages;
  }

  void gen_file_header(const std::string &file) const {
    cpp::emit_to(target,
                 "// clang-format off\n"
                 "// Generated by the protocol buffer compiler.  DO NOT EDIT!\n"
                 "// NO CHECKED-IN PROTOBUF GENCODE\n"
                 "// generation command line:\n"
                 "//    protoc --plugin=protoc-gen-hpp=/path/to/{}\n"
                 "//           --hpp_out {}:${{out_dir}}\n"
                 "//           {}\n\n",
                 cpp::comment_text{context.options.plugin_name.filename().string()},
                 cpp::comment_text{context.options.raw_parameters},
                 cpp::comment_text{file});
  }

  static auto dependencies(file_descriptor_t &descriptor) {
    return descriptor.proto().dependency |
           std::views::filter([](const auto &dep) { return dep != "hpp_proto/hpp_options.proto"; });
  }

  static void set_field_cpp_type(field_descriptor_t &field, std::string_view relative_type_name, bool is_nested,
                                 generation_diagnostics &diagnostics) {
    using enum FieldDescriptorProto::Type;
    auto type = field.proto().type;
    if (type == TYPE_ENUM) {
      field.qualified_cpp_field_type = cpp::format("{}", field.enum_field_type_descriptor()->qualified_name);
    } else {
      field.qualified_cpp_field_type = cpp::format("{}", field.message_field_type_descriptor()->qualified_name);
    }

    if (field.is_foreign) {
      field.cpp_field_type = field.qualified_cpp_field_type;
    } else if (field.is_recursive) {
      // only the last component of the type_name should be used
      field.cpp_field_type = cpp::format("{}", field.message_field_type_descriptor()->cpp_name);
    } else if (is_nested) {
      // Nested types have public aliases in the generated parent message, so retain
      // that concise spelling. Multi-level names need special treatment only when
      // emitted as template arguments, where Child::Kind is a dependent type.
      field.has_dependent_nested_type = relative_type_name.contains('.');
      field.cpp_field_type = cpp::format("{}", cpp_qualified_name(relative_type_name, diagnostics));
    } else {
      // only the components excluding the common ancestor should be used
      const auto num_components = std::ranges::count(relative_type_name, '.');
      const std::string_view v = field.qualified_cpp_field_type.view();
      auto num_colons = (2 * num_components) + 1;
      auto reverse_view = std::ranges::reverse_view(v);
      auto reverse_it =
          std::ranges::find_if(reverse_view, [&num_colons](char c) mutable { return c == ':' && (--num_colons == 0); });
      auto pos = static_cast<std::size_t>(std::distance(v.begin(), reverse_it.base()));
      field.cpp_field_type = field.qualified_cpp_field_type.substr(pos);
    }
  }

  /**
   * @brief Resolves the dependency of a field within a message descriptor pool.
   *
   * This function analyzes the relationship between a field and its parent message,
   * determining if the field refers to another message or enum type within the same
   * protobuf scope. If a dependency is found, it updates the dependent message's
   * descriptor to include the qualified name of the dependee type.
   *
   * @param pool The descriptor pool containing all message and enum descriptors.
   * @param field The field descriptor to resolve dependencies for.
   *
   * The function works by:
   * - Identifying the common ancestor scope between the field's parent message and its type.
   * - Extracting the full qualified dependent and dependee names.
   * - Locating the dependent message descriptor in the pool.
   * - If the dependent and dependee are in the same file scope, it adds the dependee
   *   to the dependent message's set of dependencies.
   */
  // NOLINTNEXTLINE(misc-no-recursion)
  static void resolve_field_dependency(hpp_gen_descriptor_pool &pool, std::string_view field_message_name,
                                       field_descriptor_t &field, generation_diagnostics &diagnostics) {
    using enum FieldDescriptorProto::Type;
    auto type = field.proto().type;
    auto field_type_name = std::string_view{field.proto().type_name}.substr(1);
    std::string_view dependee_name = field_type_name;
    if (type == TYPE_ENUM) {
      // For enum types, adjust dependee_name to refer to the parent message of the enum
      dependee_name = field_type_name.substr(0, field_type_name.find_last_of('.'));
    } else if (field.is_map_entry()) {
      auto &value_field = field.message_field_type_descriptor()->fields()[1];
      type = value_field.proto().type;
      if (type == TYPE_MESSAGE || type == TYPE_GROUP || type == TYPE_ENUM) {
        resolve_field_dependency(pool, field_message_name, value_field, diagnostics);
      }
      return;
    }

    // Find the common ancestor scope between the field's parent and its type
    auto common_ancestor = get_common_ancestor(field_message_name, dependee_name);

    // Extract the full qualified dependent and dependee names
    auto dependent_name = field_message_name.substr(0, field_message_name.find('.', common_ancestor.size() + 1));
    dependee_name = dependee_name.substr(0, dependee_name.find('.', common_ancestor.size() + 1));

    field.is_recursive = (common_ancestor.size() == dependee_name.size()) && type != TYPE_ENUM;
    field.is_foreign = (pool.get_message_descriptor(common_ancestor) == nullptr);

    auto relative_field_type =
        field_type_name.substr(common_ancestor.size() + (field_type_name.size() > common_ancestor.size() ? 1 : 0));
    set_field_cpp_type(field, relative_field_type, common_ancestor.size() == field_message_name.size(), diagnostics);

    // If the common ancestor equals dependee_name, the field's type is a nested enum of the enclosing message or a
    // file level enum. If the common ancestor equals dependent_name, the field's type is a nested message of the
    // parent message. In either case there is no external dependency to record, so return.
    if (dependee_name.size() == common_ancestor.size() || dependent_name.size() == common_ancestor.size()) {
      return;
    }
    message_descriptor_t *dependent_msg = pool.get_message_descriptor(dependent_name);
    auto *dependee_msg = pool.get_message_descriptor(dependee_name);

    if (dependent_msg != nullptr && dependee_msg != nullptr &&
        dependent_msg->parent_file() == dependee_msg->parent_file()) {
      dependent_msg->dependencies.insert(dependee_msg);
    }
  }

  static void resolve_message_field(hpp_gen_descriptor_pool &pool, field_descriptor_t &field,
                                    generation_diagnostics &diagnostics) {
    auto *parent = field.parent_message();
    if (parent == nullptr || !parent->is_map_entry()) {
      resolve_field_dependency(pool, field.qualified_parent_name(), field, diagnostics);
    }
    auto *field_type_msg = field.message_field_type_descriptor();
    field_type_msg->used_by_fields.push_back(&field);
  }

  static void resolve_enum_field(hpp_gen_descriptor_pool &pool, field_descriptor_t &field,
                                 generation_diagnostics &diagnostics) {
    resolve_field_dependency(pool, field.qualified_parent_name(), field, diagnostics);
    auto *enum_d = field.enum_field_type_descriptor();
    if (enum_d != nullptr) {
      field.is_closed_enum = enum_d->is_closed();
      if (!field.proto().default_value.empty()) {
        field.set_enum_default_value(field.proto(), diagnostics);
      } else if (field.proto().label == FieldDescriptorProto::Label::LABEL_OPTIONAL) {
        const auto proto_default_value = cpp_identifier(enum_d->proto().value[0].name, diagnostics);
        field.default_value = cpp::format("{}::{}", field.cpp_field_type, proto_default_value);
        field.default_value_template_arg = cpp::format("{}::{}", field.qualified_cpp_field_type, proto_default_value);
      }
    }
  }

  static void resolve_enum_qualified_name(enum_descriptor_t &desc, const cpp::qualified_name &scope) {
    desc.qualified_name = scope.append(desc.cpp_name);
  }

  static bool range_contains_name(auto &&range, const cpp::identifier &name) {
    return std::ranges::any_of(range, [&name](const auto &descriptor) { return descriptor.cpp_name == name; });
  }

  static bool message_schema_uses_name(message_descriptor_t &message, const cpp::identifier &name) {
    return range_contains_name(message.fields(), name) || range_contains_name(message.messages(), name) ||
           range_contains_name(message.enums(), name) || range_contains_name(message.oneofs(), name) ||
           range_contains_name(message.extensions(), name);
  }

  static bool is_fixed_message_member(const message_descriptor_t &message, const cpp::identifier &name) {
    if (name.view() == "Traits" || name.view() == "hpp_proto_traits_type" || name.view() == "unknown_fields_") {
      return true;
    }
    if (name.view() == "glaze_reflect" && well_known_codecs.contains(std::string{message.full_name()})) {
      return true;
    }
    return !message.proto().extension_range.empty() &&
           (name.view() == "get_extension" || name.view() == "set_extension" || name.view() == "has_extension");
  }

  static bool is_fixed_extension_member(const cpp::identifier &name) {
    return name.view() == "Traits" || name.view() == "value_type" || name.view() == "value" || name.view() == "pb_meta";
  }

  static void validate_enum_values(const enum_descriptor_t &enumeration, generation_diagnostics &diagnostics) {
    std::map<std::string, std::string_view> values;
    for (const auto &value : enumeration.proto().value) {
      const auto cpp_name = cpp_identifier(value.name, diagnostics);
      const auto [existing, inserted] = values.emplace(cpp_name.str(), value.name);
      if (!inserted) {
        diagnostics.record(
            std::format("protobuf enum values '{}' and '{}' in enum '{}' both map to C++ name '{}'; rename one value",
                        existing->second, value.name, enumeration.full_name(), cpp_name.view()));
      }
    }
  }

  static void report_name_collision(const message_descriptor_t &message, const cpp::identifier &name,
                                    std::string_view generated_api, generation_diagnostics &diagnostics) {
    diagnostics.record(
        std::format("protobuf declaration in message '{}' maps to C++ name '{}', which collides with {}; rename the "
                    "protobuf declaration",
                    message.full_name(), name.view(), generated_api));
  }

  static void validate_message_members(message_descriptor_t &message, generation_diagnostics &diagnostics) {
    std::map<std::string, std::string_view> names;
    auto validate_range = [&message, &names, &diagnostics](auto &&range, std::string_view declaration_kind,
                                                           bool namespace_declaration, bool extension_declaration) {
      for (const auto &descriptor : range) {
        if (is_fixed_message_member(message, descriptor.cpp_name)) {
          report_name_collision(message, descriptor.cpp_name, "a generated message member", diagnostics);
        }
        if (namespace_declaration && is_generator_namespace_helper(descriptor.cpp_name)) {
          report_name_collision(message, descriptor.cpp_name, "a generated namespace function", diagnostics);
        }
        if (extension_declaration && is_fixed_extension_member(descriptor.cpp_name)) {
          report_name_collision(message, descriptor.cpp_name, "a generated extension member", diagnostics);
        }
        if (descriptor.cpp_name == message.cpp_name) {
          report_name_collision(message, descriptor.cpp_name, "the enclosing C++ class name", diagnostics);
        }
        const auto [existing, inserted] = names.emplace(descriptor.cpp_name.str(), declaration_kind);
        if (!inserted) {
          diagnostics.record(
              std::format("protobuf {} and {} in message '{}' both map to C++ name '{}'; rename one declaration",
                          existing->second, declaration_kind, message.full_name(), descriptor.cpp_name.view()));
        }
      }
    };

    validate_range(message.fields(), "field", false, false);
    validate_range(message.messages(), "nested message", true, false);
    validate_range(message.enums(), "nested enum", true, false);
    validate_range(message.oneofs(), "oneof", false, false);
    validate_range(message.extensions(), "extension", false, true);
  }

  static void validate_oneof_helpers(message_descriptor_t &message, generation_diagnostics &diagnostics) {
    for (auto &oneof : message.oneofs()) {
      oneof.case_name = oneof.cpp_name.append_word(cpp_identifier("oneof_case", diagnostics));
      oneof.number_table_name = oneof.cpp_name.append_word(cpp_identifier("oneof_numbers", diagnostics));
      if (oneof.case_name == message.cpp_name || message_schema_uses_name(message, oneof.case_name)) {
        report_name_collision(message, oneof.case_name, "a generated oneof case type", diagnostics);
      }
      if (oneof.number_table_name == message.cpp_name || message_schema_uses_name(message, oneof.number_table_name)) {
        report_name_collision(message, oneof.number_table_name, "a generated oneof number table", diagnostics);
      }
    }
  }

  template <typename Messages, typename Enums, typename Extensions>
  static void validate_namespace_declarations(Messages messages, Enums enums, Extensions extensions,
                                              std::string_view scope, generation_diagnostics &diagnostics) {
    std::map<std::string, std::string> declarations;
    const auto add = [&declarations, scope, &diagnostics](const cpp::identifier &name, std::string description) {
      const auto [existing, inserted] = declarations.emplace(name.str(), description);
      if (!inserted) {
        diagnostics.record(
            std::format("generated C++ declarations '{}' and '{}' both use name '{}' in {}; rename one protobuf "
                        "declaration",
                        existing->second, description, name.view(), scope));
      }
    };

    for (const auto &message : messages) {
      add(message.cpp_name, std::format("message {}", message.full_name()));
      add(message.nested_scope_name, std::format("nested namespace for message {}", message.full_name()));
    }
    for (const auto &enumeration : enums) {
      add(enumeration.cpp_name, std::format("enum {}", enumeration.full_name()));
    }
    for (const auto &extension : extensions) {
      add(extension.cpp_name, std::format("extension {}", extension.proto().name));
    }
  }

  // NOLINTNEXTLINE(misc-no-recursion)
  static void validate_generated_names(message_descriptor_t &message, generation_diagnostics &diagnostics) {
    if (is_fixed_message_member(message, message.cpp_name) || is_generator_namespace_helper(message.cpp_name)) {
      report_name_collision(message, message.cpp_name, "the generated message class API", diagnostics);
    }
    validate_message_members(message, diagnostics);
    validate_oneof_helpers(message, diagnostics);
    message.nested_scope_name = message.cpp_name.disambiguated_with(cpp_identifier("nested", diagnostics));
    validate_namespace_declarations(message.messages(), message.enums(), message.extensions(),
                                    std::format("the nested namespace for message '{}'", message.full_name()),
                                    diagnostics);
    for (const auto &enumeration : message.enums()) {
      validate_enum_values(enumeration, diagnostics);
    }
    for (auto &nested : message.messages()) {
      validate_generated_names(nested, diagnostics);
    }
  }

  // Name validation intentionally walks every declaration kind in one pass so
  // all top-level C++ scopes share the same collision table.
  // NOLINTNEXTLINE(readability-function-cognitive-complexity)
  static void validate_generated_names(hpp_gen_descriptor_pool &pool, generation_diagnostics &diagnostics) {
    std::map<std::string, std::map<std::string, std::string>> namespace_declarations;
    std::map<std::string, std::string> namespace_packages;
    const auto add_namespace_declaration =
        [&namespace_declarations, &diagnostics](const cpp::qualified_name &cpp_namespace,
                                                const cpp::identifier &name, std::string description) {
      if (cpp_namespace.empty() && name.view().starts_with('_')) {
        diagnostics.record(
            std::format("protobuf declaration '{}' maps to C++ global name '{}', which is reserved; rename the "
                        "protobuf declaration or add a package",
                        description, name.view()));
      }
      auto &declarations = namespace_declarations[cpp_namespace.str()];
      const auto [existing, inserted] = declarations.emplace(name.str(), description);
      if (!inserted) {
        const auto scope = cpp_namespace.empty() ? std::string{"the global namespace"}
                                                 : std::format("C++ namespace '{}'", cpp_namespace.view());
        diagnostics.record(
            std::format("generated C++ declarations '{}' and '{}' both use name '{}' in {}; rename one protobuf "
                        "declaration",
                        existing->second, description, name.view(), scope));
      }
    };

    for (auto &file : pool.files()) {
      if (file.cpp_namespace.view().starts_with('_')) {
        diagnostics.record(
            std::format("protobuf package '{}' maps to implementation-reserved global C++ namespace '{}'; rename the "
                        "package or set a non-reserved namespace_prefix",
                        file.proto().package, file.cpp_namespace.view()));
      }
      const auto [existing_package, package_inserted] =
          namespace_packages.emplace(file.cpp_namespace.str(), file.proto().package);
      if (!package_inserted && existing_package->second != file.proto().package) {
        diagnostics.record(
            std::format("protobuf packages '{}' and '{}' both map to C++ namespace '{}'; rename one package",
                        existing_package->second, file.proto().package, file.cpp_namespace.view()));
      }
      for (const auto &message : file.messages()) {
        add_namespace_declaration(file.cpp_namespace, message.cpp_name, std::format("message {}", message.full_name()));
        add_namespace_declaration(file.cpp_namespace, message.nested_scope_name,
                                  std::format("nested namespace for message {}", message.full_name()));
      }
      for (auto &extension : file.extensions()) {
        add_namespace_declaration(file.cpp_namespace, extension.cpp_name,
                                  std::format("extension {}", extension.proto().name));
        if (is_fixed_extension_member(extension.cpp_name) || is_generator_namespace_helper(extension.cpp_name)) {
          diagnostics.record(
              std::format("protobuf extension '{}' maps to generated C++ API name '{}'; rename the extension",
                          extension.proto().name, extension.cpp_name.view()));
        }
      }
      for (auto &enumeration : file.enums()) {
        validate_enum_values(enumeration, diagnostics);
        add_namespace_declaration(file.cpp_namespace, enumeration.cpp_name,
                                  std::format("enum {}", enumeration.full_name()));
        if (is_generator_namespace_helper(enumeration.cpp_name)) {
          diagnostics.record(
              std::format("protobuf enum '{}' maps to generated C++ namespace API name '{}'; rename the enum",
                          enumeration.full_name(), enumeration.cpp_name.view()));
        }
      }
      for (const auto &service : file.proto().service) {
        if (service.method.empty()) {
          continue;
        }
        const auto service_name = namespace_declaration_identifier(service.name, diagnostics);
        add_namespace_declaration(file.cpp_namespace, service_name, std::format("service {}", service.name));

        std::map<std::string, std::string_view> methods;
        for (const auto &method : service.method) {
          const auto method_name = service_method_identifier(method.name, diagnostics);
          const auto [existing, inserted] = methods.emplace(method_name.str(), method.name);
          if (!inserted) {
            diagnostics.record(
                std::format("protobuf RPC methods '{}' and '{}' in service '{}' both map to C++ name '{}'; rename "
                            "one method",
                            existing->second, method.name, service.name, method_name.view()));
          }
        }
      }
      for (auto &message : file.messages()) {
        validate_generated_names(message, diagnostics);
      }
    }
  }

  struct file_descriptor_entity {
    cpp::qualified_name name;
    std::string_view proto_file;
  };

  static bool qualified_entity_is_prefix_of(std::string_view entity, std::string_view name) {
    return name.size() > entity.size() + 1U && name.starts_with(entity) && name.substr(entity.size()).starts_with("::");
  }

  static void validate_file_descriptor_names(const hpp_gen_descriptor_pool &pool,
                                             generation_diagnostics &diagnostics) {
    std::vector<file_descriptor_entity> entities;
    for (const auto &file : pool.files()) {
      if (file.messages().empty()) {
        continue;
      }
      entities.push_back({.name = file.descriptor_name.qualified_descriptor_name(), .proto_file = file.proto().name});
      entities.push_back(
          {.name = file.descriptor_name.qualified_descriptor_set_name(), .proto_file = file.proto().name});
    }

    const auto collide = [](const file_descriptor_entity &first, const file_descriptor_entity &second) {
      const auto first_name = first.name.view();
      const auto second_name = second.name.view();
      return first_name == second_name || qualified_entity_is_prefix_of(first_name, second_name) ||
             qualified_entity_is_prefix_of(second_name, first_name);
    };
    const auto report = [&diagnostics](const file_descriptor_entity &first, const file_descriptor_entity &second) {
      diagnostics.record(
          std::format("generated C++ file descriptor declarations collide:\n"
                      "  {} -> ::{}\n"
                      "  {} -> ::{}\n"
                      "Rename one .proto file or directory, or set "
                      "(hpp_proto.hpp_file_opts).file_descriptor_name to a unique C++ identifier.",
                      first.proto_file, first.name.view(), second.proto_file, second.name.view()));
    };

    for (auto first = entities.begin(); first != entities.end(); ++first) {
      for (auto second = std::next(first); second != entities.end(); ++second) {
        if (collide(*first, *second)) {
          report(*first, *second);
          return;
        }
      }
    }
  }

  struct message_name_scope {
    cpp::qualified_name namespace_prefix;
    cpp::qualified_name nesting;
  };

  // NOLINTNEXTLINE(misc-no-recursion)
  static void resolve_message_qualified_name(message_descriptor_t &msg, const message_name_scope &scope) {
    const auto unqualified_name = scope.nesting.append(msg.cpp_name);
    msg.qualified_name = cpp::format("{}<Traits>", scope.namespace_prefix.append(unqualified_name));
    msg.no_namespace_qualified_name = cpp::format("{}<Traits>", unqualified_name);

    const message_name_scope nested_scope = {
        .namespace_prefix = scope.namespace_prefix,
        .nesting = scope.nesting.append(msg.nested_scope_name),
    };

    for (auto &nested_msg : msg.messages()) {
      resolve_message_qualified_name(nested_msg, nested_scope);
    }

    const auto nested_enum_scope = nested_scope.namespace_prefix.append(nested_scope.nesting);
    for (auto &nested_enum : msg.enums()) {
      resolve_enum_qualified_name(nested_enum, nested_enum_scope);
    }
  }

  static void resolve_message_dependencies(hpp_gen_descriptor_pool &pool, generation_diagnostics &diagnostics) {
    validate_generated_names(pool, diagnostics);
    for (auto &file : pool.files()) {
      for (auto &msg : file.messages()) {
        resolve_message_qualified_name(msg, {.namespace_prefix = file.cpp_namespace, .nesting = cpp::qualified_name{}});
      }
      for (auto &desc : file.enums()) {
        resolve_enum_qualified_name(desc, file.cpp_namespace);
      }
    }

    for (auto &field : pool.fields()) {
      using enum FieldDescriptorProto::Type;
      switch (field.proto().type) {
      case TYPE_MESSAGE:
      case TYPE_GROUP:
        resolve_message_field(pool, field, diagnostics);
        break;
      case TYPE_ENUM:
        resolve_enum_field(pool, field, diagnostics);
        break;
      default:
        break;
      };
    }
  }
};

struct msg_code_generator : code_generator {
  std::string syntax;
  std::string out_of_class_data;
  std::back_insert_iterator<std::string> out_of_class_target;
  std::string out_of_ns_data;
  std::back_insert_iterator<std::string> out_of_ns_target;

  explicit msg_code_generator(std::vector<CodeGeneratorResponse::File> &files, generation_context &generation)
      : code_generator(files, generation), out_of_class_target(out_of_class_data),
        out_of_ns_target(out_of_ns_data) {}

  void process(file_descriptor_t &descriptor) {
    syntax = descriptor.syntax;
    auto file_name = descriptor.proto().name;
    gen_file_header(file_name);
    file.name = file_name.substr(0, file_name.size() - proto_suffix_length) + "msg.hpp";
    format_to(target, "#pragma once\n\n"
                      "#include <hpp_proto/field_types.hpp>\n");

    for (const auto &d : dependencies(descriptor)) {
      auto include = generated_include(d, ".msg.hpp");
      if (!include.has_value()) {
        return;
      }
      cpp::emit_to(target, "#include {}\n", *include);
    }
    format_to(target, "// @@protoc_insertion_point(includes)\n\n");

    const auto &ns = descriptor.cpp_namespace;
    if (!ns.empty()) {
      cpp::emit_to(target,
                   "\nnamespace {} {{\n"
                   "// Generated message headers mirror protobuf schema literals and generated special members.\n"
                   "//NOLINTBEGIN(performance-enum-size,misc-const-correctness,cppcoreguidelines-avoid-magic-numbers,"
                   "readability-magic-numbers,bugprone-exception-escape,modernize-raw-string-literal,"
                   "clang-analyzer-optin.performance.Padding)\n\n",
                   ns);
    }

    for (auto &e : descriptor.enums()) {
      process(e);
    }

    for (auto *m : order_messages(descriptor.messages())) {
      process(*m, descriptor.proto().package);
    }

    std::ranges::copy(out_of_class_data, target);

    if (!ns.empty()) {
      cpp::emit_to(target,
                   "// NOLINTEND(performance-enum-size,misc-const-correctness,cppcoreguidelines-avoid-magic-numbers,"
                   "readability-magic-numbers,bugprone-exception-escape,modernize-raw-string-literal,"
                   "clang-analyzer-optin.performance.Padding)\n"
                   "}} // namespace {}\n",
                   ns);

      std::ranges::copy(out_of_ns_data, target);
      format_to(target, "// clang-format on\n");
    }
  }

  static cpp::source_fragment field_type_wrapper(field_descriptor_t &descriptor) {
    const auto &proto = descriptor.proto();
    using enum FieldDescriptorProto::Label;
    using enum FieldDescriptorProto::Type;
    if (proto.label == LABEL_REPEATED) {
      return descriptor.is_recursive ? cpp::source_fragment{"Traits::template recursive_repeated_t"}
                                     : cpp::source_fragment{"Traits::template repeated_t"};
    }
    if (proto.type == TYPE_GROUP || proto.type == TYPE_MESSAGE) {
      if (descriptor.is_recursive) {
        return cpp::source_fragment{"Traits::template optional_indirect_t"};
      }
      if (descriptor.is_cpp_optional) {
        return cpp::source_fragment{"std::optional"};
      }
    } else if (descriptor.is_cpp_optional) {
      return cpp::source_fragment{"::hpp_proto::optional"};
    }
    return {};
  }

  static cpp::source_fragment field_template_argument_type(field_descriptor_t &descriptor) {
    // A multi-level nested type such as Child::Kind is dependent when reached
    // through the generated Child<Traits> alias. Use its resolved spelling in
    // template argument lists instead of exposing a redundant qualification in
    // ordinary member declarations.
    const auto &type = descriptor.has_dependent_nested_type ? descriptor.qualified_cpp_field_type
                                                            : descriptor.cpp_field_type;
    return type_as_template_arg(type);
  }

  static cpp::source_fragment field_type(field_descriptor_t &descriptor) {
    if (descriptor.is_map_entry()) {
      auto *type_desc = descriptor.message_field_type_descriptor();
      if (type_desc->fields()[1].is_recursive) {
        return cpp::format("Traits::template map_t<{}, typename Traits::template indirect_t<{}>>",
                           field_template_argument_type(type_desc->fields().front()),
                           type_desc->fields()[1].cpp_field_type);
      }
      return cpp::format("Traits::template map_t<{}, {}>", field_template_argument_type(type_desc->fields().front()),
                         field_template_argument_type(type_desc->fields()[1]));
    }

    auto wrapper = field_type_wrapper(descriptor);

    if (wrapper.view() == "::hpp_proto::optional" && !descriptor.default_value_template_arg.empty()) {
      return cpp::format("::hpp_proto::optional<{0}, {1}>", field_template_argument_type(descriptor),
                         descriptor.default_value_template_arg);
    }
    if (!wrapper.empty()) {
      return cpp::format("{}<{}>", wrapper, field_template_argument_type(descriptor));
    }
    return descriptor.cpp_field_type;
  }

  static bool needs_indirect_oneof_alternative(field_descriptor_t &descriptor) {
    using enum FieldDescriptorProto::Type;
    auto type = descriptor.proto().type;
    if (type != TYPE_MESSAGE && type != TYPE_GROUP) {
      return false;
    }

    auto *parent = descriptor.parent_message();
    auto *message_type = descriptor.message_field_type_descriptor();
    return parent != nullptr && message_type != nullptr && message_type->forward_messages.contains(parent);
  }

  static cpp::source_fragment oneof_field_type(field_descriptor_t &descriptor) {
    if (needs_indirect_oneof_alternative(descriptor)) {
      return cpp::format(
          "std::conditional_t<std::same_as<Traits, ::hpp_proto::non_owning_traits>, {0}, typename Traits::template "
          "indirect_t<{0}>>",
          field_template_argument_type(descriptor));
    }
    return field_template_argument_type(descriptor);
  }

  void set_presence_rule(field_descriptor_t &descriptor) const {
    using enum FieldDescriptorProto::Type;
    using enum FieldDescriptorProto::Label;
    std::string qualified_name = std::string{descriptor.qualified_parent_name()} + "." + descriptor.proto().name;

    descriptor.is_cpp_optional =
        (syntax != "proto2" || context.options.proto2_explicit_presences.empty())
            ? descriptor.explicit_presence()
            : (descriptor.proto().label == LABEL_OPTIONAL &&
               (descriptor.proto().type == TYPE_MESSAGE || descriptor.proto().type == TYPE_GROUP ||
                std::ranges::any_of(context.options.proto2_explicit_presences, [&qualified_name](const auto &s) {
                  return qualified_name.starts_with(std::string_view{s}.substr(1));
                })));
  }

  void process(field_descriptor_t &descriptor) {
    set_presence_rule(descriptor);
    cpp::source_fragment initializer{" = {}"};
    using enum FieldDescriptorProto::Type;

    if (field_type_wrapper(descriptor).size() > 1 || descriptor.proto().type == TYPE_STRING ||
        descriptor.proto().type == TYPE_BYTES) {
      initializer = {};
    } else if (!descriptor.default_value.empty()) {
      initializer = cpp::format(" = {}", descriptor.default_value);
    }
    cpp::emit_to(target, "{}{} {}{};\n", source_indent(), field_type(descriptor), descriptor.cpp_name, initializer);
  }

  void process(oneof_descriptor_t &descriptor, std::int32_t number) {
    auto fields = descriptor.fields();
    if (number != fields[0].proto().number) {
      return;
    }

    if (fields.size() > 1) {
      cpp::source_fragment types;

      cpp::emit_to(target,
                   "{0}// NOLINTNEXTLINE(cppcoreguidelines-use-enum-class)\n"
                   "{0}enum {1} : int {{\n",
                   source_indent(), descriptor.case_name);
      indent_num += 2;
      std::size_t index = 1;
      for (auto &f : fields) {
        const auto sep = index != fields.size() ? cpp::source_fragment{","} : cpp::source_fragment{};
        cpp::emit_to(target, "{}{} = {}{}\n", source_indent(), f.cpp_name, index++, sep);
      }
      indent_num -= 2;
      format_to(target, "{}}};\n\n", indent());
      cpp::emit_to(target,
                   "{}static constexpr std::array<std::uint32_t, {}> {}{{\n"
                   "{}  0U",
                   source_indent(), fields.size() + 1, descriptor.number_table_name, source_indent());

      for (auto &f : fields) {
        format_to(target, ", {}U", f.proto().number);
        types.append(cpp::format(", {}", oneof_field_type(f)));
      }
      format_to(target, "}};\n");
      format_to(target, "{}// NOLINTNEXTLINE(readability-redundant-typename)\n", indent());
      cpp::emit_to(target, "{}std::variant<std::monostate{}> {};\n", source_indent(), types, descriptor.cpp_name);
    } else {
      auto &f = fields[0];
      cpp::emit_to(target, "{}std::optional<{}> {};\n", source_indent(), field_template_argument_type(f),
                   f.cpp_name);
    }
  }

  void process(enum_descriptor_t &descriptor) {
    cpp::emit_to(target, "{}enum class {} {{\n", source_indent(), descriptor.cpp_name);
    indent_num += 2;
    std::size_t index = 0;
    for (const auto &e : descriptor.proto().value) {
      const auto sep =
          (index++ == descriptor.proto().value.size() - 1) ? cpp::source_fragment{} : cpp::source_fragment{","};
      cpp::emit_to(target, "{}{} = {}{}\n", source_indent(), cpp_identifier(e.name, context.diagnostics), e.number,
                   sep);
    }

    indent_num -= 2;
    format_to(target, "{}}};\n\n", indent());

    cpp::emit_to(target, "{}constexpr bool is_valid({} value){{\n", source_indent(), descriptor.cpp_name);
    if (descriptor.sorted_values.empty()) {
      format_to(target, "{}  return false;\n", indent());
    } else {
      format_to(target, "{}  int v = static_cast<int>(value);\n", indent());
      if (descriptor.continuous) {
        format_to(target, "{}  return v >= {} && v <= {};\n", indent(), descriptor.sorted_values.front(),
                  descriptor.sorted_values.back());
      } else {
        format_to(target,
                  "{0}  constexpr std::array<int, {1}> valid_values{{{2}}};\n"
                  "{0}  return std::ranges::any_of(valid_values, [v](int u){{ return u==v; }});\n",
                  indent(), descriptor.proto().value.size(), join_to_string(descriptor.sorted_values, ","));
      }
    }
    format_to(target, "{}}}\n\n", indent());
  }

  // NOLINTBEGIN(misc-no-recursion,readability-function-cognitive-complexity)
  void process(message_descriptor_t &descriptor, const std::string &pb_scope) {
    if (descriptor.is_map_entry()) {
      return;
    }

    if (!pb_scope.empty()) {
      descriptor.pb_name = pb_scope + "." + descriptor.pb_name;
    }

    for (const auto *fwd : descriptor.forward_messages) {
      cpp::emit_to(target,
                   "{0}template <typename Traits>\n"
                   "{0}struct {1};\n",
                   source_indent(), fwd->cpp_name);
    }

    if (!descriptor.enums().empty() || descriptor.has_non_map_nested_message) {
      cpp::emit_to(target, "{}namespace {} {{\n", source_indent(), descriptor.nested_scope_name);
      indent_num += 2;
      for (auto &e : descriptor.enums()) {
        process(e);
      }

      for (auto *m : order_messages(descriptor.messages())) {
        process(*m, descriptor.pb_name);
      }

      indent_num -= 2;
      cpp::emit_to(target, "{}}} //namespace {}\n\n", source_indent(), descriptor.nested_scope_name);
    }

    cpp::emit_to(target,
                 "{0}template <typename Traits = ::hpp_proto::default_traits>\n"
                 "{0}struct {1} {{\n",
                 source_indent(), descriptor.cpp_name);
    indent_num += 2;
    format_to(target, "{}using hpp_proto_traits_type = Traits;\n", indent());
    for (auto &e : descriptor.enums()) {
      cpp::emit_to(target, "{}using {} = {};\n", source_indent(), e.cpp_name, e.qualified_name);
    }

    if (well_known_codecs.contains(descriptor.pb_name)) {
      format_to(target, "\n{}constexpr static bool glaze_reflect = false;\n\n", indent());
    }

    for (auto &m : descriptor.messages()) {
      if (!m.is_map_entry()) {
        cpp::emit_to(target, "{0}using {1} = {2}::{1}<Traits>;\n\n", source_indent(), m.cpp_name,
                     descriptor.nested_scope_name);
      }
    }

    for (auto &f : descriptor.fields()) {
      set_presence_rule(f);
      if (!f.proto().oneof_index.has_value()) {
        process(f);
      } else {
        auto index = *f.proto().oneof_index;
        process(descriptor.oneofs()[index], f.proto().number);
      }
    }

    for (auto &f : descriptor.extensions()) {
      cpp::emit_to(target, "\n{}struct {};\n", source_indent(), f.cpp_name);
    }

    if (descriptor.proto().extension_range.empty()) {
      format_to(target,
                "\n"
                "{0}[[no_unique_address]] ::hpp_proto::pb_unknown_fields<Traits> unknown_fields_;",
                indent());
    } else {
      cpp::emit_to(target,
                   "\n"
                   "{0}::hpp_proto::pb_extensions<Traits> unknown_fields_;\n\n"
                   "{0}[[nodiscard]] ::hpp_proto::status get_extension(auto &ext, "
                   "::hpp_proto::concepts::is_option_type auto && "
                   "...option) const {{\n"
                   "{0}  return ext.get_from(*this, std::forward<decltype(option)>(option)...);\n"
                   "{0}}}\n"
                   "{0}[[nodiscard]] auto set_extension(const auto &ext,\n"
                   "{0}                                 ::hpp_proto::concepts::is_option_type auto &&...option) {{\n"
                   "{0}  return ext.set_to(*this, std::forward<decltype(option)>(option)...);\n"
                   "{0}}}\n"
                   "{0}[[nodiscard]] bool has_extension(const auto &ext) const {{\n"
                   "{0}  return ext.in(*this);\n"
                   "{0}}}\n",
                   source_indent(), descriptor.cpp_name);
    }

    cpp::emit_to(target, "\n{0}bool operator == (const {1}&) const = default;\n", source_indent(), descriptor.cpp_name);

    indent_num -= 2;
    format_to(target, "{}}};\n\n", indent());
    const auto &qualified_name = descriptor.no_namespace_qualified_name;
    const auto typename_prefix =
        qualified_name.ends_with(">") ? cpp::source_fragment{} : cpp::source_fragment{"typename "};
    const cpp::string_literal_bytes type_url{std::string{"type.googleapis.com/"} + descriptor.pb_name};
    cpp::emit_to(out_of_class_target,
                 "template <typename Traits>\n"
                 "constexpr auto message_type_url(const {0}{1}& /*unused*/) {{ return "
                 "::hpp_proto::string_literal<{2}>{{}}; }}\n",
                 typename_prefix, qualified_name, type_url);
    cpp::emit_to(out_of_ns_target,
                 "template <typename Traits>\n"
                 "struct hpp_proto::is_hpp_generated<{0}{1}> : std::true_type {{}};\n",
                 typename_prefix, descriptor.qualified_name);
  }

  // NOLINTEND(misc-no-recursion,readability-function-cognitive-complexity)
};

struct hpp_meta_generator : code_generator {
  std::string syntax;
  using code_generator::code_generator;

  void process(file_descriptor_t &descriptor) {
    auto file_name = descriptor.proto().name;
    gen_file_header(file_name);
    file.name = file_name.substr(0, file_name.size() - proto_suffix_length) + "pb.hpp";

    syntax = descriptor.syntax;
    auto own_msg_include = generated_include(descriptor.proto().name, ".msg.hpp");
    if (!own_msg_include.has_value()) {
      return;
    }
    cpp::emit_to(target,
                 "#pragma once\n\n"
                 "#include <hpp_proto/binpb.hpp>\n"
                 "#include {}\n",
                 *own_msg_include);
    for (const auto &d : descriptor.proto().dependency) {
      if (d != "hpp_proto/hpp_options.proto") {
        auto include = generated_include(d, ".pb.hpp");
        if (!include.has_value()) {
          return;
        }
        cpp::emit_to(target, "#include {}\n", *include);
      }
    }

    format_to(target, "\n");

    auto package = descriptor.proto().package;
    auto ns = cpp_qualified_name(descriptor.namespace_prefix, "." + package, context.diagnostics);

    if (!ns.empty()) {
      cpp::emit_to(target, "\nnamespace {} {{\n\n", ns);
    }
    format_to(target, "// Generated protobuf metadata is intentionally made of schema field numbers.\n"
                      "//NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,"
                      "bugprone-exception-escape)\n\n");

    for (auto &m : descriptor.messages()) {
      process(m, package);
    }

    for (auto &f : descriptor.extensions()) {
      format_extension(f);
    }

    format_to(target, "//NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,"
                      "bugprone-exception-escape)\n");
    if (!ns.empty()) {
      cpp::emit_to(target, "}} // namespace {}\n", ns);
    }

    format_to(target, "// clang-format on\n");
  }

  // NOLINTBEGIN(misc-no-recursion)
  void process(message_descriptor_t &descriptor, const std::string &pb_scope) {
    std::string pb_name = descriptor.proto().name;
    if (!pb_scope.empty()) {
      pb_name = pb_scope + "." + pb_name;
    }

    auto &qualified_name = descriptor.no_namespace_qualified_name;

    cpp::emit_to(target,
                 "{0}template <typename Traits>\n"
                 "{0}auto pb_meta(const {1}<Traits> &) -> std::tuple<\n",
                 source_indent(), descriptor.cpp_name);
    indent_num += 2;

    for (auto &f : descriptor.fields()) {
      if (!f.proto().oneof_index.has_value()) {
        process(f, 0UL);
      } else {
        auto index = *f.proto().oneof_index;
        auto &oneof = descriptor.oneofs()[index];
        if (oneof.fields()[0].proto().number == f.proto().number) {
          process(oneof, descriptor);
        }
      }
    }

    if (!descriptor.proto().extension_range.empty() || !descriptor.fields().empty()) {
      cpp::emit_to(target, "{}::hpp_proto::field_meta<UINT32_MAX, &{}::unknown_fields_>", source_indent(),
                   qualified_name);
    }
    indent_num -= 2;

    format_to(target, ">;\n\n");

    if (descriptor.has_non_map_nested_message) {
      cpp::emit_to(target, "{}namespace {} {{\n", source_indent(), descriptor.nested_scope_name);
      indent_num += 2;

      for (auto &m : descriptor.messages()) {
        if (!m.is_map_entry()) {
          process(m, pb_name);
        }
      }
      indent_num -= 2;
      cpp::emit_to(target, "{}}} //namespace {}\n\n", source_indent(), descriptor.nested_scope_name);
    }

    for (auto &f : descriptor.extensions()) {
      format_extension(f);
    }
  }

  static bool emit_closed_enum_validation(const field_descriptor_t &descriptor) {
    using enum google::protobuf::FieldDescriptorProto<>::Label;
    if (!descriptor.is_closed_enum) {
      return false;
    }

    const auto *parent = descriptor.parent_message();
    const bool is_unwrapped_singular_field = descriptor.extendee_descriptor() == nullptr && parent != nullptr &&
                                             !parent->is_map_entry() && descriptor.proto().label == LABEL_OPTIONAL &&
                                             !descriptor.proto().oneof_index.has_value() && !descriptor.is_cpp_optional;

    // protoc does not permit a closed enum with implicit presence. When hpp-gen deliberately flattens a proto2
    // optional enum into a scalar, give that C++ representation open-enum wire behavior. The generated is_valid()
    // function remains available for applications that need to enforce the schema's closed value set.
    return !is_unwrapped_singular_field;
  }

  static std::vector<cpp::source_fragment> meta_options(const field_descriptor_t &descriptor) {
    std::vector<cpp::source_fragment> options;
    using enum google::protobuf::FieldDescriptorProto<>::Label;
    const bool is_oneof_alternative = descriptor.proto().oneof_index.has_value();
    const bool is_optional_closed_enum_extension = descriptor.is_closed_enum &&
                                                   descriptor.extendee_descriptor() != nullptr &&
                                                   descriptor.proto().label == LABEL_OPTIONAL;
    if (descriptor.is_cpp_optional || descriptor.is_required() || is_oneof_alternative ||
        is_optional_closed_enum_extension) {
      options.emplace_back("::hpp_proto::field_option::explicit_presence");
    } else if (descriptor.is_packed()) {
      options.emplace_back("::hpp_proto::field_option::is_packed");
    }

    if (descriptor.is_delimited()) {
      options.emplace_back("::hpp_proto::field_option::group");
    } else if (descriptor.requires_utf8_validation()) {
      options.emplace_back("::hpp_proto::field_option::utf8_validation");
    } else if (emit_closed_enum_validation(descriptor)) {
      options.emplace_back("::hpp_proto::field_option::closed_enum");
    } else if (options.empty()) {
      options.emplace_back("::hpp_proto::field_option::none");
    }
    return options;
  }
  // NOLINTEND(misc-no-recursion)
  // NOLINTBEGIN(readability-function-cognitive-complexity)
  void process(field_descriptor_t &descriptor, std::size_t oneof_index) {
    auto options = meta_options(descriptor);
    auto proto = descriptor.proto();
    using enum google::protobuf::FieldDescriptorProto<>::Label;
    using enum google::protobuf::FieldDescriptorProto<>::Type;

    if (descriptor.is_map_entry()) {
      auto get_meta_type = [](const auto &field) {
        return field.cpp_meta_type.view() == "void" ? field.qualified_cpp_field_type : field.cpp_meta_type;
      };
      auto *type_desc = descriptor.message_field_type_descriptor();
      const auto key_options = join_source_fragments(meta_options(type_desc->fields()[0]), cpp::source_fragment{" | "});
      const auto value_options =
          join_source_fragments(meta_options(type_desc->fields()[1]), cpp::source_fragment{" | "});
      if (type_desc->fields()[1].is_recursive) {
        descriptor.cpp_meta_type =
            cpp::format("::hpp_proto::map_entry<{}, typename Traits::template indirect_t<{}>, {}, {}>",
                        type_as_template_arg(get_meta_type(type_desc->fields()[0])),
                        get_meta_type(type_desc->fields()[1]), key_options, value_options);
      } else {
        descriptor.cpp_meta_type = cpp::format(
            "::hpp_proto::map_entry<{}, {}, {}, {}>", type_as_template_arg(get_meta_type(type_desc->fields()[0])),
            type_as_template_arg(get_meta_type(type_desc->fields()[1])), key_options, value_options);
      }
    }

    cpp::source_fragment default_value;

    if (options[0].view() == "::hpp_proto::field_option::none" || descriptor.is_closed_enum) {
      default_value = descriptor.default_value_template_arg;
    }

    cpp::source_fragment type_and_default_value;
    if (descriptor.cpp_meta_type.view() != "void" || !default_value.empty()) {
      type_and_default_value = cpp::format(", {}", descriptor.cpp_meta_type);
      if (!default_value.empty()) {
        type_and_default_value.append(cpp::format(", {}", default_value));
      }
    }

    const auto cpp_name =
        descriptor.parent_message() == nullptr
            ? cpp::format("{}", descriptor.cpp_name)
            : cpp::format("{}<Traits>::{}", descriptor.parent_message()->cpp_name, descriptor.cpp_name);

    if (descriptor.extendee_descriptor() == nullptr) {
      const auto access = oneof_index == 0 ? cpp::format("&{}", cpp_name) : cpp::format("{}", oneof_index);
      const auto option_source = join_source_fragments(options, cpp::source_fragment{" | "});

      cpp::emit_to(target, "{}::hpp_proto::field_meta<{}, {}, {}{}>,\n", source_indent(), proto.number, access,
                   option_source, type_and_default_value);
    }
  }

  void format_extension(code_generator::field_descriptor_t &descriptor) {
    const auto cpp_name =
        descriptor.parent_message() == nullptr
            ? cpp::format("{}", descriptor.cpp_name)
            : cpp::format("{}<Traits>::{}", descriptor.parent_message()->cpp_name, descriptor.cpp_name);

    using enum google::protobuf::FieldDescriptorProto<>::Label;
    using enum google::protobuf::FieldDescriptorProto<>::Type;
    auto proto = descriptor.proto();
    const auto &qualified_extendee = descriptor.extendee_descriptor()->qualified_name;
    const auto extendee_template =
        qualified_extendee.substr(0, qualified_extendee.size() - sizeof("<Traits>") + 1); // remove trailing <Traits>

    auto default_value = descriptor.default_value_template_arg;
    if (default_value.empty()) {
      default_value = cpp::source_fragment{"std::monostate{}"};
    }

    auto field_value_type = descriptor.cpp_field_type;
    const bool is_repeated = proto.label == LABEL_REPEATED;

    const auto get_result_type =
        is_repeated ? cpp::format("Traits::template repeated_t<{}>", type_as_template_arg(field_value_type))
                    : field_value_type;

    cpp::source_fragment extra_crtp_arg;
    if (proto.type == TYPE_MESSAGE || proto.type == TYPE_GROUP || proto.type == TYPE_STRING ||
        proto.type == TYPE_BYTES || is_repeated || descriptor.parent_message() != nullptr) {
      cpp::source_fragment default_traits;
      if (descriptor.parent_message() == nullptr) {
        extra_crtp_arg = cpp::source_fragment{"<Traits>"};
        default_traits = cpp::source_fragment{" = ::hpp_proto::default_traits"};
      }
      cpp::emit_to(target, "{0}template <typename Traits{1}>\n", source_indent(), default_traits);
    }

    cpp::source_fragment initializer{" = {}"};

    if (!descriptor.default_value.empty()) {
      initializer = cpp::format(" = {}", descriptor.default_value);
    }

    const auto options = join_source_fragments(meta_options(descriptor), cpp::source_fragment{" | "});
    cpp::emit_to(target,
                 "{0}struct {1}\n"
                 "{0}    : ::hpp_proto::extension_base<{1}{2}, {3}> {{\n"
                 "{0}  using value_type={4};\n"
                 "{0}  value_type value{5};\n"
                 "{0}  using pb_meta = std::tuple<::hpp_proto::field_meta<{6}, &{1}{2}::value, {7}, {8}, {9}>>;\n"
                 "{0}}};\n\n",
                 source_indent(), cpp_name, extra_crtp_arg, extendee_template, get_result_type, initializer,
                 proto.number, options, descriptor.cpp_meta_type, default_value);
  }

  // NOLINTEND(readability-function-cognitive-complexity)

  void process(oneof_descriptor_t &descriptor, message_descriptor_t &parent) {
    auto fields = descriptor.fields();
    if (fields.size() > 1) {
      format_to(target, "{}::hpp_proto::oneof_field_meta<\n", indent());
      indent_num += 2;
      cpp::emit_to(target, "{}&{}::{},\n", source_indent(), parent.no_namespace_qualified_name, descriptor.cpp_name);
      std::size_t i = 0;
      for (auto &f : fields) {
        process(f, ++i);
      }

      indent_num -= 2;
      if (!fields.empty()) {
        auto &content = file.content;
        content.resize(content.size() - 2);
      }
      format_to(target, ">,\n");
    } else {
      process(fields[0], 0);
    }
  }
};

struct glaze_meta_generator : code_generator {
  using code_generator::code_generator;

  void process(file_descriptor_t &descriptor) {
    auto file_name = descriptor.proto().name;
    gen_file_header(file_name);
    file.name = file_name.substr(0, file_name.size() - proto_suffix_length) + "glz.hpp";

    std::string sole_message_name;
    if (descriptor.messages().size() == 1) {
      sole_message_name = descriptor.messages().front().pb_name;
    }

    if (sole_message_name != "google.protobuf.Any") {
      format_to(target, "#pragma once\n\n"
                        "#include <hpp_proto/json.hpp>\n");

      for (const auto &d : descriptor.proto().dependency) {
        auto include = generated_include(d, ".glz.hpp");
        if (!include.has_value()) {
          return;
        }
        cpp::emit_to(target, "#include {}\n", *include);
      }

      auto own_msg_include = generated_include(descriptor.proto().name, ".msg.hpp");
      if (!own_msg_include.has_value()) {
        return;
      }
      cpp::emit_to(target, "#include {}\n\n", *own_msg_include);

      if (!sole_message_name.empty() && well_known_codecs.contains(sole_message_name)) {
        cpp::emit_to(target, "#include <hpp_proto/json/{}.hpp>\n\n", well_known_codecs.at(sole_message_name));
      }
    } else {
      auto own_msg_include = generated_include(descriptor.proto().name, ".msg.hpp");
      if (!own_msg_include.has_value()) {
        return;
      }
      cpp::emit_to(target,
                   "#pragma once\n\n"
                   "#include <hpp_proto/dynamic_message/json.hpp>\n\n"
                   "#include {}\n\n",
                   *own_msg_include);
    }

    for (auto &m : descriptor.messages()) {
      process(m);
    }

    for (auto &e : descriptor.enums()) {
      process(e);
    }

    format_to(target, "// clang-format on\n");
  }

  // NOLINTBEGIN(misc-no-recursion,readability-function-cognitive-complexity)
  void process(message_descriptor_t &descriptor) {
    auto qualified_name = descriptor.qualified_name;

    const static std::set<std::string> well_known_wrapper_types = {
        "google.protobuf.DoubleValue", "google.protobuf.FloatValue",  "google.protobuf.Int64Value",
        "google.protobuf.UInt64Value", "google.protobuf.Int32Value",  "google.protobuf.UInt32Value",
        "google.protobuf.BoolValue",   "google.protobuf.StringValue", "google.protobuf.BytesValue"};

    if (well_known_wrapper_types.contains(descriptor.pb_name)) {
      cpp::source_fragment opts{"Opts"};
      if (descriptor.pb_name == "google.protobuf.Int64Value" || descriptor.pb_name == "google.protobuf.UInt64Value") {
        opts = cpp::source_fragment{"opt_true<ws_handled<Opts>(), quoted_num_opt_tag{}>"};
      }

      cpp::source_fragment parse_operation;
      if (descriptor.pb_name == "google.protobuf.StringValue") {
        parse_operation =
            cpp::source_fragment{"    decltype(auto) v = hpp_proto::detail::as_modifiable(ctx, value.value);\n"
                                 "    parse<JSON>::template op<Opts>(v, ctx, it, end);\n"
                                 "    if (!bool(ctx.error) && !is_utf8(v.data(), v.size())){{\n"
                                 "        ctx.error = error_code::syntax_error;\n"
                                 "    }}"};
      } else {
        parse_operation = cpp::format("    parse<JSON>::template op<{0}>(value.value, ctx, it, end);", opts);
      }

      cpp::emit_to(target,
                   "namespace glz {{\n"
                   "template <typename Traits>\n"
                   "struct to<JSON, {0}> {{\n"
                   "template <auto Opts>\n"
                   "  GLZ_ALWAYS_INLINE static void op(auto &&value, auto&& ...args) {{\n"
                   "    serialize<JSON>::template op<{1}>(value.value, "
                   "std::forward<decltype(args)>(args)...);\n"
                   "  }}\n"
                   "}};\n\n"
                   "template <typename Traits>\n"
                   "struct from<JSON, {0}> {{\n"
                   "template <auto Opts>\n"
                   "  GLZ_ALWAYS_INLINE static void op(auto &value, auto& ctx, auto& it, auto& end) {{\n"
                   "{2}\n"
                   "  }}\n"
                   "}};\n"
                   "}} // namespace glz\n\n",
                   qualified_name, opts, parse_operation);
    } else if (well_known_codecs.contains(descriptor.pb_name)) {
      cpp::emit_to(target,
                   "template <typename Traits>\n"
                   "struct hpp_proto::json_codec<{0}> {{\n"
                   "  using type = ::hpp_proto::{1};\n"
                   "}};\n\n",
                   qualified_name, well_known_codecs.at(descriptor.pb_name));
    } else if (descriptor.pb_name == "google.protobuf.Value") {
      cpp::emit_to(target,
                   // clang-format off
                     "namespace glz {{\n"
                     "template <typename T>\n"
                     "decltype(auto) value_fields(T &value) {{\n"
                     "  if constexpr (requires {{ value.fields; }}) {{\n"
                     "    return (value.fields);\n"
                     "  }} else {{\n"
                     "    return ((*value).fields);\n"
                     "  }}\n"
                     "}}\n\n"
                     "template <typename T>\n"
                     "decltype(auto) value_values(T &value) {{\n"
                     "  if constexpr (requires {{ value.values; }}) {{\n"
                     "    return (value.values);\n"
                     "  }} else {{\n"
                     "    return ((*value).values);\n"
                     "  }}\n"
                     "}}\n\n"
                     "template <typename Traits>\n"
                     "struct to<JSON, {0}> {{\n"
                     "  template <auto Opts>\n"
                     "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&b, auto &&ix) {{\n"
                     "    std::visit(\n"
                     "        [&ctx, &b, &ix](auto &v) {{\n"
                     "          using type = std::decay_t<decltype(v)>;\n"
                     "          if constexpr (requires {{ v.values; }}) {{\n"
                     "            serialize<JSON>::template op<Opts>(v.values, ctx, b, ix);\n"
                     "          }} else if constexpr (requires {{ (*v).values; }}) {{\n"
                     "            serialize<JSON>::template op<Opts>((*v).values, ctx, b, ix);\n"
                     "          }} else if constexpr (requires {{ v.fields; }}) {{\n"
                     "            serialize<JSON>::template op<Opts>(v.fields, ctx, b, ix);\n"
                     "          }} else if constexpr (requires {{ (*v).fields; }}) {{\n"
                     "            serialize<JSON>::template op<Opts>((*v).fields, ctx, b, ix);\n"
                     "          }} else if constexpr (!std::same_as<type, std::monostate>) {{\n"
                     "            serialize<JSON>::template op<Opts>(v, ctx, b, ix);\n"
                     "          }}\n"
                     "        }},\n"
                     "        value.kind);\n"
                     "  }}\n"
                     "}};\n\n"                    
                     "template <typename Traits>\n"
                     "struct from<JSON, {0}> {{\n"
                     "  template <auto Options>\n"
                     "  static void op(auto &&value, is_context auto &&ctx, auto &&it, auto &&end) {{\n"
                     "    if constexpr (!check_ws_handled(Options)) {{\n"
                     "      skip_ws<Options>(ctx, it, end);\n"
                     "      if (bool(ctx.error)) [[unlikely]]{{\n"
                     "        return;\n"
                     "      }}\n"
                     "    }}\n"
                     "    static constexpr auto Opts = ws_handled_off<Options>();\n"
                     "    if (*it == 'n') {{\n"
                     "      match<\"null\", Opts>(ctx, it, end);\n"
                     "      if (bool(ctx.error)) [[unlikely]]{{\n"
                     "        return;\n"
                     "      }}\n"
                     "      value.kind.template emplace<{1}::NullValue>();\n"
                     "    }} else if ((*it >= '0' && *it <= '9') || *it == '-') {{\n"
                     "      parse<JSON>::op<Opts>(value.kind.template emplace<double>(), ctx, it, end);\n"
                     "    }} else if (*it == '\"') {{\n"
                     "      decltype(auto) str = hpp_proto::detail::as_modifiable(ctx, value.kind.template emplace<google::protobuf::Value<Traits>::kind_oneof_case::string_value>());\n"
                     "      parse<JSON>::op<Opts>(str, ctx, it, end);\n"
                     "      if (!bool(ctx.error) && !is_utf8(str.data(), str.size())){{\n"
                     "        ctx.error = error_code::syntax_error;\n"
                     "      }}\n"
                     "    }} else if (*it == 't' || *it == 'f') {{\n"
                     "      parse<JSON>::op<Opts>(value.kind.template emplace<bool>(), ctx, it, end);\n"
                     "    }} else if (*it == '{{') {{\n"
                     "      auto& struct_value = value.kind.template emplace<{0}::kind_oneof_case::struct_value>();\n"
                     "      decltype(auto) fields = value_fields(struct_value);\n"
                     "      decltype(auto) v = hpp_proto::detail::as_modifiable(ctx, fields);\n"
                     "      util::parse_repeated<Opts>(true, v, ctx, it, end);\n"                       
                     "    }} else if (*it == '[') {{\n"
                     "      auto& list_value = value.kind.template emplace<{0}::kind_oneof_case::list_value>();\n"
                     "      decltype(auto) values = value_values(list_value);\n"
                     "      decltype(auto) v = hpp_proto::detail::as_modifiable(ctx, values);\n"
                     "      util::parse_repeated<Opts>(false, v, ctx, it, end);\n"                     
                     "    }} else {{\n"
                     "      ctx.error = error_code::syntax_error;\n"
                     "    }}\n"
                     "  }}\n"
                     "}};\n"
                     "}} // namespace glz\n\n",
                   // clang-format on
                   qualified_name, descriptor.parent_file()->cpp_namespace);
    } else if (descriptor.pb_name == "google.protobuf.Any") {
      cpp::emit_to(
          target,
          "namespace glz {{\n"
          "template <typename Traits>\n"
          "struct to<JSON, {0}> {{\n"
          "  template <auto Opts>"
          "  GLZ_ALWAYS_INLINE static void op(auto &&value, ::hpp_proto::concepts::is_json_context auto "
          "&ctx, auto &b, auto &ix) {{\n"
          "    static_assert(requires {{ ctx.get_dynamic_message_factory(); }}, \"write_json() for Any requires "
          "use_factory{{dynamic_message_factory}} argument\");\n"
          "    any_message_json_serializer::to_json<Opts>(value, ctx, b, ix);\n"
          "  }}\n"
          "}};\n\n"
          "template <typename Traits>\n"
          "struct from<JSON, {0}> {{\n"
          "  template <auto Opts>\n"
          "  GLZ_ALWAYS_INLINE static void op(auto &&value, ::hpp_proto::concepts::is_json_context auto "
          "&ctx, auto &it, auto &end) {{\n"
          "    static_assert(requires {{ ctx.get_dynamic_message_factory(); }}, \"read_json() for Any requires "
          "use_factory{{dynamic_message_factory}} argument\");\n"
          "    any_message_json_serializer::from_json<Opts>(value, ctx, it, end);\n"
          "  }}\n"
          "}};\n"
          "}} // namespace glz\n\n",
          qualified_name);
    } else if (descriptor.pb_name == "google.protobuf.Struct") {
      format_to(target,
                "namespace glz {{\n"
                "\n"
                "template <typename Traits>\n"
                "struct to<JSON, google::protobuf::Struct<Traits>> {{\n"
                "  template <auto Opts>\n"
                "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&b, auto &&ix) {{\n"
                "    const bool dump_brace = !check_opening_handled(Opts);\n"
                "    if (dump_brace) {{\n"
                "      util::dump_opening_brace<Opts>(ctx, b, ix);\n"
                "    }}\n"
                "    const char *separator = nullptr;\n"
                "    for (auto field : value.fields) {{\n"
                "      if (field.second->kind.index() != 0U) {{\n"
                "        if (separator != nullptr) {{\n"
                "          util::dump_field_separator<Opts>(false, ctx, b, ix, *separator);\n"
                "        }}\n"
                "        serialize<JSON>::template op<Opts>(field.first, ctx, b, ix);\n"
                "        util::dump_field_separator<Opts>(true, ctx, b, ix, ':');\n"
                "        serialize<JSON>::op<Opts>(field.second, ctx, b, ix);\n"
                "        if (bool(ctx.error)) {{\n"
                "          return;\n"
                "        }}\n"
                "        separator = \",\";\n"
                "      }}\n"
                "    }}\n"
                "    if (dump_brace) {{\n"
                "      util::dump_closing_brace<Opts>(ctx, b, ix);\n"
                "    }}\n"
                "  }}\n"
                "}};\n"
                "\n"
                "template <typename Traits>\n"
                "struct from<JSON, google::protobuf::Struct<Traits>> {{\n"
                "  template <auto Opts>\n"
                "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&it, auto &&end) {{\n"
                "    decltype(auto) v = hpp_proto::detail::as_modifiable(ctx, value.fields);\n"
                "    util::parse_repeated<Opts>(true, v, ctx, it, end);\n"
                "  }}\n"
                "}};\n"
                "}} // namespace glz\n");
    } else if (descriptor.pb_name == "google.protobuf.ListValue") {
      format_to(target,
                "namespace glz {{\n"
                "\n"
                "template <typename Traits>\n"
                "struct to<JSON, google::protobuf::ListValue<Traits>> {{\n"
                "  template <auto Opts>\n"
                "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&b, auto &&ix) {{\n"
                "    using values_t = std::remove_cvref_t<decltype(value.values)>;\n"
                "    to<JSON, values_t>::template op<Opts>(value.values, ctx, b, ix);\n"
                "  }}\n"
                "}};\n"
                "\n"
                "template <typename Traits>\n"
                "struct from<JSON, google::protobuf::ListValue<Traits>> {{\n"
                "  template <auto Opts>\n"
                "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&it, auto &&end) {{\n"
                "    decltype(auto) v = hpp_proto::detail::as_modifiable(ctx, value.values);\n"
                "    util::parse_repeated<Opts>(false, v, ctx, it, end);\n"
                "  }}\n"
                "}};\n"
                "}} // namespace glz\n");
    } else {
      cpp::emit_to(target,
                   "template <typename Traits>\n"
                   "struct glz::meta<{0}> {{\n"
                   "  using T = {0};\n"
                   "  static constexpr auto value = object(\n",
                   qualified_name);

      for (auto &f : descriptor.fields()) {
        if (!f.proto().oneof_index.has_value()) {
          process(f);
        } else {
          auto index = *f.proto().oneof_index;
          auto &oneof = descriptor.oneofs()[index];
          if (oneof.fields()[0].proto().number == f.proto().number) {
            process(oneof);
          }
        }
      }
      if (!descriptor.fields().empty()) {
        auto &content = file.content;
        content.resize(content.size() - 2);
      }

      format_to(target, ");\n}};\n\n");

      for (auto &m : descriptor.messages()) {
        if (!m.is_map_entry()) {
          process(m);
        }
      }

      for (auto &e : descriptor.enums()) {
        process(e);
      }
    }

    cpp::emit_to(target,
                 "template <typename Traits>\n"
                 "struct hpp_proto::has_glz<{0}> : std::true_type {{}};\n",
                 qualified_name);
  }
  // NOLINTEND(misc-no-recursion,readability-function-cognitive-complexity)

  void process(field_descriptor_t &descriptor) {
    using FieldDescriptorProto = google::protobuf::FieldDescriptorProto<traits_type>;
    using enum FieldDescriptorProto::Type;
    using enum FieldDescriptorProto::Label;

    auto type = descriptor.proto().type;
    const bool is_google_any = (type == TYPE_MESSAGE && descriptor.proto().type_name == ".google.protobuf.Any");

    auto emit_field = [&](const std::string &name, bool is_alias) {
      cpp::source_fragment expr;
      if (descriptor.is_cpp_optional && !is_google_any) {
        expr = cpp::format("&T::{}", descriptor.cpp_name);
      } else if (descriptor.proto().label == LABEL_REQUIRED) {

        if (type == TYPE_INT64 || type == TYPE_UINT64 || type == TYPE_FIXED64 || type == TYPE_SFIXED64 ||
            type == TYPE_SINT64) {
          expr = cpp::format("glz::quoted_num<&T::{}>", descriptor.cpp_name);
        } else {
          expr = cpp::format("&T::{}", descriptor.cpp_name);
        }
      } else {
        auto name_and_default_value = cpp::format("{}", descriptor.cpp_name);
        if (!descriptor.default_value_template_arg.empty()) {
          name_and_default_value.append(cpp::format(", {}", descriptor.default_value_template_arg));
        }
        expr = cpp::format("::hpp_proto::as_optional_ref<&T::{}>", name_and_default_value);
      }

      const cpp::string_literal_bytes literal{name};
      if (is_alias) {
        cpp::emit_to(target, "    {}, ::hpp_proto::as_alias<{}>,\n", literal, expr);
      } else {
        cpp::emit_to(target, "    {}, {},\n", literal, expr);
      }
    };

    const std::string &json_name = descriptor.proto().json_name;
    const std::string &proto_name = descriptor.proto().name;

    if (context.options.preserve_proto_field_names) {
      emit_field(proto_name, false);
      if (json_name != proto_name) {
        emit_field(json_name, true);
      }
    } else {
      emit_field(json_name, false);
      if (proto_name != json_name) {
        emit_field(proto_name, true);
      }
    }
  }

  void process(oneof_descriptor_t &descriptor) {
    auto fields = descriptor.fields();
    if (fields.size() > 1) {
      for (unsigned i = 0; i < fields.size(); ++i) {
        auto emit_oneof = [&](const std::string &name, bool is_alias) {
          const cpp::string_literal_bytes literal{name};
          if (is_alias) {
            cpp::emit_to(target, "    {}, ::hpp_proto::as_oneof_alias<&T::{},{}>,\n", literal, descriptor.cpp_name,
                         i + 1);
          } else {
            cpp::emit_to(target, "    {}, ::hpp_proto::as_oneof_member<&T::{},{}>,\n", literal, descriptor.cpp_name,
                         i + 1);
          }
        };

        const std::string &json_name = fields[i].proto().json_name;
        const std::string &proto_name = fields[i].proto().name;

        if (context.options.preserve_proto_field_names) {
          emit_oneof(proto_name, false);
          if (json_name != proto_name) {
            emit_oneof(json_name, true);
          }
        } else {
          emit_oneof(json_name, false);
          if (proto_name != json_name) {
            emit_oneof(proto_name, true);
          }
        }
      }
    } else {
      process(fields[0]);
    }
  }

  void process(enum_descriptor_t &descriptor) {
    if (descriptor.cpp_name.view() != "NullValue" || descriptor.parent_file()->proto().package != "google.protobuf") {
      cpp::emit_to(target,
                   "template <>\n"
                   "struct glz::meta<{0}> {{\n"
                   "  using enum {0};\n"
                   "  static constexpr auto value = enumerate(\n",
                   descriptor.qualified_name);

      indent_num += 4;
      std::size_t index = 0;
      std::vector<const google::protobuf::EnumValueDescriptorProto<> *> values;
      values.resize(descriptor.proto().value.size());
      std::ranges::transform(descriptor.proto().value, values.begin(), [](const auto &v) { return &v; });
      std::ranges::sort(values, {}, [](auto *v) { return v->number; });
      for (const auto *e : values) {
        const auto sep = index++ == values.size() - 1 ? cpp::source_fragment{");"} : cpp::source_fragment{","};
        cpp::emit_to(target, "{}{}, {}{}\n", source_indent(), cpp::string_literal_bytes{e->name},
                     cpp_identifier(e->name, context.diagnostics), sep);
      }

      indent_num -= 4;
      format_to(target, "}};\n\n", indent());
    } else {
      cpp::emit_to(
          target,
          "namespace glz {{\n"
          "template <>\n"
          "struct to<JSON, {0}> {{\n"
          "  template <auto Opts>\n"
          "  GLZ_ALWAYS_INLINE static void op(auto && /*value*/, auto&& ...args) {{\n"
          "    serialize<JSON>::template op<Opts>(std::monostate{{}}, std::forward<decltype(args)>(args)...);\n"
          "  }}\n"
          "}};\n\n"
          "template <>\n"
          "struct from<JSON, {0}> {{\n"
          "  template <auto Opts>\n"
          "  GLZ_ALWAYS_INLINE static void op(auto &value, auto&& ...args) {{\n"
          "    parse<JSON>::template op<Opts>(std::monostate{{}}, std::forward<decltype(args)>(args)...);\n"
          "    value = {0}::NULL_VALUE;\n"
          "  }}\n"
          "}};\n"
          "}}\n\n",
          descriptor.qualified_name);
    }
  }
};

struct desc_hpp_generator : code_generator {
  using code_generator::code_generator;

  void process(file_descriptor_t &descriptor) {
    auto path = descriptor.proto().name;
    gen_file_header(path);
    file.name = path.substr(0, path.size() - proto_suffix_length) + "desc.hpp";

    format_to(target, "#pragma once\n"
                      "#include <hpp_proto/file_descriptor_pb.hpp>\n\n");

    for (const auto &d : descriptor.proto().dependency) {
      auto include = generated_include(d, ".desc.hpp");
      if (!include.has_value()) {
        return;
      }
      cpp::emit_to(target, "#include {}\n", *include);
    }

    const auto &descriptor_name = descriptor.descriptor_name;
    const auto &ns = descriptor_name.namespace_name();
    cpp::emit_to(target, "\nnamespace {} {{\n\n", ns);

    std::vector<std::uint8_t> buf;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto &proto = const_cast<google::protobuf::FileDescriptorProto<> &>(descriptor.proto());
    proto.source_code_info.reset();
    (void)::hpp_proto::write_binpb(proto, buf);

    std::string descriptor_bytes;
    descriptor_bytes.reserve(buf.size());
    std::ranges::transform(buf, std::back_inserter(descriptor_bytes),
                           [](std::uint8_t byte) { return static_cast<char>(byte); });
    const cpp::string_literal_bytes descriptor_literal{descriptor_bytes};
    cpp::emit_to(target,
                 "using namespace std::literals::string_view_literals;\n"
                 "inline constexpr ::hpp_proto::file_descriptor_pb {}{{\n  ",
                 descriptor_name.descriptor_identifier());
    // libc++'s format output buffer overflows under ASan when one replacement
    // field contains descriptor.proto's very large string literal. The literal
    // is already fully encoded by string_literal_bytes, so append that lexical
    // value directly instead of passing it through another formatting buffer.
    std::ranges::copy(descriptor_literal.view(), target);
    format_to(target, "sv\n}};\n\n");

    cpp::emit_to(target, "inline auto {}(){{\n", descriptor_name.descriptor_set_identifier());
    const auto &dependency_names = descriptor.get_dependency_names();
    format_to(target, "  return ::hpp_proto::distinct_file_descriptor_pb_array{{\n");
    for (const auto &p : dependency_names) {
      cpp::emit_to(target, "    ::{},\n", p);
    }

    format_to(target, "  }};\n"
                      "}}\n");

    cpp::emit_to(target, "}} // namespace {}\n\n", ns);
    format_to(target, "// clang-format on\n");
  }
};

struct service_generator : code_generator {
  hpp_gen_descriptor_pool &pool;

  service_generator(std::vector<CodeGeneratorResponse::File> &files, hpp_gen_descriptor_pool &descriptor_pool,
                    generation_context &generation)
      : code_generator(files, generation), pool(descriptor_pool) {}

  cpp::source_fragment resolved_message_type(std::string_view proto_name) {
    if (proto_name.starts_with('.')) {
      proto_name.remove_prefix(1);
    }
    const auto *message = pool.get_message_descriptor(proto_name);
    if (message == nullptr) {
      context.diagnostics.record(std::format("RPC message type not found: {}", proto_name));
      return {};
    }
    return message->qualified_name;
  }

  void process(file_descriptor_t &descriptor) {
    auto path = descriptor.proto().name;
    gen_file_header(path);
    file.name = path.substr(0, path.size() - proto_suffix_length) + "service.hpp";

    for (const auto &d : descriptor.proto().dependency) {
      auto include = generated_include(d, ".pb.hpp");
      if (!include.has_value()) {
        return;
      }
      cpp::emit_to(target, "#include {}\n", *include);
    }

    auto own_pb_include = generated_include(descriptor.proto().name, ".pb.hpp");
    if (!own_pb_include.has_value()) {
      return;
    }
    cpp::emit_to(target, "#include {}\n\n", *own_pb_include);

    auto package = descriptor.proto().package;
    auto ns = cpp_qualified_name(descriptor.namespace_prefix, "." + package, context.diagnostics);

    if (!ns.empty()) {
      cpp::emit_to(target, "\nnamespace {} {{\n\n", ns);
    }

    for (const auto &s : descriptor.proto().service) {
      if (s.method.empty()) {
        continue;
      }

      const auto service_identifier = namespace_declaration_identifier(s.name, context.diagnostics);
      cpp::emit_to(target, "namespace {} {{\n", service_identifier);
      auto proto_service_name = package.empty() ? s.name : package + "." + s.name;
      cpp::source_fragment methods;
      cpp::source_fragment method_separator;
      std::size_t ordinal = 0;
      for (const auto &m : s.method) {
        const auto method_identifier = service_method_identifier(m.name, context.diagnostics);
        methods.append(method_separator).append(cpp::format("{}", method_identifier));
        method_separator = cpp::source_fragment{","};
        const int rpc_type = (m.server_streaming ? 2 : 0) + (m.client_streaming ? 1 : 0);
        const cpp::string_literal_bytes method_path{"/" + proto_service_name + "/" + m.name};
        const auto request_type = resolved_message_type(m.input_type);
        const auto response_type = resolved_message_type(m.output_type);
        cpp::emit_to(target,
                     "  struct {} {{\n"
                     "    constexpr static const char* method_name = {};\n"
                     "    constexpr static bool client_streaming = {};\n"
                     "    constexpr static bool server_streaming = {};\n"
                     "    constexpr static int rpc_type = {};\n"
                     "    constexpr static auto ordinal = {};\n"
                     "    template <typename Traits>\n"
                     "    using request_t = {};\n"
                     "    template <typename Traits>\n"
                     "    using response_t = {};\n"
                     "  }};\n",
                     method_identifier, method_path, m.client_streaming, m.server_streaming, rpc_type, ordinal++,
                     request_type, response_type);
      }
      cpp::emit_to(target,
                   "  using _methods = std::tuple<{}>;\n"
                   "}}; // namespace {}\n\n",
                   methods, service_identifier);
    }

    if (!ns.empty()) {
      cpp::emit_to(target, "}} // namespace {}\n", ns);
    }
  }
};

namespace {

void split(std::string_view str, char deliminator, auto &&callback) {
  std::size_t pos = 0;
  while (pos < str.size()) {
    auto next_pos = str.find(deliminator, pos);
    const auto length = next_pos == std::string_view::npos ? str.size() - pos : next_pos - pos;
    callback(str.substr(pos, length));
    if (next_pos == std::string_view::npos) {
      break;
    }
    pos = next_pos + 1;
  }
}
} // namespace

namespace hpp_proto::protoc {

std::expected<plugin_options, generator_option_error> parse_plugin_options(std::string_view parameters,
                                                                           std::filesystem::path plugin_name) {
  plugin_options result;
  result.generation.plugin_name = std::move(plugin_name);
  result.generation.raw_parameters = parameters;
  result.generation.proto2_explicit_presences.clear();

  std::optional<generator_option_error> error;
  split(parameters, ',', [&result, &error](std::string_view option) {
    const auto equal_sign_pos = option.find('=');
    const auto key = option.substr(0, equal_sign_pos);
    const auto value = equal_sign_pos == std::string_view::npos ? std::string_view{}
                                                                : option.substr(equal_sign_pos + 1);

    if (key == "directory_prefix") {
      result.generation.directory_prefix = value;
    } else if (key == "namespace_prefix") {
      auto namespace_prefix = cpp::qualified_name::from_dotted(value);
      if (!namespace_prefix.has_value()) {
        error = generator_option_error{namespace_prefix.error().message};
        return;
      }
      result.generation.namespace_prefix = std::move(*namespace_prefix);
    } else if (key == "proto2_explicit_presence") {
      result.generation.proto2_explicit_presences.emplace_back(value);
    } else if (key == "preserve_proto_field_names") {
      result.generation.preserve_proto_field_names = value == "true" || value.empty();
    } else if (key == "export_request") {
      result.export_request = std::filesystem::path{value};
    }
  });

  if (error.has_value()) {
    return std::unexpected(std::move(*error));
  }
  if (result.generation.proto2_explicit_presences.empty()) {
    result.generation.proto2_explicit_presences.emplace_back(".");
  }
  return result;
}

code_generator_response hpp_generator::generate(code_generator_request request) const {
  generation_context context{.options = options_};
  code_generator_response response;
  using enum code_generator_response::Feature;
  response.supported_features =
      static_cast<std::uint64_t>(FEATURE_PROTO3_OPTIONAL) | static_cast<std::uint64_t>(FEATURE_SUPPORTS_EDITIONS);
  response.minimum_edition = static_cast<std::int32_t>(google::protobuf::Edition::EDITION_PROTO2);
  response.maximum_edition = static_cast<std::int32_t>(google::protobuf::Edition::EDITION_2024);

  hpp_gen_descriptor_pool pool{hpp_addons::context_type{.generation = &context}};
  const auto init_status = pool.init(
      google::protobuf::FileDescriptorSet<>{.file = std::move(request.proto_file), .unknown_fields_ = {}});
  if (!init_status.has_value() && !context.diagnostics.has_error()) {
    context.diagnostics.record("hpp descriptor pool init error");
  }

  if (!context.diagnostics.has_error()) {
    code_generator::validate_file_descriptor_names(pool, context.diagnostics);
  }
  if (!context.diagnostics.has_error()) {
    code_generator::resolve_message_dependencies(pool, context.diagnostics);
  }

  if (!context.diagnostics.has_error()) {
    for (const auto &file_name : request.file_to_generate) {
      auto *descriptor = pool.get_file_descriptor(file_name);
      if (descriptor == nullptr) {
        context.diagnostics.record(std::format("hpp file_to_generate not found: {}", file_name));
        break;
      }

      msg_code_generator msg_code(response.file, context);
      msg_code.process(*descriptor);
      if (context.diagnostics.has_error()) {
        break;
      }

      hpp_meta_generator hpp_meta_code(response.file, context);
      hpp_meta_code.process(*descriptor);
      if (context.diagnostics.has_error()) {
        break;
      }

      glaze_meta_generator glz_meta_code(response.file, context);
      glz_meta_code.process(*descriptor);
      if (context.diagnostics.has_error()) {
        break;
      }

      if (!descriptor->messages().empty()) {
        desc_hpp_generator desc_hpp_code(response.file, context);
        desc_hpp_code.process(*descriptor);
      }
      if (context.diagnostics.has_error()) {
        break;
      }

      if (!descriptor->proto().service.empty()) {
        service_generator service_code(response.file, pool, context);
        service_code.process(*descriptor);
        if (context.diagnostics.has_error()) {
          break;
        }
      }
    }
  }

  if (context.diagnostics.has_error()) {
    response.error = context.diagnostics.message();
    response.file.clear();
  }
  return response;
}

} // namespace hpp_proto::protoc
