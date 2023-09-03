// MIT License
//
// Copyright (c) 2023 Huang-Ming Huang
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

#include <algorithm>
#include <fmt/format.h>
#include <fstream>
#include <google/protobuf/compiler/plugin.pb.hpp>
#include <hpp_proto/descriptor_pool.h>
#include <iostream>
#include <numeric>
#include <set>
#include <unordered_set>

namespace gpb = google::protobuf;

std::unordered_set<std::string_view> keywords = {
    //
    "NULL",          "alignas",      "alignof",   "and",        "and_eq",
    "asm",           "auto",         "bitand",    "bitor",      "bool",
    "break",         "case",         "catch",     "char",       "class",
    "compl",         "const",        "constexpr", "const_cast", "continue",
    "decltype",      "default",      "delete",    "do",         "double",
    "dynamic_cast",  "else",         "enum",      "explicit",   "export",
    "extern",        "false",        "float",     "for",        "friend",
    "goto",          "if",           "inline",    "int",        "long",
    "mutable",       "namespace",    "new",       "noexcept",   "not",
    "not_eq",        "nullptr",      "operator",  "or",         "or_eq",
    "private",       "protected",    "public",    "register",   "reinterpret_cast",
    "return",        "short",        "signed",    "sizeof",     "static",
    "static_assert", "static_cast",  "struct",    "switch",     "template",
    "this",          "thread_local", "throw",     "true",       "try",
    "typedef",       "typeid",       "typename",  "union",      "unsigned",
    "using",         "virtual",      "void",      "volatile",   "wchar_t",
    "while",         "xor",          "xor_eq",    "char8_t",    "char16_t",
    "char32_t",      "concept",      "consteval", "constinit",  "co_await",
    "co_return",     "co_yield",     "requires",
};

std::vector<std::string> force_optionals;
std::string root_namespace;
std::string top_directory;
bool non_owning_mode = false;

std::string resolve_keyword(std::string_view name) {
  if (keywords.count(name) > 0) {
    return std::string(name) + "_";
  }
  return std::string(name);
}

std::string qualified_cpp_name(std::string_view name) {
  std::string result;
  auto append_component = [&result](std::string_view comp) { result += resolve_keyword(comp); };

  std::size_t i = 0;
  std::size_t j;
  while ((j = name.find('.', i)) != std::string_view::npos) {
    if (j == 0 && root_namespace.size()) {
      result += root_namespace;
    } else if (i == j) {
      result += "::";
    } else {
      result += resolve_keyword(name.substr(i, j - i));
      result += "::";
    }
    i = j + 1;
  }
  result += resolve_keyword(name.substr(i));
  return result;
}

constexpr size_t cpp_escaped_len(char c) {
  /* clang-format off */
  constexpr unsigned char cpp_escaped_len_table[256] = {
      4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 4, 4, 2, 4, 4,  // \t, \n, \r
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
      1, 1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1,  // ", '
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2,  // '0'..'9'
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 'A'..'O'
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1,  // 'P'..'Z', '\'
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 'a'..'o'
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4,  // 'p'..'z', DEL
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  };
  /* clang-format on */
  return cpp_escaped_len_table[static_cast<unsigned char>(c)];
}
// Calculates the length of the C-style escaped version of 'src'.
// Assumes that non-printable characters are escaped using octal sequences,
// and that UTF-8 bytes are not handled specially.
inline size_t cpp_escaped_len(std::string_view src) {
  size_t len = 0;
  for (char c : src)
    len += cpp_escaped_len(c);
  return len;
}

std::string cpp_escape(std::string_view src) {
  size_t escaped_len = cpp_escaped_len(src);
  if (escaped_len == src.size()) {
    return std::string(src.data(), src.size());
  }
  std::string result;
  result.reserve(escaped_len);
  auto itr = std::back_inserter(result);

  for (char c : src) {
    size_t char_len = cpp_escaped_len(c);
    if (char_len == 1) {
      *itr++ = c;
    } else if (char_len == 2) {
      switch (c) {
      case '\n':
        *itr++ = '\\';
        *itr++ = 'n';
        break;
      case '\r':
        *itr++ = '\\';
        *itr++ = 'r';
        break;
      case '\t':
        *itr++ = '\\';
        *itr++ = 't';
        break;
      case '\"':
        *itr++ = '\\';
        *itr++ = '\"';
        break;
      case '\'':
        *itr++ = '\\';
        *itr++ = '\'';
        break;
      case '\\':
        *itr++ = '\\';
        *itr++ = '\\';
        break;
      case '?':
        *itr++ = '\\';
        *itr++ = '?';
        break;
      }
    } else {
      *itr++ = '\\';
      *itr++ = '0' + static_cast<unsigned char>(c) / 64;
      *itr++ = '0' + (static_cast<unsigned char>(c) % 64) / 8;
      *itr++ = '0' + static_cast<unsigned char>(c) % 8;
    }
  }
  return result;
}

std::string basename(const std::string &name) {
  std::string result = name.substr(0, name.find_last_of('.'));
  if (top_directory.size())
    result = top_directory + "/" + result;
  return result;
}

std::size_t shared_scope_position(std::string_view s1, std::string_view s2) {
  auto pos = std::mismatch(s1.begin(), s1.end(), s2.begin(), s2.end()).first - s1.begin();
  if (pos == s1.size() && pos == s2.size())
    return pos;
  if (pos > 0) {
    if (s1.size() > s2.size())
      std::swap(s1, s2);
    if (pos == s1.size() && s2[pos] == '.')
      return pos;
    pos = s1.find_last_of('.', pos - 1);
    if (pos != std::string_view::npos)
      return pos;
  }
  return std::string_view::npos;
}

std::size_t replace_all(std::string &inout, std::string_view what, std::string_view with) {
  std::size_t count{};
  for (std::string::size_type pos{}; inout.npos != (pos = inout.find(what.data(), pos, what.length()));
       pos += with.length(), ++count) {
    inout.replace(pos, what.length(), with.data(), with.length());
  }
  return count;
}

struct hpp_addons {

  template <typename Derived>
  struct field_descriptor {
    std::string cpp_name;
    std::string cpp_field_type;
    std::string cpp_meta_type = "void";
    std::string default_value;
    std::string default_value_template_arg;
    std::string_view qualified_parent_name;
    Derived *map_fields[2] = {nullptr, nullptr};
    bool is_recursive = false;
    bool is_cpp_optional = false;

    field_descriptor(const gpb::FieldDescriptorProto &proto, const std::string &parent_name)
        : cpp_name(resolve_keyword(proto.name)), qualified_parent_name(parent_name) {
      using enum gpb::FieldDescriptorProto::Type;
      using enum gpb::FieldDescriptorProto::Label;
      is_cpp_optional = (proto.label == LABEL_OPTIONAL) &&
                        (proto.type == TYPE_GROUP || proto.type == TYPE_MESSAGE || proto.proto3_optional ||
                         std::any_of(force_optionals.begin(), force_optionals.end(),
                                     [f = parent_name + "." + proto.name](const auto &s) { return f.starts_with(s); }));
      set_cpp_type(proto);
      set_default_value(proto);
    }

    void set_cpp_type(const gpb::FieldDescriptorProto &proto) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (proto.type) {
      case TYPE_DOUBLE:
        cpp_field_type = "double";
        break;
      case TYPE_FLOAT:
        cpp_field_type = "float";
        break;
      case TYPE_INT64:
        cpp_field_type = "int64_t";
        cpp_meta_type = "zpp::bits::vint64_t";
        break;
      case TYPE_UINT64:
        cpp_field_type = "uint64_t";
        cpp_meta_type = "zpp::bits::vuint64_t";
        break;
      case TYPE_INT32:
        cpp_field_type = "int32_t";
        cpp_meta_type = "zpp::bits::vint64_t";
        break;
      case TYPE_FIXED64:
        cpp_field_type = "uint64_t";
        break;
      case TYPE_FIXED32:
        cpp_field_type = "uint32_t";
        break;
      case TYPE_BOOL:
        cpp_field_type = "bool";
        cpp_meta_type = "bool";
        break;
      case TYPE_STRING:
        cpp_field_type = non_owning_mode ? "std::string_view" : "std::string";
        break;
      case TYPE_GROUP:
      case TYPE_MESSAGE:
      case TYPE_ENUM:
        if (proto.type_name.size()) {
          auto pos = shared_scope_position(qualified_parent_name, proto.type_name);

          is_recursive = (pos == proto.type_name.size());
          if (pos == 0) {
            cpp_field_type = qualified_cpp_name(proto.type_name);
          } else if (is_recursive) {
            auto pos = proto.type_name.find_last_of('.');
            cpp_field_type = resolve_keyword(proto.type_name.substr(pos + 1));
          } else {
            cpp_field_type = qualified_cpp_name(proto.type_name.substr(pos + 1));
          }
        }
        break;
      case TYPE_BYTES:
        cpp_field_type = non_owning_mode ? "std::span<std::byte>" : "hpp::proto::bytes";
        break;
      case TYPE_UINT32:
        cpp_field_type = "uint32_t";
        cpp_meta_type = "zpp::bits::vuint32_t";
        break;
      case TYPE_SFIXED32:
        cpp_field_type = "int32_t";
        break;
      case TYPE_SFIXED64:
        cpp_field_type = "int64_t";
        break;
      case TYPE_SINT32:
        cpp_field_type = "int32_t";
        cpp_meta_type = "zpp::bits::vsint32_t";
        break;
      case TYPE_SINT64:
        cpp_field_type = "int64_t";
        cpp_meta_type = "zpp::bits::vsint64_t";
        break;
      }
    }

    void set_default_value(const gpb::FieldDescriptorProto &proto) {
      using enum gpb::FieldDescriptorProto::Type;
      using enum gpb::FieldDescriptorProto::Label;

      if (proto.default_value.size()) {
        if (proto.type == TYPE_STRING) {
          if (proto.default_value.size()) {
            std::string escaped = cpp_escape(proto.default_value);
            default_value = fmt::format("\"{}\"", escaped);
            default_value_template_arg = fmt::format("hpp::proto::compile_time_string{{\"{}\"}}", escaped);
          }
        } else if (proto.type == TYPE_BYTES) {
          if (proto.default_value.size()) {
            std::string escaped = cpp_escape(proto.default_value);
            default_value = fmt::format("\"{}\"_bytes", escaped);
            default_value_template_arg = fmt::format("hpp::proto::compile_time_string{{\"{}\"}}", escaped);
          }
        } else if (proto.type == TYPE_ENUM) {
          default_value = fmt::format("{}::{}", cpp_field_type, proto.default_value);
          default_value_template_arg = fmt::format("{}::{}", qualified_cpp_name(proto.type_name), proto.default_value);
        } else if (proto.type == TYPE_DOUBLE || proto.type == TYPE_FLOAT) {
          if (proto.default_value == "nan") {
            default_value = fmt::format("std::numeric_limits<{}>::quiet_NaN()", cpp_field_type);
          } else if (proto.default_value == "inf") {
            default_value = fmt::format("std::numeric_limits<{}>::infinity()", cpp_field_type);
          } else if (proto.default_value == "-inf") {
            default_value = fmt::format("-std::numeric_limits<{}>::infinity()", cpp_field_type);
          } else if (proto.type == TYPE_FLOAT) {
            if (proto.default_value.find('.') == std::string::npos &&
                proto.default_value.find('e') == std::string::npos)
              default_value = proto.default_value + ".0f";
            else
              default_value = proto.default_value + "f";
          } else {
            default_value = fmt::format("double({})", proto.default_value);
          }

          const char *wrap_type = (proto.type == TYPE_DOUBLE) ? "DOUBLE" : "FLOAT";

          default_value_template_arg = fmt::format("HPP_PROTO_WRAP_{}({})", wrap_type, default_value);
        } else {
          std::string_view typename_view = cpp_field_type;
          std::string suffix;
          if (typename_view[0] == 'u')
            suffix = "U";

          if (typename_view.substr(typename_view.size() - 4, 2) == "64")
            suffix += "LL";

          if (proto.default_value == "-9223372036854775808")
            default_value = "-9223372036854775807LL-1";
          else
            default_value = fmt::format("{}{}", proto.default_value, suffix);
          default_value_template_arg = default_value;
        }
      }
    }
  };

  template <typename EnumD>
  struct enum_descriptor {
    std::string cpp_name;
    enum_descriptor(const gpb::EnumDescriptorProto &proto) : cpp_name(resolve_keyword(proto.name)) {}
  };

  template <typename OneofD, typename FieldD>
  struct oneof_descriptor {
    std::vector<FieldD *> fields;
    std::string cpp_name;

    oneof_descriptor(const gpb::OneofDescriptorProto &proto) : cpp_name(resolve_keyword(proto.name)) {}

    void normalize_cpp_name() {
      if (fields.size() == 1) {
        std::string_view field_name = cpp_name;
        if (field_name[0] == '_' && field_name.substr(1) == fields[0]->cpp_name)
          cpp_name = cpp_name.substr(1);
      }
    }
  };

  template <typename MessageD, typename EnumD, typename OneofD, typename FieldD>
  struct message_descriptor {
    std::vector<FieldD *> fields;
    std::vector<EnumD *> enums;
    std::vector<MessageD *> messages;
    std::vector<OneofD *> oneofs;
    std::vector<FieldD *> extensions;

    std::string cpp_name;
    std::set<std::string> dependencies;
    std::set<std::string> forward_declarations;
    bool is_map_entry;

    message_descriptor(const gpb::DescriptorProto &proto) : cpp_name(resolve_keyword(proto.name)) {
      is_map_entry = proto.options.has_value() && proto.options->map_entry;

      fields.reserve(proto.field.size());
      messages.reserve(proto.nested_type.size());
      enums.reserve(proto.enum_type.size());
      oneofs.reserve(proto.oneof_decl.size());
      extensions.reserve(proto.extension.size());
    }

    void add_field(FieldD &f) {
      fields.push_back(&f);
      if (f.proto.oneof_index.has_value()) {
        oneofs[*f.proto.oneof_index]->fields.push_back(&f);
      }
    }
    void add_enum(EnumD &e) { enums.push_back(&e); }
    void add_message(MessageD &m) { messages.push_back(&m); }
    void add_oneof(OneofD &o) { oneofs.push_back(&o); }
    void add_extension(FieldD &f) { extensions.push_back(&f); }
  };

  template <typename FileD, typename MessageD, typename EnumD, typename FieldD>
  struct file_descriptor {
    std::vector<MessageD *> messages;
    std::vector<EnumD *> enums;
    std::vector<FieldD *> extensions;
    int syntax;
    file_descriptor(const gpb::FileDescriptorProto &proto) {
      if (proto.syntax == "proto3")
        syntax = 3;
      else
        syntax = 2;

      messages.reserve(proto.message_type.size());
      enums.reserve(proto.enum_type.size());
      extensions.reserve(proto.extension.size());
    }
    void add_enum(EnumD &e) { enums.push_back(&e); }
    void add_message(MessageD &m) { messages.push_back(&m); }
    void add_extension(FieldD &f) { extensions.push_back(&f); }
  };
};

using hpp_gen_decriptor_pool = hpp::proto::descriptor_pool<hpp_addons>;

struct code_generator {
  std::size_t indent_num = 0;

  gpb::compiler::CodeGeneratorResponse::File &file;
  std::back_insert_iterator<std::string> target;

  using message_descriptor_t = hpp_gen_decriptor_pool::message_descriptor_t;
  using enum_descriptor_t = hpp_gen_decriptor_pool::enum_descriptor_t;
  using oneof_descriptor_t = hpp_gen_decriptor_pool::oneof_descriptor_t;
  using field_descriptor_t = hpp_gen_decriptor_pool::field_descriptor_t;
  using file_descriptor_t = hpp_gen_decriptor_pool::file_descriptor_t;

  code_generator(std::vector<gpb::compiler::CodeGeneratorResponse::File> &files)
      : file(files.emplace_back()), target(file.content) {}

  std::string_view indent() {
    static std::string spaces(128, ' ');
    while (indent_num > spaces.size())
      spaces.resize(spaces.size() * 2);
    return std::string_view{spaces.data(), indent_num};
  }

  static void mark_field_recursive(message_descriptor_t &descriptor, std::string dep) {
    for (auto f : descriptor.fields) {
      if (f->cpp_field_type == dep)
        f->is_recursive = true;
    }
    for (auto m : descriptor.messages) {
      mark_field_recursive(*m, dep);
    }
  }

  static void resolve_dependency_cycle(message_descriptor_t &descriptor) {
    auto nh = descriptor.dependencies.extract(descriptor.dependencies.begin());
    auto &dep = nh.value();
    descriptor.forward_declarations.insert(std::move(nh));

    mark_field_recursive(descriptor, dep);
  }

  static std::vector<message_descriptor_t *> order_messages(std::vector<message_descriptor_t *> &messages) {
    std::vector<message_descriptor_t *> resolved_messages;
    std::vector<message_descriptor_t *> unresolved_messages;
    resolved_messages.reserve(messages.size());
    unresolved_messages.reserve(messages.size());
    std::set<std::string> resolved_message_names;

    for (auto m : messages) {
      if (m->dependencies.size() == 0) {
        resolved_messages.push_back(m);
        resolved_message_names.insert(m->cpp_name);
      } else {
        unresolved_messages.push_back(m);
      }
    }

    std::size_t unresolved_size = unresolved_messages.size();
    while (unresolved_size) {
      for (auto itr = unresolved_messages.rbegin(); itr != unresolved_messages.rend(); ++itr) {
        auto &pm = *itr;
        auto &deps = pm->dependencies;
        if (std::includes(resolved_message_names.begin(), resolved_message_names.end(), deps.begin(), deps.end())) {
          resolved_messages.push_back(pm);
          resolved_message_names.insert(pm->cpp_name);
          if (itr != unresolved_messages.rbegin()) {
            std::swap(pm, unresolved_messages.back());
          }
          unresolved_messages.resize(unresolved_messages.size() - 1);
        }
      }

      if (unresolved_size > unresolved_messages.size())
        unresolved_size = unresolved_messages.size();
      else {
        std::sort(unresolved_messages.begin(), unresolved_messages.end(),
                  [](auto lhs, auto rhs) { return lhs->cpp_name < rhs->cpp_name; });
        auto x = *(unresolved_messages.rbegin());
        resolve_dependency_cycle(*x);
      }
    }
    return resolved_messages;
  }
};

struct msg_code_generator : code_generator {
  int syntax;

  msg_code_generator(std::vector<gpb::compiler::CodeGeneratorResponse::File> &files) : code_generator(files) {}

  void resolve_message_dependencies(hpp_gen_decriptor_pool &pool) {
    for (auto &field : pool.fields) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      auto type = field.proto.type;
      if ((type == TYPE_MESSAGE || type == TYPE_GROUP || type == TYPE_ENUM) && field.proto.type_name.size()) {
        auto type_name = field.proto.type_name;
        auto message_name = field.qualified_parent_name;
        auto pos = shared_scope_position(message_name, type_name);
        std::string depender, dependee;
        if (pos > 0 && pos < message_name.size() && pos != type_name.size()) {
          auto depender_pos = message_name.find_first_of('.', pos + 1);
          depender = message_name.substr(0, depender_pos);
          dependee = type_name.substr(pos + 1);
          auto dependee_pos = dependee.find('.');
          if (dependee_pos != std::string::npos) {
            dependee = dependee.substr(0, dependee_pos);
          } else if (type == TYPE_ENUM) {
            depender = "";
          }
        }

        auto itr = pool.message_map.find(depender);
        if (itr != pool.message_map.end()) {
          itr->second->dependencies.insert(qualified_cpp_name(dependee));
        }

        if (type == TYPE_ENUM && field.proto.label == gpb::FieldDescriptorProto::Label::LABEL_OPTIONAL &&
            field.proto.default_value.empty()) {
          auto enum_d = pool.find_type(pool.enum_map, type_name);
          std::string proto_default_value = resolve_keyword(enum_d->proto.value[0].name);
          field.default_value = fmt::format("{}::{}", field.cpp_field_type, proto_default_value);
          field.default_value_template_arg = fmt::format("{}::{}", qualified_cpp_name(type_name), proto_default_value);
        }
      }
    }
  }

  void process(file_descriptor_t &descriptor) {
    syntax = descriptor.syntax;
    auto file_name = descriptor.proto.name;
    file.name = file_name.substr(0, file_name.size() - 5) + "msg.hpp";
    fmt::format_to(target, "#pragma once\n\n"
                           "#include <hpp_proto/field_types.h>\n");

    for (auto &d : descriptor.proto.dependency)
      fmt::format_to(target, "#include <{}.msg.hpp>\n", basename(d));

    auto ns = root_namespace + qualified_cpp_name(descriptor.proto.package);
    if (ns.size())
      fmt::format_to(target, "\nnamespace {} {{\n\n", ns);

    fmt::format_to(target, "{}using namespace hpp::proto::literals;\n", indent());

    for (auto e : descriptor.enums)
      process(*e);

    for (auto m : order_messages(descriptor.messages))
      process(*m);

    if (ns.size())
      fmt::format_to(target, "}} // namespace {}\n", ns);
  }

  std::string_view field_type_wrapper(field_descriptor_t &descriptor) {
    const auto &proto = descriptor.proto;
    using enum gpb::FieldDescriptorProto::Label;
    using enum gpb::FieldDescriptorProto::Type;
    if (proto.label == LABEL_REPEATED)
      return non_owning_mode ? "std::span" : "std::vector";
    if (descriptor.is_recursive)
      return non_owning_mode ? "*" : "hpp::proto::heap_based_optional";
    if (descriptor.is_cpp_optional) {
      if (proto.type == TYPE_GROUP || proto.type == TYPE_MESSAGE)
        return "std::optional";
      return "hpp::proto::optional";
    }
    return "";
  }

  std::string field_type(field_descriptor_t &descriptor) {
    if (descriptor.map_fields[0]) {
      if (!non_owning_mode) {
        const char *type = descriptor.map_fields[1]->is_recursive ? "std::map" : "hpp::proto::flat_map";
        // when using flat_map with bool, it would lead std::vector<bool> as one of its members; which is not what we
        // need.
        auto transform_if_bool = [recursive = descriptor.map_fields[1]->is_recursive](const std::string &name) {
          return recursive || name != "bool" ? name : std::string{"hpp::proto::boolean"};
        };
        return fmt::format("{}<{},{}>", type, transform_if_bool(descriptor.map_fields[0]->cpp_field_type),
                           transform_if_bool(descriptor.map_fields[1]->cpp_field_type));
      } else {
        return fmt::format("std::span<std::pair<{},{}>>", descriptor.map_fields[0]->cpp_field_type,
                           descriptor.map_fields[1]->cpp_field_type);
      }
    }

    auto wrapper = field_type_wrapper(descriptor);

    if (wrapper == "std::vector" && descriptor.cpp_field_type == "bool") {
      return fmt::format("std::vector<hpp::proto::boolean>");
    } else if (wrapper == "hpp::proto::optional" && descriptor.default_value_template_arg.size()) {
      return fmt::format("hpp::proto::optional<{},{}>", descriptor.cpp_field_type,
                         descriptor.default_value_template_arg);
    } else if (wrapper == "*") {
      return fmt::format("const {}*", descriptor.cpp_field_type);
    } else if (wrapper.size()) {
      return fmt::format("{}<{}>", wrapper, descriptor.cpp_field_type);
    }
    return std::string(descriptor.cpp_field_type);
  }

  void process(field_descriptor_t &descriptor) {
    std::string attribute;
    std::string_view initializer = " = {}";
    if (field_type_wrapper(descriptor).size() > 1)
      initializer = "";
    else if (descriptor.default_value.size()) {
      initializer = " = " + descriptor.default_value;
      if (descriptor.cpp_name == "bytes_with_zero") {
        std::string r = fmt::format("{}{}{} {}{};\n", indent(), attribute, field_type(descriptor), descriptor.cpp_name,
                                    initializer);
      }
    }
    fmt::format_to(target, "{}{}{} {}{};\n", indent(), attribute, field_type(descriptor), descriptor.cpp_name,
                   initializer);

    if (descriptor.cpp_name == "bytes_with_zero") {
      const char *rr = file.content.data() + 17060;
      int i = 0;
    }
  }

  void process(oneof_descriptor_t &descriptor, int32_t number) {
    if (number != descriptor.fields[0]->proto.number)
      return;

    if (descriptor.fields.size() > 1) {
      std::string types;

      fmt::format_to(target, "{}enum {}_oneof_case : int {{\n", indent(), descriptor.cpp_name);
      indent_num += 2;
      int index = 1;
      for (auto f : descriptor.fields) {
        const char *sep = (index != descriptor.fields.size()) ? "," : "";
        fmt::format_to(target, "{}{} = {}{}\n", indent(), f->cpp_name, index++, sep);
      }
      indent_num -= 2;
      fmt::format_to(target, "{}}};\n\n", indent());

      for (auto f : descriptor.fields) {
        types += (", " + f->cpp_field_type);
      }
      fmt::format_to(target, "{}std::variant<std::monostate{}> {};\n", indent(), types, descriptor.cpp_name);
    } else {
      auto f = descriptor.fields[0];
      std::string attribute;

      fmt::format_to(target, "{}{}std::optional<{}> {};\n", indent(), attribute, f->cpp_field_type, f->cpp_name);
    }
  }

  void process(enum_descriptor_t &descriptor) {
    fmt::format_to(target, "{}enum class {} {{\n", indent(), descriptor.cpp_name);
    indent_num += 2;
    int index = 0;
    for (auto &e : descriptor.proto.value) {
      char sep = (index++ == descriptor.proto.value.size() - 1) ? ' ' : ',';
      fmt::format_to(target, "{}{} = {}{}\n", indent(), resolve_keyword(e.name), e.number, sep);
    }

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());
  }

  void process(message_descriptor_t &descriptor) {
    if (descriptor.is_map_entry)
      return;
    for (auto &fwd : descriptor.forward_declarations) {
      fmt::format_to(target, "{}struct {};\n", indent(), fwd);
    }

    std::string attribute;

    fmt::format_to(target, "{}struct {}{} {{\n", indent(), attribute, descriptor.cpp_name);
    indent_num += 2;

    for (auto &e : descriptor.enums)
      process(*e);

    for (auto m : order_messages(descriptor.messages))
      process(*m);

    for (auto f : descriptor.fields) {
      if (!f->proto.oneof_index.has_value())
        process(*f);
      else {
        auto index = *f->proto.oneof_index;
        process(*(descriptor.oneofs[index]), f->proto.number);
      }
    }

    for (auto f : descriptor.extensions) {
      fmt::format_to(target, "\n{}constexpr auto {}();\n", indent(), f->cpp_name);
    }

    if (descriptor.proto.extension_range.size()) {
      if (!non_owning_mode) {
        fmt::format_to(target,
                       "\n"
                       "{0}struct extension_t {{\n"
                       "{0}  using pb_extension = {1};\n"
                       "{0}  hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;\n"
                       "{0}  bool operator==(const extension_t &other) const = default;\n"
                       "#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR\n"
                       "{0}auto operator <=> (const extension_t&) const = default;\n"
                       "#endif\n"
                       "{0}}} extensions;\n\n"
                       "{0}[[nodiscard]] auto get_extension(auto meta) const {{\n"
                       "{0}  return meta.read(extensions, std::monostate{{}});\n"
                       "{0}}}\n"
                       "{0}template<typename Meta>"
                       "{0}[[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {{\n"
                       "{0}  return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));\n"
                       "{0}}}\n"
                       "{0}template<typename Meta>"
                       "{0}requires Meta::is_repeated"
                       "{0}[[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename "
                       "Meta::element_type> value) {{\n"
                       "{0}  return meta.write(extensions, std::span{{value.begin(), value.end()}});\n"
                       "{0}}}\n"
                       "{0}bool has_extension(auto meta) const {{\n"
                       "{0}  return meta.element_of(extensions);\n"
                       "{0}}}\n",
                       indent(), descriptor.cpp_name);

      } else {
        fmt::format_to(
            target,
            "\n"
            "{0}struct extension_t {{\n"
            "{0}  using pb_extension = {1};\n"
            "{0}  std::span<std::pair<uint32_t, std::span<const std::byte>>> fields;\n"
            "{0}}} extensions;\n\n"
            "{0}[[nodiscard]] auto get_extension(auto meta) const {{\n"
            "{0}  return meta.read(extensions, std::monostate{{}});\n"
            "{0}}}\n"
            "{0}[[nodiscard]] auto get_extension(auto meta, hpp::proto::concepts::memory_resource auto &mr) const {{\n"
            "{0}  return meta.read(extensions, mr);\n"
            "{0}}}\n"
            "{0}template<typename Meta>\n"
            "{0}[[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value,\n"
            "{0}                                 hpp::proto::concepts::memory_resource auto &mr) {{\n"
            "{0}  return meta.write(extensions, std::forward<typename Meta::set_value_type>(value), mr);\n"
            "{0}}}\n"
            "{0}template<typename Meta>\n"
            "{0}requires Meta::is_repeated\n"
            "{0}[[nodiscard]] auto set_extension(Meta meta,\n"
            "{0}                                 std::initializer_list<typename Meta::element_type> value,\n"
            "{0}                                 hpp::proto::concepts::memory_resource auto &mr) {{\n"
            "{0}  return meta.write(extensions, std::span{{value.begin(), value.end()}}, mr);\n"
            "{0}}}\n"
            "{0}bool has_extension(auto meta) const {{\n"
            "{0}  return meta.element_of(extensions);\n"
            "{0}}}\n",
            indent(), descriptor.cpp_name);
      }
    }

    if (!non_owning_mode) {
      fmt::format_to(target,
                     "\n{0}bool operator == (const {1}&) const = default;\n"
                     "#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR\n"
                     "\n{0}auto operator <=> (const {1}&) const = default;\n"
                     "#endif\n",
                     indent(), descriptor.cpp_name);
    }

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());
  }
};

bool is_numeric(enum gpb::FieldDescriptorProto::Type type) {
  using enum gpb::FieldDescriptorProto::Type;
  return type != TYPE_MESSAGE || type != TYPE_STRING || type != TYPE_BYTES || type != TYPE_GROUP;
}

struct hpp_meta_generateor : code_generator {
  int syntax;
  using code_generator::code_generator;

  void process(file_descriptor_t &descriptor) {
    auto file_name = descriptor.proto.name;
    file.name = file_name.substr(0, file_name.size() - 5) + "pb.hpp";

    syntax = descriptor.syntax;
    fmt::format_to(target,
                   "#pragma once\n\n"
                   "#include <hpp_proto/pb_serializer.h>\n"
                   "#include <{}.msg.hpp>\n",
                   basename(descriptor.proto.name));
    for (auto &d : descriptor.proto.dependency)
      fmt::format_to(target, "#include <{}.pb.hpp>\n", basename(d));

    fmt::format_to(target, "\n");

    auto package = descriptor.proto.package;
    auto ns = qualified_cpp_name(package);

    if (ns.size())
      fmt::format_to(target,
                     "\nnamespace {} {{\n\n"
                     "using namespace zpp::bits::literals;\n\n",
                     root_namespace + ns);

    for (auto m : descriptor.messages)
      process(*m, "", package);

    for (auto f : descriptor.extensions)
      process(*f, "", package);

    if (ns.size())
      fmt::format_to(target, "}} // namespace {}\n", root_namespace + ns);
  }

  void process(message_descriptor_t &descriptor, const std::string &cpp_scope, const std::string &pb_scope) {
    std::string pb_name = descriptor.proto.name;
    if (pb_scope.size())
      pb_name = pb_scope + "." + pb_name;

    std::string qualified_cpp_name = descriptor.cpp_name;
    if (cpp_scope.size())
      qualified_cpp_name = cpp_scope + "::" + qualified_cpp_name;
    fmt::format_to(target, "auto pb_meta(const {} &) -> std::tuple<\n", qualified_cpp_name);
    indent_num += 2;

    uint32_t num_fields = 0;
    for (auto f : descriptor.fields) {
      if (!f->proto.oneof_index.has_value()) {
        process(*f, qualified_cpp_name, pb_name);
        num_fields++;
      } else {
        auto index = *f->proto.oneof_index;
        auto &oneof = *(descriptor.oneofs[index]);
        if (oneof.fields[0]->proto.number == f->proto.number) {
          process(oneof, qualified_cpp_name, pb_name);
          num_fields++;
        }
      }
    }

    if (descriptor.proto.extension_range.size()) {
      fmt::format_to(target, "{}hpp::proto::field_meta<UINT32_MAX>", indent());
    } else if (descriptor.fields.size()) {
      auto &content = file.content;
      content.resize(content.size() - 2);
    }
    indent_num -= 2;

    fmt::format_to(target, ">;\n\n");

    fmt::format_to(target, "auto serialize(const {}&) -> zpp::bits::members<{}>;\n\n", qualified_cpp_name,
                   num_fields + (descriptor.proto.extension_range.size() ? 1 : 0));

    if (num_fields > 50) {
      std::vector<int> v(num_fields);
      std::iota(v.begin(), v.end(), 0);
      auto args = fmt::format("a{}", fmt::join(v, ", a"));

      fmt::format_to(target,
                     "ZPP_BITS_INLINE constexpr decltype(auto) visit_members({0} &object, auto &&visitor) {{\n"
                     "  auto&& [{1}] = object;\n"
                     "  return visitor({1});\n"
                     "}}\n\n"
                     "ZPP_BITS_INLINE constexpr decltype(auto) visit_members(const {0} &object, auto &&visitor) {{\n"
                     "  auto&& [{1}] = object;\n"
                     "  return visitor({1});\n"
                     "}}\n\n",
                     qualified_cpp_name, args);
    }

    fmt::format_to(target,
                   "inline const char* pb_url(const {}&) {{ return "
                   "\"type.googleapis.com/{}\"; }}\n\n",
                   qualified_cpp_name, pb_name);

    for (auto f : descriptor.extensions)
      process(*f, qualified_cpp_name, pb_name);

    for (auto m : descriptor.messages) {
      if (!m->is_map_entry)
        process(*m, qualified_cpp_name, pb_name);
    }
  }

  void process(field_descriptor_t &descriptor, const std::string &cpp_scope, const std::string &pb_scope) {
    std::string_view rule = "defaulted";
    auto proto = descriptor.proto;
    using enum gpb::FieldDescriptorProto::Label;

    bool numeric = is_numeric(proto.type);

    if (descriptor.is_cpp_optional)
      rule = "explicit_presence";
    else if (proto.label == LABEL_REPEATED && numeric) {
      std::optional<bool> packed;
      if (proto.options.has_value() && proto.options->packed.has_value())
        packed = proto.options->packed.value();
      if ((packed.has_value() && !packed.value()) || (syntax == 2 && !packed.has_value()))
        rule = "unpacked_repeated";
    }

    if (proto.type == gpb::FieldDescriptorProto::Type::TYPE_GROUP) {
      rule = "group";
    }

    if (descriptor.map_fields[0]) {

      auto get_meta_type = [](const auto *field) {
        return field->cpp_meta_type == "void" ? field->cpp_field_type : field->cpp_meta_type;
      };

      descriptor.cpp_meta_type = fmt::format("hpp::proto::map_entry<{}, {}>", get_meta_type(descriptor.map_fields[0]),
                                             get_meta_type(descriptor.map_fields[1]));
    }

    std::string default_value;

    if (rule == "defaulted") {
      default_value = descriptor.default_value_template_arg;
    }

    std::string type_and_default_value;
    if (descriptor.cpp_meta_type != "void" || default_value.size()) {
      type_and_default_value = fmt::format(", {}", descriptor.cpp_meta_type);
      if (default_value.size()) {
        fmt::format_to(std::back_inserter(type_and_default_value), ", {}", default_value);
      }
    }

    if (proto.extendee.empty()) {
      fmt::format_to(target, "{}hpp::proto::field_meta<{}, hpp::proto::encoding_rule::{}{}>,\n", indent(), proto.number,
                     rule, type_and_default_value);
    } else {
      std::string_view extension_prefix;
      if (proto.label == LABEL_REPEATED)
        extension_prefix = "repeated_";
      type_and_default_value = fmt::format(
          ", {}, {}", descriptor.cpp_meta_type == "void" ? descriptor.cpp_field_type : descriptor.cpp_meta_type,
          descriptor.cpp_field_type);

      if (descriptor.default_value_template_arg.size()) {
        type_and_default_value += ", " + descriptor.default_value_template_arg;
      }

      auto cpp_name = cpp_scope.empty() ? descriptor.cpp_name : cpp_scope + "::" + descriptor.cpp_name;

      fmt::format_to(target,
                     "{0}constexpr auto {1}() {{\n"
                     "{0}  return hpp::proto::{2}extension_meta<{3}, {4}, "
                     "hpp::proto::encoding_rule::{5}{6}>{{}};\n"
                     "{0}}}\n\n",
                     indent(), cpp_name, extension_prefix, qualified_cpp_name(descriptor.proto.extendee), proto.number,
                     rule, type_and_default_value);
    }
  }

  void process(oneof_descriptor_t &descriptor, const std::string &cpp_scope, const std::string &pb_scope) {

    if (descriptor.fields.size() > 1) {
      std::string types;
      std::string sep;
      for (auto &f : descriptor.fields) {
        types += (sep + f->cpp_field_type);
        sep = ",";
      }
      fmt::format_to(target, "{}std::tuple<\n", indent());
      indent_num += 2;
      for (auto f : descriptor.fields)
        process(*f, cpp_scope, pb_scope);

      indent_num -= 2;
      if (descriptor.fields.size()) {
        auto &content = file.content;
        content.resize(content.size() - 2);
      }
      fmt::format_to(target, ">,\n");
    } else {
      process(*descriptor.fields[0], cpp_scope, pb_scope);
    }
  }

  void process(enum_descriptor_t &descriptor) {
    fmt::format_to(target, "{}enum class {} {{\n", indent(), descriptor.cpp_name);
    indent_num += 2;
    int index = 0;
    for (auto &e : descriptor.proto.value) {
      char sep = (index++ == descriptor.proto.value.size() - 1) ? ' ' : ',';
      fmt::format_to(target, "{}{} = {}{}\n", indent(), resolve_keyword(e.name), e.number, sep);
    }

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());
  }
};

struct glaze_meta_generator : code_generator {
  using code_generator::code_generator;

  void process(file_descriptor_t &descriptor) {
    auto file_name = descriptor.proto.name;
    file.name = file_name.substr(0, file_name.size() - 5) + "glz.hpp";
    fmt::format_to(target, "#pragma once\n\n"
                           "#include <hpp_proto/json_serializer.h>\n");

    for (auto &d : descriptor.proto.dependency)
      fmt::format_to(target, "#include <{}.glz.hpp>\n", basename(d));

    fmt::format_to(target, "#include <{}.msg.hpp>\n\n", basename(descriptor.proto.name));

    auto package = descriptor.proto.package;
    auto ns = root_namespace + qualified_cpp_name(package);
    for (auto m : descriptor.messages)
      process(*m, ns);

    for (auto e : descriptor.enums)
      process(*e, ns);
  }

  void process(message_descriptor_t &descriptor, const std::string &scope) {
    auto qualified_name = scope.size() ? scope + "::" + descriptor.cpp_name : descriptor.cpp_name;
    fmt::format_to(target,
                   "template <>\n"
                   "struct glz::meta<{0}> {{\n"
                   "  using T = {0};\n"
                   "  static constexpr auto value = object(\n",
                   qualified_name);

    for (auto f : descriptor.fields) {
      if (!f->proto.oneof_index.has_value()) {
        process(*f);
      } else {
        auto index = *f->proto.oneof_index;
        auto &oneof = *(descriptor.oneofs[index]);
        if (oneof.fields[0]->proto.number == f->proto.number) {
          process(oneof);
        }
      }
    }

    if (descriptor.fields.size()) {
      auto &content = file.content;
      content.resize(content.size() - 2);
    }

    fmt::format_to(target, ");\n}};\n\n");

    for (auto m : descriptor.messages) {
      if (!m->is_map_entry)
        process(*m, qualified_name);
    }

    for (auto e : descriptor.enums)
      process(*e, qualified_name);
  }

  void process(field_descriptor_t &descriptor) {
    using enum google::protobuf::FieldDescriptorProto::Type;
    using enum google::protobuf::FieldDescriptorProto::Label;

    if (descriptor.is_cpp_optional) {
      fmt::format_to(target, "    \"{}\", &T::{},\n", descriptor.proto.json_name, descriptor.cpp_name);
    } else if (descriptor.proto.label == LABEL_REQUIRED) {
      auto type = descriptor.proto.type;
      if (type == TYPE_INT64 || type == TYPE_UINT64 || type == TYPE_FIXED64 || type == TYPE_SFIXED64 ||
          type == TYPE_SINT64) {
        fmt::format_to(target, "    \"{}\", glz::quoted<&T::{}>(),\n", descriptor.proto.json_name, descriptor.cpp_name);
      } else {
        fmt::format_to(target, "    \"{}\", &T::{},\n", descriptor.proto.json_name, descriptor.cpp_name);
      }
    } else {
      std::string name_and_default_value = descriptor.cpp_name;
      if (descriptor.default_value_template_arg.size()) {
        name_and_default_value += ", " + descriptor.default_value_template_arg;
      }
      fmt::format_to(target, "    \"{}\", hpp::proto::as_optional_ref<&T::{}>(),\n", descriptor.proto.json_name,
                     name_and_default_value);
    }
  }

  void process(oneof_descriptor_t &descriptor) {
    if (descriptor.fields.size() > 1) {
      for (unsigned i = 0; i < descriptor.fields.size(); ++i) {
        fmt::format_to(target,
                       "    \"{}\", [](auto &&self) -> auto {{ return hpp::proto::wrap_oneof<{}>(self.{}); }},\n",
                       descriptor.fields[i]->proto.json_name, i + 1, descriptor.cpp_name);
      }
    } else {
      process(*descriptor.fields[0]);
    }
  }

  void process(enum_descriptor_t &descriptor, const std::string &scope) {
    auto qualified_name = scope.size() ? scope + "::" + descriptor.cpp_name : descriptor.cpp_name;
    fmt::format_to(target,
                   "template <>\n"
                   "struct glz::meta<{0}> {{\n"
                   "  using enum {0};\n"
                   "  static constexpr auto value = enumerate(\n",
                   qualified_name);

    indent_num += 4;
    int index = 0;
    for (auto &e : descriptor.proto.value) {
      const char *sep = (index++ == descriptor.proto.value.size() - 1) ? ");" : ",";
      fmt::format_to(target, "{0}\"{1}\", {1}{2}\n", indent(), resolve_keyword(e.name), sep);
    }

    indent_num -= 4;
    fmt::format_to(target, "}};\n\n", indent());
  }
};

int main(int argc, const char **argv) {

  std::vector<char> request_data;

  auto read_file = [&request_data](auto &&strm) {
    std::copy(std::istreambuf_iterator<char>(strm), std::istreambuf_iterator<char>(), std::back_inserter(request_data));
  };

  if (argc > 2 && std::string_view("--input") == argv[1]) {
    read_file(std::ifstream(argv[2]));
  } else {
    read_file(std::cin);
  }

  if (const char *env_p = std::getenv("HPP_GEN_EXPORT_REQUEST")) {
    std::ofstream out(env_p);
    std::copy(request_data.begin(), request_data.end(), std::ostreambuf_iterator<char>(out));
  }

  if (const char *env_p = std::getenv("HPP_EXPLICIT_PRESENCE")) {
    std::string s = env_p;
    std::size_t start_pos = 0;
    std::size_t end_pos;
    if (s.size()) {
      while ((end_pos = s.find(',', start_pos)) != std::string::npos) {
        force_optionals.emplace_back(s.substr(start_pos, end_pos - start_pos));
        start_pos = end_pos + 1;
      }
      force_optionals.emplace_back(s.substr(start_pos));
    }
  }

  if (const char *env_p = std::getenv("HPP_ROOT_NAMESPACE")) {
    root_namespace = env_p;
    if (!root_namespace.ends_with("::"))
      root_namespace += "::";
  }

  if (const char *env_p = std::getenv("HPP_NON_OWNING")) {
    non_owning_mode = strcmp("ON", env_p) == 0 || strcmp("TRUE", env_p) == 0 || strcmp("YES", env_p) == 0;
  }

  if (const char *env_p = std::getenv("HPP_TOP_DIRECTORY")) {
    top_directory = env_p;
  }

  gpb::compiler::CodeGeneratorRequest request;

  if (auto ec = hpp::proto::read_proto(request, request_data); ec) {
    fputs("hpp decode error", stderr);
    return 1;
  }

  hpp_gen_decriptor_pool pool(request.proto_file);

  for (auto &f : pool.fields) {
    using enum google::protobuf::FieldDescriptorProto::Type;
    if (f.proto.type_name.size() && (f.proto.type) == TYPE_MESSAGE) {
      auto m = pool.message_map[f.proto.type_name];
      if (m->is_map_entry) {
        f.map_fields[0] = m->fields[0];
        f.map_fields[1] = m->fields[1];
      }
    }
  }

  gpb::compiler::CodeGeneratorResponse response;
  response.supported_features = (uint64_t)gpb::compiler::CodeGeneratorResponse::Feature::FEATURE_PROTO3_OPTIONAL;

  for (const auto &file_name : request.file_to_generate) {
    auto itr = pool.file_map.find(file_name);
    assert(itr != pool.file_map.end());
    auto &descriptor = *(itr->second);

    msg_code_generator msg_code(response.file);
    msg_code.resolve_message_dependencies(pool);
    msg_code.process(descriptor);

    hpp_meta_generateor hpp_meta_code(response.file);
    hpp_meta_code.process(descriptor);

    glaze_meta_generator glz_meta_code(response.file);
    glz_meta_code.process(descriptor);
  }

  std::vector<char> data;
  if (auto ec = hpp::proto::write_proto(response, data); ec) {
    fputs("hpp encode error", stderr);
    return 1;
  }
  std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));

  return 0;
}