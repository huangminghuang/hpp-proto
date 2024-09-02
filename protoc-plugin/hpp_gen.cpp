// MIT License
//
// Copyright (c) 2024 Huang-Ming Huang
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
#include <hpp_proto/descriptor_pool.hpp>
#include <iostream>
#include <numeric>
#include <set>
#include <unordered_set>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace gpb = google::protobuf;
// NOLINTBEGIN(cert-err58-cpp)
const std::unordered_set<std::string_view> keywords = {
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
// NOLINTEND(cert-err58-cpp)

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
std::string plugin_name;
std::string plugin_parameters;
std::vector<std::string> proto2_explicit_presences;
std::string root_namespace;
std::string top_directory;
bool non_owning_mode = false;
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

std::string resolve_keyword(std::string_view name) {
  if (keywords.contains(name)) {
    return std::string(name) + "_";
  }
  return std::string(name);
}

std::string qualified_cpp_name(std::string_view name) {
  std::string result;
  std::size_t i = 0;
  std::size_t j = 0;
  while ((j = name.find('.', i)) != std::string_view::npos) {
    if (j == 0 && !root_namespace.empty()) {
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
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
  return cpp_escaped_len_table[static_cast<unsigned char>(c)];
  // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
}
// Calculates the length of the C-style escaped version of 'src'.
// Assumes that non-printable characters are escaped using octal sequences,
// and that UTF-8 bytes are not handled specially.
inline size_t cpp_escaped_len(std::string_view src) {
  size_t len = 0;
  for (const char c : src) {
    len += cpp_escaped_len(c);
  }
  return len;
}

std::string cpp_escape(std::string_view src) {
  const size_t escaped_len = cpp_escaped_len(src);
  if (escaped_len == src.size()) {
    return {src.data(), src.size()};
  }
  std::string result;
  result.reserve(escaped_len);
  auto itr = std::back_inserter(result);

  for (const char c : src) {
    const size_t char_len = cpp_escaped_len(c);
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
      default:
        break;
      }
    } else {
      *itr++ = '\\';
      // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
      *itr++ = static_cast<char>('0' + static_cast<unsigned char>(c) / 64);
      *itr++ = static_cast<char>('0' + (static_cast<unsigned char>(c) % 64) / 8);
      *itr++ = static_cast<char>('0' + static_cast<unsigned char>(c) % 8);
      // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }
  }
  return result;
}

std::string basename(const std::string &name) {
  std::string result = name.substr(0, name.find_last_of('.'));
  if (!top_directory.empty()) {
    result = top_directory + "/" + result;
  }
  return result;
}

std::size_t shared_scope_position(std::string_view s1, std::string_view s2) {
  std::size_t pos = std::mismatch(s1.begin(), s1.end(), s2.begin(), s2.end()).first - s1.begin();
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

template <typename T>
std::string to_hex(const T &data) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string result;
  result.resize(data.size() * 4);
  unsigned index = 0;
  for (auto b : data) {
    const auto c = static_cast<unsigned>(b);
    result[index++] = '\\';
    result[index++] = 'x';
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
    result[index++] = qmap[c >> 4U];
    result[index++] = qmap[c & 0x0FU];
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
  }
  return result;
}

struct hpp_addons {

  template <typename Derived>
  struct field_descriptor {
    std::string cpp_name;
    std::string cpp_field_type;
    std::string qualified_cpp_field_type;
    std::string cpp_meta_type = "void";
    std::string default_value;
    std::string default_value_template_arg;
    std::string_view qualified_parent_name;
    void *parent = nullptr;
    Derived *map_fields[2] = {nullptr, nullptr};
    bool is_recursive = false;
    bool is_cpp_optional = false;

    field_descriptor(const gpb::FieldDescriptorProto &proto, const std::string &parent_name)
        : cpp_name(resolve_keyword(proto.name)), qualified_parent_name(parent_name) {
      using enum gpb::FieldDescriptorProto::Type;
      using enum gpb::FieldDescriptorProto::Label;
      set_cpp_type(proto);
      set_default_value(proto);
    }

    void set_cpp_type(const gpb::FieldDescriptorProto &proto) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      switch (proto.type) {
      case TYPE_DOUBLE:
        cpp_field_type = "double";
        qualified_cpp_field_type = "double";
        break;
      case TYPE_FLOAT:
        cpp_field_type = "float";
        qualified_cpp_field_type = "float";
        break;
      case TYPE_INT64:
        cpp_field_type = "int64_t";
        qualified_cpp_field_type = "int64_t";
        cpp_meta_type = "hpp::proto::vint64_t";
        break;
      case TYPE_UINT64:
        cpp_field_type = "uint64_t";
        qualified_cpp_field_type = "uint64_t";
        cpp_meta_type = "hpp::proto::vuint64_t";
        break;
      case TYPE_INT32:
        cpp_field_type = "int32_t";
        qualified_cpp_field_type = "int32_t";
        cpp_meta_type = "hpp::proto::vint64_t";
        break;
      case TYPE_FIXED64:
        cpp_field_type = "uint64_t";
        qualified_cpp_field_type = "uint64_t";
        break;
      case TYPE_FIXED32:
        cpp_field_type = "uint32_t";
        qualified_cpp_field_type = "uint32_t";
        break;
      case TYPE_BOOL:
        cpp_field_type = "bool";
        qualified_cpp_field_type = "bool";
        cpp_meta_type = "bool";
        break;
      case TYPE_STRING:
        cpp_field_type = non_owning_mode ? "std::string_view" : "std::string";
        qualified_cpp_field_type = cpp_field_type;
        break;
      case TYPE_GROUP:
      case TYPE_MESSAGE:
      case TYPE_ENUM:
        if (!proto.type_name.empty()) {
          auto pos = shared_scope_position(qualified_parent_name, proto.type_name);

          is_recursive = (pos == proto.type_name.size());
          qualified_cpp_field_type = qualified_cpp_name(proto.type_name);
          if (pos == 0) {
            cpp_field_type = qualified_cpp_field_type;
          } else if (is_recursive) {
            cpp_field_type = resolve_keyword(proto.type_name.substr(proto.type_name.find_last_of('.') + 1));
          } else {
            cpp_field_type = qualified_cpp_name(proto.type_name.substr(pos + 1));
          }
        }
        break;
      case TYPE_BYTES:
        cpp_field_type = non_owning_mode ? "hpp::proto::bytes_view" : "hpp::proto::bytes";
        qualified_cpp_field_type = cpp_field_type;
        break;
      case TYPE_UINT32:
        cpp_field_type = "uint32_t";
        qualified_cpp_field_type = cpp_field_type;
        cpp_meta_type = "hpp::proto::vuint32_t";
        break;
      case TYPE_SFIXED32:
        cpp_field_type = "int32_t";
        qualified_cpp_field_type = cpp_field_type;
        break;
      case TYPE_SFIXED64:
        cpp_field_type = "int64_t";
        qualified_cpp_field_type = cpp_field_type;
        break;
      case TYPE_SINT32:
        cpp_field_type = "int32_t";
        qualified_cpp_field_type = cpp_field_type;
        cpp_meta_type = "hpp::proto::vsint32_t";
        break;
      case TYPE_SINT64:
        cpp_field_type = "int64_t";
        qualified_cpp_field_type = cpp_field_type;
        cpp_meta_type = "hpp::proto::vsint64_t";
        break;
      }
    }

    // NOLINTBEGIN(readability-function-cognitive-complexity)
    void set_default_value(const gpb::FieldDescriptorProto &proto) {
      using enum gpb::FieldDescriptorProto::Type;
      using enum gpb::FieldDescriptorProto::Label;

      if (!proto.default_value.empty()) {
        if (proto.type == TYPE_STRING) {
          if (!proto.default_value.empty()) {
            std::string escaped = cpp_escape(proto.default_value);
            default_value = fmt::format("\"{}\"", escaped);
            default_value_template_arg = fmt::format("hpp::proto::string_literal<\"{}\">{{}}", escaped);
          }
        } else if (proto.type == TYPE_BYTES) {
          if (!proto.default_value.empty()) {
            std::string escaped = cpp_escape(proto.default_value);
            default_value = fmt::format("hpp::proto::bytes_literal<\"{}\">{{}}", escaped);
            default_value_template_arg = fmt::format("hpp::proto::bytes_literal<\"{}\">{{}}", escaped);
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
                proto.default_value.find('e') == std::string::npos) {
              default_value = proto.default_value + ".0F";
            } else {
              default_value = proto.default_value + "F";
            }
          } else {
            default_value = fmt::format("double({})", proto.default_value);
          }

          const char *wrap_type = (proto.type == TYPE_DOUBLE) ? "DOUBLE" : "FLOAT";

          default_value_template_arg = fmt::format("HPP_PROTO_WRAP_{}({})", wrap_type, default_value);
        } else {
          const std::string_view typename_view = cpp_field_type;
          std::string suffix;
          if (typename_view[0] == 'u') {
            suffix = "U";
          }

          if (typename_view.substr(typename_view.size() - 4, 2) == "64") {
            suffix += "LL";
          }

          if (proto.default_value == "-9223372036854775808") {
            default_value = "-9223372036854775807LL-1";
          } else {
            default_value = fmt::format("{}{}", proto.default_value, suffix);
          }
          default_value_template_arg = default_value;
        }
      }
    }
    // NOLINTEND(readability-function-cognitive-complexity)
  };

  template <typename EnumD>
  struct enum_descriptor {
    std::string cpp_name;
    explicit enum_descriptor(const gpb::EnumDescriptorProto &proto) : cpp_name(resolve_keyword(proto.name)) {}
  };

  template <typename OneofD, typename FieldD>
  struct oneof_descriptor {
    std::vector<FieldD *> fields;
    std::string cpp_name;

    explicit oneof_descriptor(const gpb::OneofDescriptorProto &proto) : cpp_name(resolve_keyword(proto.name)) {}
  };

  template <typename MessageD, typename EnumD, typename OneofD, typename FieldD>
  struct message_descriptor {
    std::vector<FieldD *> fields;
    std::vector<EnumD *> enums;
    std::vector<MessageD *> messages;
    std::vector<OneofD *> oneofs;
    std::vector<FieldD *> extensions;

    std::string pb_name;
    std::string cpp_name;
    std::set<std::string> dependencies;
    std::set<FieldD *> used_by_fields;
    MessageD *message_parent = nullptr;
    void *file_parent = nullptr;
    std::set<std::string> forward_declarations;
    bool has_recursive_map_field = false;

    bool is_map_entry;

    explicit message_descriptor(const gpb::DescriptorProto &proto)
        : pb_name(proto.name), cpp_name(resolve_keyword(proto.name)),
          is_map_entry(proto.options.has_value() && proto.options->map_entry) {

      fields.reserve(proto.field.size());
      messages.reserve(proto.nested_type.size());
      enums.reserve(proto.enum_type.size());
      oneofs.reserve(proto.oneof_decl.size());
      extensions.reserve(proto.extension.size());
    }

    void add_field(FieldD &f) {
      f.parent = this;
      fields.push_back(&f);
      if (f.proto.oneof_index.has_value()) {
        oneofs[*f.proto.oneof_index]->fields.push_back(&f);
      }
    }
    void add_enum(EnumD &e) { enums.push_back(&e); }
    void add_message(MessageD &m) {
      m.message_parent = static_cast<MessageD *>(this);
      messages.push_back(&m);
    }
    void add_oneof(OneofD &o) { oneofs.push_back(&o); }
    void add_extension(FieldD &f) { extensions.push_back(&f); }
  };

  template <typename FileD, typename MessageD, typename EnumD, typename FieldD>
  struct file_descriptor {
    std::vector<MessageD *> messages;
    std::vector<EnumD *> enums;
    std::vector<FieldD *> extensions;
    std::vector<FileD *> dependencies;
    std::vector<std::string> dependency_names;

    std::string syntax;
    std::string cpp_namespace;
    std::string cpp_name;
    explicit file_descriptor(const gpb::FileDescriptorProto &proto)
        : syntax(proto.syntax.empty() ? std::string{"proto2"} : proto.syntax), cpp_name(proto.name) {

      messages.reserve(proto.message_type.size());
      enums.reserve(proto.enum_type.size());
      extensions.reserve(proto.extension.size());
      cpp_namespace = root_namespace + qualified_cpp_name(proto.package);
      std::replace_if(cpp_name.begin(), cpp_name.end(), [](unsigned char c) { return std::isalnum(c) == 0; }, '_');
      cpp_name = resolve_keyword(cpp_name);
    }
    void add_enum(EnumD &e) { enums.push_back(&e); }
    void add_message(MessageD &m) {
      m.file_parent = this;
      messages.push_back(&m);
    }
    void add_extension(FieldD &f) { extensions.push_back(&f); }

    void resolve_dependencies(const hpp::proto::flat_map<std::string, FileD *> &map) {
      auto &self = static_cast<FileD &>(*this);
      dependencies.resize(self.proto.dependency.size());
      std::transform(self.proto.dependency.begin(), self.proto.dependency.end(), dependencies.begin(),
                     [&map](auto &dep) { return map.at(dep); });
    }

    // NOLINTBEGIN(misc-no-recursion)
    const std::vector<std::string> &get_dependency_names() {
      if (dependency_names.empty()) {
        auto it = std::back_inserter(dependency_names);
        for (auto *dep : dependencies) {
          auto &names = dep->get_dependency_names();
          std::copy(names.begin(), names.end(), it);
        }
        std::sort(dependency_names.begin(), dependency_names.end());
        dependency_names.erase(std::unique(dependency_names.begin(), dependency_names.end()), dependency_names.end());
        dependency_names.push_back(cpp_name);
      }
      return dependency_names;
    }
    // NOLINTEND(misc-no-recursion)
  };
};

using hpp_gen_descriptor_pool = hpp::proto::descriptor_pool<hpp_addons>;

const static std::map<std::string, std::string> well_known_codecs = {{"google.protobuf.Duration", "duration_codec"},
                                                                     {"google.protobuf.Timestamp", "timestamp_codec"},
                                                                     {"google.protobuf.FieldMask", "field_mask_codec"}};

struct code_generator {
  std::size_t indent_num = 0;
  // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
  gpb::compiler::CodeGeneratorResponse::File &file;
  // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
  std::back_insert_iterator<std::string> target;

  using message_descriptor_t = hpp_gen_descriptor_pool::message_descriptor_t;
  using enum_descriptor_t = hpp_gen_descriptor_pool::enum_descriptor_t;
  using oneof_descriptor_t = hpp_gen_descriptor_pool::oneof_descriptor_t;
  using field_descriptor_t = hpp_gen_descriptor_pool::field_descriptor_t;
  using file_descriptor_t = hpp_gen_descriptor_pool::file_descriptor_t;

  static message_descriptor_t *message_parent_of(field_descriptor_t *f) {
    return static_cast<message_descriptor_t *>(f->parent);
  }

  static message_descriptor_t *message_parent_of(message_descriptor_t *m) { return m->message_parent; }

  explicit code_generator(std::vector<gpb::compiler::CodeGeneratorResponse::File> &files)
      : file(files.emplace_back()), target(file.content) {}

  [[nodiscard]] std::string_view indent() const {
    const int init_max_indent_spaces = 128;
    static std::string spaces(init_max_indent_spaces, ' ');
    if (indent_num > spaces.size()) {
      spaces.resize(indent_num);
    }
    return std::string_view{spaces.data(), indent_num};
  }

  // NOLINTBEGIN(misc-no-recursion)
  static void mark_field_recursive(message_descriptor_t &descriptor, const std::string &dep) {
    for (auto *f : descriptor.fields) {
      if (f->cpp_field_type == dep) {
        f->is_recursive = true;
      }
    }
    for (auto *m : descriptor.messages) {
      mark_field_recursive(*m, dep);
    }
  }
  // NOLINTEND(misc-no-recursion)

  static message_descriptor_t *resolve_container_dependency_cycle(std::vector<message_descriptor_t *> &unresolved) {
    // First, find the dependency which used the by repeated field
    for (auto *depended : unresolved) {
      std::map<message_descriptor_t *, bool> used_by_messages;
      for (auto *f : depended->used_by_fields) {
        auto *message = message_parent_of(f);
        if (std::find(unresolved.begin(), unresolved.end(), message) != unresolved.end()) {
          used_by_messages[message] |= (f->proto.label != gpb::FieldDescriptorProto::Label::LABEL_REPEATED);
          f->is_recursive = true;
        }
      }

      for (auto [m, no_non_repeated_usage] : used_by_messages) {
        if (!no_non_repeated_usage && !m->is_map_entry) {
          m->dependencies.erase(depended->cpp_name);
          m->forward_declarations.insert(depended->cpp_name);
          return m;
        }
      }
    }
    // find the dependency which used the by map field
    for (auto *depended : unresolved) {
      std::map<message_descriptor_t *, bool> used_by_messages;
      for (auto *f : depended->used_by_fields) {
        auto *message = message_parent_of(f);
        if (std::find(unresolved.begin(), unresolved.end(), message) != unresolved.end() || message->is_map_entry) {
          used_by_messages[message] |= !(message->is_map_entry);
          f->is_recursive = true;
        }
      }

      for (auto [m, no_non_map_usage] : used_by_messages) {
        if (!no_non_map_usage) {
          m->message_parent->has_recursive_map_field = true;
          m->message_parent->dependencies.erase(depended->cpp_name);
          m->message_parent->forward_declarations.insert(depended->cpp_name);
          return m->message_parent;
        }
      }
    }
    return nullptr;
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

    for (auto *m : messages) {
      if (m->dependencies.empty()) {
        resolved_messages.push_back(m);
        resolved_message_names.insert(m->cpp_name);
      } else {
        unresolved_messages.push_back(m);
      }
    }

    while (!unresolved_messages.empty()) {
      for (auto &pm : std::ranges::reverse_view{unresolved_messages}) {
        auto &deps = pm->dependencies;
        if (std::includes(resolved_message_names.begin(), resolved_message_names.end(), deps.begin(), deps.end())) {
          resolved_messages.push_back(pm);
          resolved_message_names.insert(pm->cpp_name);
          pm = nullptr;
        }
      }

      auto null_end = std::remove(unresolved_messages.begin(), unresolved_messages.end(), nullptr);
      if (null_end != unresolved_messages.end()) {
        unresolved_messages.erase(null_end, unresolved_messages.end());
      } else {
        message_descriptor_t *to_be_resolved = resolve_container_dependency_cycle(unresolved_messages);
        if (to_be_resolved != nullptr) {
          resolved_messages.push_back(to_be_resolved);
          unresolved_messages.erase(std::remove(unresolved_messages.begin(), unresolved_messages.end(), to_be_resolved),
                                    unresolved_messages.end());
          resolved_message_names.insert(to_be_resolved->cpp_name);
        } else {
          std::sort(unresolved_messages.begin(), unresolved_messages.end(),
                    [](auto lhs, auto rhs) { return lhs->cpp_name < rhs->cpp_name; });
          auto *x = *(unresolved_messages.rbegin());
          resolve_dependency_cycle(*x);
        }
      }
    }
    return resolved_messages;
  }

  void gen_file_header(const std::string &file) const {
    fmt::format_to(target,
                   "// Generated by the protocol buffer compiler.  DO NOT EDIT!\n"
                   "// NO CHECKED-IN PROTOBUF GENCODE\n"
                   "// generation command line:\n"
                   "//    protoc --plugin=protoc-gen-hpp={} --hpp_out {}:${{out_dir}} {}\n\n",
                   plugin_name, plugin_parameters, file);
  }
};

struct msg_code_generator : code_generator {
  std::string syntax;
  std::string out_of_class_data;
  std::back_insert_iterator<std::string> out_of_class_target;

  explicit msg_code_generator(std::vector<gpb::compiler::CodeGeneratorResponse::File> &files)
      : code_generator(files), out_of_class_target(out_of_class_data) {}

  static void resolve_message_dependencies(hpp_gen_descriptor_pool &pool) {
    for (auto &field : pool.fields) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      auto type = field.proto.type;
      if ((type == TYPE_MESSAGE || type == TYPE_GROUP || type == TYPE_ENUM) && !field.proto.type_name.empty()) {
        auto type_name = field.proto.type_name;
        auto message_name = field.qualified_parent_name;
        auto pos = shared_scope_position(message_name, type_name);
        std::string dependent;
        std::string dependee;
        if (pos > 0 && pos < message_name.size() && pos != type_name.size()) {
          auto dependent_pos = message_name.find_first_of('.', pos + 1);
          dependent = message_name.substr(0, dependent_pos);
          dependee = type_name.substr(pos + 1);
          auto dependee_pos = dependee.find('.');
          if (dependee_pos != std::string::npos) {
            dependee = dependee.substr(0, dependee_pos);
          } else if (type == TYPE_ENUM) {
            dependent = "";
          }
        }

        auto itr = pool.message_map.find(dependent);
        if (itr != pool.message_map.end()) {
          itr->second->dependencies.insert(qualified_cpp_name(dependee));
        }

        itr = pool.message_map.find(type_name);
        if (itr != pool.message_map.end()) {
          itr->second->used_by_fields.insert(&field);
        }

        if (type == TYPE_ENUM && field.proto.label == gpb::FieldDescriptorProto::Label::LABEL_OPTIONAL &&
            field.proto.default_value.empty()) {
          auto *enum_d = pool.find_type(pool.enum_map, type_name);
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
    gen_file_header(file_name);
    file.name = file_name.substr(0, file_name.size() - 5) + "msg.hpp";
    fmt::format_to(target, "#pragma once\n\n"
                           "#include <hpp_proto/field_types.hpp>\n");

    for (const auto &d : descriptor.proto.dependency) {
      fmt::format_to(target, "#include \"{}.msg.hpp\"\n", basename(d));
    }

    const auto &ns = descriptor.cpp_namespace;
    if (!ns.empty()) {
      fmt::format_to(target,
                     "\nnamespace {} {{\n"
                     "//NOLINTBEGIN(readability-redundant-member-init,performance-enum-size)\n\n",
                     ns);
    }

    for (auto *e : descriptor.enums) {
      process(*e);
    }

    for (auto *m : order_messages(descriptor.messages)) {
      process(*m, "", descriptor.proto.package);
    }

    std::copy(out_of_class_data.begin(), out_of_class_data.end(), target);

    if (!ns.empty()) {
      fmt::format_to(target,
                     "// NOLINTEND(readability-redundant-member-init,performance-enum-size)\n"
                     "}} // namespace {}\n",
                     ns);
    }
  }

  static std::string_view field_type_wrapper(field_descriptor_t &descriptor) {
    const auto &proto = descriptor.proto;
    using enum gpb::FieldDescriptorProto::Label;
    using enum gpb::FieldDescriptorProto::Type;
    if (proto.label == LABEL_REPEATED) {
      return non_owning_mode ? "std::span" : "std::vector";
    }
    if (descriptor.is_recursive) {
      return non_owning_mode ? "*" : "hpp::proto::heap_based_optional";
    }
    if (descriptor.is_cpp_optional) {
      if (proto.type == TYPE_GROUP || proto.type == TYPE_MESSAGE) {
        return "std::optional";
      }
      return "hpp::proto::optional";
    }
    return "";
  }

  static std::string field_type(field_descriptor_t &descriptor) {
    if (descriptor.map_fields[0] != nullptr) {
      if (!non_owning_mode) {
        const char *type = "hpp::proto::flat_map";
        // when using flat_map with bool, it would lead std::vector<bool> as one of its members; which is not what we
        // need.
        auto transform_if_bool = [](const std::string &name) {
          return (name == "bool") ? std::string{"hpp::proto::boolean"} : name;
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
    } else if (wrapper == "hpp::proto::optional" && !descriptor.default_value_template_arg.empty()) {
      return fmt::format("hpp::proto::optional<{},{}>", descriptor.cpp_field_type,
                         descriptor.default_value_template_arg);
    } else if (wrapper == "*") {
      return fmt::format("const {}*", descriptor.cpp_field_type);
    } else if (wrapper == "std::span") {
      return fmt::format("{}<const {}>", wrapper, descriptor.cpp_field_type);
    } else if (!wrapper.empty()) {
      return fmt::format("{}<{}>", wrapper, descriptor.cpp_field_type);
    }
    return descriptor.cpp_field_type;
  }

  void set_presence_rule(field_descriptor_t &descriptor) {
    using enum gpb::FieldDescriptorProto::Type;
    using enum gpb::FieldDescriptorProto::Label;
    std::string qualified_name = std::string{descriptor.qualified_parent_name} + "." + descriptor.proto.name;
    descriptor.is_cpp_optional =
        (descriptor.proto.label == LABEL_OPTIONAL) &&
        (descriptor.proto.type == TYPE_GROUP || descriptor.proto.type == TYPE_MESSAGE ||
         descriptor.proto.proto3_optional ||
         (syntax == "proto2" &&
          std::any_of(proto2_explicit_presences.begin(), proto2_explicit_presences.end(),
                      [&qualified_name](const auto &s) { return qualified_name.starts_with(s); })));
  }

  void process(field_descriptor_t &descriptor) {
    set_presence_rule(descriptor);
    std::string attribute;
    std::string initializer = " = {}";

    if (field_type_wrapper(descriptor).size() > 1) {
      initializer = "";
    } else if (!descriptor.default_value.empty()) {
      initializer = " = " + descriptor.default_value;
    }
    fmt::format_to(target, "{}{}{} {}{};\n", indent(), attribute, field_type(descriptor), descriptor.cpp_name,
                   initializer);
  }

  void process(oneof_descriptor_t &descriptor, int32_t number) {
    if (number != descriptor.fields[0]->proto.number) {
      return;
    }

    if (descriptor.fields.size() > 1) {
      std::string types;

      fmt::format_to(target, "{}enum {}_oneof_case : int {{\n", indent(), descriptor.cpp_name);
      indent_num += 2;
      std::size_t index = 1;
      for (auto *f : descriptor.fields) {
        const char *sep = (index != descriptor.fields.size()) ? "," : "";
        fmt::format_to(target, "{}{} = {}{}\n", indent(), f->cpp_name, index++, sep);
      }
      indent_num -= 2;
      fmt::format_to(target, "{}}};\n\n", indent());

      for (auto *f : descriptor.fields) {
        types += (", " + f->cpp_field_type);
      }
      fmt::format_to(target, "{}std::variant<std::monostate{}> {};\n", indent(), types, descriptor.cpp_name);
    } else {
      auto *f = descriptor.fields[0];
      std::string attribute;

      fmt::format_to(target, "{}{}std::optional<{}> {};\n", indent(), attribute, f->cpp_field_type, f->cpp_name);
    }
  }

  void process(enum_descriptor_t &descriptor) {
    fmt::format_to(target, "{}enum class {} {{\n", indent(), descriptor.cpp_name);
    indent_num += 2;
    std::size_t index = 0;
    for (const auto &e : descriptor.proto.value) {
      char sep = (index++ == descriptor.proto.value.size() - 1) ? ' ' : ',';
      fmt::format_to(target, "{}{} = {}{}\n", indent(), resolve_keyword(e.name), e.number, sep);
    }

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());
  }

  // NOLINTBEGIN(misc-no-recursion,readability-function-cognitive-complexity)
  void process(message_descriptor_t &descriptor, const std::string &cpp_scope, const std::string &pb_scope) {
    if (descriptor.is_map_entry) {
      return;
    }

    if (!pb_scope.empty()) {
      descriptor.pb_name = pb_scope + "." + descriptor.pb_name;
    }

    std::string qualified_cpp_name = descriptor.cpp_name;
    if (!cpp_scope.empty()) {
      qualified_cpp_name = cpp_scope + "::" + qualified_cpp_name;
    }

    for (const auto &fwd : descriptor.forward_declarations) {
      fmt::format_to(target, "{}struct {};\n", indent(), fwd);
    }

    std::string attribute;

    fmt::format_to(target, "{}struct {}{} {{\n", indent(), attribute, descriptor.cpp_name);
    indent_num += 2;

    if (well_known_codecs.contains(descriptor.pb_name)) {
      fmt::format_to(target, "{}constexpr static bool glaze_reflect = false;\n", indent());
    }

    for (auto &e : descriptor.enums) {
      process(*e);
    }

    for (auto *m : order_messages(descriptor.messages)) {
      process(*m, qualified_cpp_name, descriptor.pb_name);
    }

    for (auto *f : descriptor.fields) {
      set_presence_rule(*f);
      if (!f->proto.oneof_index.has_value()) {
        process(*f);
      } else {
        auto index = *f->proto.oneof_index;
        process(*(descriptor.oneofs[index]), f->proto.number);
      }
    }

    for (auto *f : descriptor.extensions) {
      fmt::format_to(target, "\n{}static constexpr auto {}();\n", indent(), f->cpp_name);
    }

    if (!descriptor.proto.extension_range.empty()) {
      if (!non_owning_mode) {
        fmt::format_to(target,
                       "\n"
                       "{0}struct extension_t {{\n"
                       "{0}  using pb_extension = {1};\n"
                       "{0}  hpp::proto::flat_map<uint32_t, std::vector<std::byte>> fields;\n"
                       "{0}  bool operator==(const extension_t &other) const = default;\n"
                       "{0}}} extensions;\n\n"
                       "{0}[[nodiscard]] auto get_extension(auto meta) const {{\n"
                       "{0}  return meta.read(extensions);\n"
                       "{0}}}\n"
                       "{0}template<typename Meta>\n"
                       "{0}[[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value) {{\n"
                       "{0}  return meta.write(extensions, std::move(value));\n"
                       "{0}}}\n"
                       "{0}template<typename Meta>\n"
                       "{0}requires Meta::is_repeated\n"
                       "{0}[[nodiscard]] auto set_extension(Meta meta, std::initializer_list<typename "
                       "Meta::element_type> value) {{\n"
                       "{0}  return meta.write(extensions, std::span{{value.begin(), value.end()}});\n"
                       "{0}}}\n"
                       "{0}[[nodiscard]] bool has_extension(auto meta) const {{\n"
                       "{0}  return meta.element_of(extensions);\n"
                       "{0}}}\n",
                       indent(), descriptor.cpp_name);

      } else {
        fmt::format_to(target,
                       "\n"
                       "{0}struct extension_t {{\n"
                       "{0}  using pb_extension = {1};\n"
                       "{0}  std::span<std::pair<uint32_t, hpp::proto::bytes_view>> fields;\n"
                       "{0}}} extensions;\n\n"
                       "{0}[[nodiscard]] auto get_extension(auto meta, hpp::proto::concepts::is_pb_context auto && "
                       "...ctx) const {{\n"
                       "{0}  static_assert(sizeof...(ctx) <= 1);\n"
                       "{0}  return meta.read(extensions, ctx...);\n"
                       "{0}}}\n"
                       "{0}template<typename Meta>\n"
                       "{0}[[nodiscard]] auto set_extension(Meta meta, typename Meta::set_value_type &&value,\n"
                       "{0}                                 hpp::proto::concepts::is_pb_context auto &&ctx) {{\n"
                       "{0}  return meta.write(extensions, std::move(value), ctx);\n"
                       "{0}}}\n"
                       "{0}template<typename Meta>\n"
                       "{0}requires Meta::is_repeated\n"
                       "{0}[[nodiscard]] auto set_extension(Meta meta,\n"
                       "{0}                                 std::initializer_list<typename Meta::element_type> value,\n"
                       "{0}                                 hpp::proto::concepts::is_pb_context auto &&ctx) {{\n"
                       "{0}  return meta.write(extensions, std::span{{value.begin(), value.end()}}, ctx);\n"
                       "{0}}}\n"
                       "{0}[[nodiscard]] bool has_extension(auto meta) const {{\n"
                       "{0}  return meta.element_of(extensions);\n"
                       "{0}}}\n",
                       indent(), descriptor.cpp_name);
      }
    }

    if (!non_owning_mode) {
      fmt::format_to(target, "\n{0}bool operator == (const {1}&) const = default;\n", indent(), descriptor.cpp_name);

    } else {
      bool need_explicit_constructors = false;
      for (auto *f : descriptor.fields) {
        if (f->is_recursive && f->proto.label == gpb::FieldDescriptorProto::Label::LABEL_REPEATED) {
          need_explicit_constructors = true;
        }
      }

      if (need_explicit_constructors) {
        std::string copy_constructor_init_list;
        int i = 0;
        for (auto *f : descriptor.fields) {
          if (i > 0) {
            copy_constructor_init_list += ",";
          }
          if (f->is_recursive && f->proto.label == gpb::FieldDescriptorProto::Label::LABEL_REPEATED) {
            copy_constructor_init_list += fmt::format("{0}(other.{0}.data(), other.{0}.size())", f->cpp_name);
          } else {
            copy_constructor_init_list += fmt::format("{0}(other.{0})", f->cpp_name);
          }
          ++i;
        }

        fmt::format_to(target,
                       "#ifdef _LIBCPP_VERSION\n"
                       "{0}constexpr {1}() noexcept = default;\n"
                       "{0}constexpr {1}(const {1}& other) noexcept\n"
                       "{0}  : {2}{{}}\n"
                       "{0}constexpr {1}& operator=(const {1}& other) noexcept = default;\n"
                       "#endif // _LIBCPP_VERSION\n",
                       indent(), descriptor.cpp_name, copy_constructor_init_list);
      }
    }

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());
    fmt::format_to(out_of_class_target,
                   "constexpr auto message_type_url(const {0}&) {{ return "
                   "hpp::proto::string_literal<\"type.googleapis.com/{1}\">{{}}; }}\n",
                   qualified_cpp_name, descriptor.pb_name);
  }
  // NOLINTEND(misc-no-recursion,readability-function-cognitive-complexity)
};

bool is_numeric(enum gpb::FieldDescriptorProto::Type type) {
  using enum gpb::FieldDescriptorProto::Type;
  return type != TYPE_MESSAGE && type != TYPE_STRING && type != TYPE_BYTES && type != TYPE_GROUP;
}

struct hpp_meta_generator : code_generator {
  std::string syntax;
  using code_generator::code_generator;

  void process(file_descriptor_t &descriptor) {
    auto file_name = descriptor.proto.name;
    gen_file_header(file_name);
    file.name = file_name.substr(0, file_name.size() - 5) + "pb.hpp";

    syntax = descriptor.syntax;
    fmt::format_to(target,
                   "#pragma once\n\n"
                   "#include <hpp_proto/pb_serializer.hpp>\n"
                   "#include \"{}.msg.hpp\"\n",
                   basename(descriptor.proto.name));
    for (const auto &d : descriptor.proto.dependency) {
      fmt::format_to(target, "#include \"{}.pb.hpp\"\n", basename(d));
    }

    fmt::format_to(target, "\n");

    auto package = descriptor.proto.package;
    auto ns = qualified_cpp_name(package);

    if (!ns.empty()) {
      fmt::format_to(target, "\nnamespace {} {{\n\n", root_namespace + ns);
    }

    for (auto *m : descriptor.messages) {
      process(*m, "", package);
    }

    for (auto *f : descriptor.extensions) {
      process(*f, "", 0UL);
    }

    if (!ns.empty()) {
      fmt::format_to(target, "}} // namespace {}\n", root_namespace + ns);
    }
  }

  // NOLINTBEGIN(misc-no-recursion)
  void process(message_descriptor_t &descriptor, const std::string &cpp_scope, const std::string &pb_scope) {
    std::string pb_name = descriptor.proto.name;
    if (!pb_scope.empty()) {
      pb_name = pb_scope + "." + pb_name;
    }

    std::string qualified_cpp_name = descriptor.cpp_name;
    if (!cpp_scope.empty()) {
      qualified_cpp_name = cpp_scope + "::" + qualified_cpp_name;
    }
    fmt::format_to(target, "auto pb_meta(const {} &) -> std::tuple<\n", qualified_cpp_name);
    indent_num += 2;

    for (auto *f : descriptor.fields) {
      if (!f->proto.oneof_index.has_value()) {
        process(*f, qualified_cpp_name, 0UL);
      } else {
        auto index = *f->proto.oneof_index;
        auto &oneof = *(descriptor.oneofs[index]);
        if (oneof.fields[0]->proto.number == f->proto.number) {
          process(oneof, qualified_cpp_name, pb_name);
        }
      }
    }

    if (!descriptor.proto.extension_range.empty()) {
      fmt::format_to(target, "{}hpp::proto::field_meta<UINT32_MAX, &{}::extensions>", indent(), qualified_cpp_name);
    } else if (!descriptor.fields.empty()) {
      auto &content = file.content;
      content.resize(content.size() - 2);
    }
    indent_num -= 2;

    fmt::format_to(target, ">;\n\n");

    for (auto *f : descriptor.extensions) {
      process(*f, qualified_cpp_name, 0UL);
    }

    for (auto *m : descriptor.messages) {
      if (!m->is_map_entry) {
        process(*m, qualified_cpp_name, pb_name);
      }
    }
  }
  // NOLINTEND(misc-no-recursion)
  // NOLINTBEGIN(readability-function-cognitive-complexity)
  void process(field_descriptor_t &descriptor, const std::string &cpp_scope, std::size_t oneof_index) {
    std::string_view options = (oneof_index) == 0 ? "none" : "explicit_presence";
    auto proto = descriptor.proto;
    using enum gpb::FieldDescriptorProto::Label;

    const bool numeric = is_numeric(proto.type);

    if (descriptor.is_cpp_optional || descriptor.proto.label == LABEL_REQUIRED) {
      options = "explicit_presence";
    } else if (proto.label == LABEL_REPEATED) {
      if (numeric) {
        std::optional<bool> packed;
        if (proto.options.has_value() && proto.options->packed.has_value()) {
          packed = proto.options->packed.value();
        }
        if ((packed.has_value() && !packed.value()) || (syntax == "proto2" && !packed.has_value())) {
          options = "unpacked_repeated";
        } else {
          options = "none";
        }
      } else {
        options = "unpacked_repeated";
      }
    }

    if (proto.type == gpb::FieldDescriptorProto::Type::TYPE_GROUP) {
      options = "group";
    }

    if (descriptor.map_fields[0] != nullptr) {

      auto get_meta_type = [](const auto *field) {
        return field->cpp_meta_type == "void" ? field->qualified_cpp_field_type : field->cpp_meta_type;
      };

      descriptor.cpp_meta_type = fmt::format("hpp::proto::map_entry<{}, {}>", get_meta_type(descriptor.map_fields[0]),
                                             get_meta_type(descriptor.map_fields[1]));
    }

    std::string default_value;

    if (options == "none") {
      default_value = descriptor.default_value_template_arg;
    }

    std::string type_and_default_value;
    if (descriptor.cpp_meta_type != "void" || !default_value.empty()) {
      type_and_default_value = fmt::format(", {}", descriptor.cpp_meta_type);
      if (!default_value.empty()) {
        fmt::format_to(std::back_inserter(type_and_default_value), ", {}", default_value);
      }
    }

    auto cpp_name = cpp_scope.empty() ? descriptor.cpp_name : cpp_scope + "::" + descriptor.cpp_name;

    std::string access = (oneof_index == 0) ? "&" + cpp_name : std::to_string(oneof_index);

    if (proto.extendee.empty()) {
      fmt::format_to(target, "{}hpp::proto::field_meta<{}, {}, hpp::proto::field_option::{}{}>,\n", indent(),
                     proto.number, access, options, type_and_default_value);
    } else {
      std::string_view extension_prefix;
      if (proto.label == LABEL_REPEATED) {
        extension_prefix = "repeated_";
      }
      type_and_default_value = fmt::format(
          ", {}, {}", descriptor.cpp_meta_type == "void" ? descriptor.cpp_field_type : descriptor.cpp_meta_type,
          descriptor.cpp_field_type);

      if (!descriptor.default_value_template_arg.empty()) {
        type_and_default_value += ", " + descriptor.default_value_template_arg;
      }

      fmt::format_to(target,
                     "{0}constexpr auto {1}() {{\n"
                     "{0}  return hpp::proto::{2}extension_meta<{3}, {4}, "
                     "hpp::proto::field_option::{5}{6}>{{}};\n"
                     "{0}}}\n\n",
                     indent(), cpp_name, extension_prefix, qualified_cpp_name(descriptor.proto.extendee), proto.number,
                     options, type_and_default_value);
    }
  }
  // NOLINTEND(readability-function-cognitive-complexity)

  void process(oneof_descriptor_t &descriptor, const std::string &cpp_scope, const std::string & /* unused */) {

    if (descriptor.fields.size() > 1) {
      std::string types;
      std::string sep;
      for (auto &f : descriptor.fields) {
        types += (sep + f->cpp_field_type);
        sep = ",";
      }
      fmt::format_to(target, "{}hpp::proto::oneof_field_meta<\n", indent());
      indent_num += 2;
      fmt::format_to(target, "{}&{}::{},\n", indent(), cpp_scope, descriptor.cpp_name);
      std::size_t i = 0;
      for (auto *f : descriptor.fields) {
        process(*f, cpp_scope, ++i);
      }

      indent_num -= 2;
      if (!descriptor.fields.empty()) {
        auto &content = file.content;
        content.resize(content.size() - 2);
      }
      fmt::format_to(target, ">,\n");
    } else {
      process(*descriptor.fields[0], cpp_scope, 0);
    }
  }

  void process(enum_descriptor_t &descriptor) {
    // NOLINTBEGIN
    fmt::format_to(target, "{}enum class {} {{\n", indent(), descriptor.cpp_name);
    // NOLINTEND
    indent_num += 2;
    std::size_t index = 0;
    for (const auto &e : descriptor.proto.value) {
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
    gen_file_header(file_name);
    file.name = file_name.substr(0, file_name.size() - 5) + "glz.hpp";

    std::string sole_message_name;
    if (descriptor.messages.size() == 1) {
      sole_message_name = descriptor.messages[0]->pb_name;
    }

    if (sole_message_name != "google.protobuf.Any") {
      fmt::format_to(target, "#pragma once\n\n"
                             "#include <hpp_proto/json_serializer.hpp>\n");

      for (const auto &d : descriptor.proto.dependency) {
        fmt::format_to(target, "#include \"{}.glz.hpp\"\n", basename(d));
      }

      fmt::format_to(target, "#include \"{}.msg.hpp\"\n\n", basename(descriptor.proto.name));

      if (!sole_message_name.empty() && well_known_codecs.contains(sole_message_name)) {
        fmt::format_to(target, "#include <hpp_proto/{}.hpp>\n\n", well_known_codecs.at(sole_message_name));
      }
    } else {
      fmt::format_to(target,
                     "#pragma once\n\n"
                     "#include <hpp_proto/dynamic_serializer.hpp>\n\n"
                     "#include \"{}.msg.hpp\"\n\n",
                     basename(descriptor.proto.name));
    }

    auto package = descriptor.proto.package;
    auto ns = root_namespace + qualified_cpp_name(package);

    for (auto *m : descriptor.messages) {
      process(*m, ns);
    }

    for (auto *e : descriptor.enums) {
      process(*e, ns);
    }
  }

  // NOLINTBEGIN(misc-no-recursion,readability-function-cognitive-complexity)
  void process(message_descriptor_t &descriptor, const std::string &scope) {
    auto qualified_name = !scope.empty() ? scope + "::" + descriptor.cpp_name : descriptor.cpp_name;

    const static std::set<std::string> well_known_wrapper_types = {
        "google.protobuf.DoubleValue", "google.protobuf.FloatValue",  "google.protobuf.Int64Value",
        "google.protobuf.UInt64Value", "google.protobuf.Int32Value",  "google.protobuf.UInt32Value",
        "google.protobuf.BoolValue",   "google.protobuf.StringValue", "google.protobuf.BytesValue"};

    if (well_known_wrapper_types.contains(descriptor.pb_name)) {
      std::string opts = "Opts";
      if (descriptor.pb_name == "google.protobuf.Int64Value" || descriptor.pb_name == "google.protobuf.UInt64Value") {
        opts = "opt_true<Opts, &opts::quoted_num>";
      }
      fmt::format_to(target,
                     "namespace glz::detail {{\n"
                     "template <>\n"
                     "struct to_json<{0}> {{\n"
                     "template <auto Opts>\n"
                     "  GLZ_ALWAYS_INLINE static void op(auto &&value, auto&& ...args) {{\n"
                     "    write<json>::template op<{1}>(value.value, "
                     "std::forward<decltype(args)>(args)...);\n"
                     "  }}\n"
                     "}};\n\n"
                     "template <>\n"
                     "struct from_json<{0}> {{\n"
                     "template <auto Opts>\n"
                     "  GLZ_ALWAYS_INLINE static void op(auto &value, auto&& ...args) {{\n"
                     "    read<json>::template op<{1}>(value.value, "
                     "std::forward<decltype(args)>(args)...);\n"
                     "  }}\n"
                     "}};\n"
                     "}} // namespace glz::detail\n\n",
                     qualified_name, opts);
    } else if (well_known_codecs.contains(descriptor.pb_name)) {
      fmt::format_to(target,
                     "template <>\n"
                     "struct hpp::proto::json_codec<{0}> {{\n"
                     "  using type = hpp::proto::{1};\n"
                     "}};\n\n",
                     qualified_name, well_known_codecs.at(descriptor.pb_name));
    } else if (descriptor.pb_name == "google.protobuf.Value") {
      fmt::format_to(target,
                     // clang-format off
                     "namespace glz::detail {{\n"
                     "template <>\n"
                     "struct to_json<{0}> {{\n"
                     "  template <auto Opts>\n"
                     "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&b, auto &&ix) {{\n"
                     "    std::visit(\n"
                     "        [&ctx, &b, &ix](auto &v) {{\n"
                     "          using type = std::decay_t<decltype(v)>;\n"
                     "          if constexpr (std::same_as<type, {1}::ListValue>) {{\n"
                     "            write<json>::template op<Opts>(v.values, ctx, b, ix);\n"
                     "          }} else if constexpr (std::same_as<type, {1}::Struct>) {{\n"
                     "            write<json>::template op<Opts>(v.fields, ctx, b, ix);\n"
                     "          }} else if constexpr (!std::same_as<type, std::monostate>) {{\n"
                     "            write<json>::template op<Opts>(v, ctx, b, ix);\n"
                     "          }}\n"
                     "        }},\n"
                     "        value.kind);\n"
                     "  }}\n"
                     "}};\n\n"                    
                     "template <>\n"
                     "struct from_json<{0}> {{\n"
                     "  template <auto Options>\n"
                     "  static void op(auto &&value, is_context auto &&ctx, auto &&it, auto &&end) {{\n"
                     "    if constexpr (!has_ws_handled(Options)) {{\n"
                     "      skip_ws<Options>(ctx, it, end);\n"
                     "      if (bool(ctx.error)) [[unlikely]]{{\n"
                     "        return;\n"
                     "      }}\n"
                     "    }}\n"
                     "    static constexpr auto Opts = ws_handled_off<Options>();\n"
                     "    if (*it == 'n') {{\n"
                     "      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)\n"
                     "      ++it;\n"
                     "      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)\n"
                     "      match<\"ull\", Opts>(ctx, it, end);\n"
                     "      if (bool(ctx.error)) [[unlikely]]{{\n"
                     "        return;\n"
                     "      }}\n"
                     "      value.kind.template emplace<{1}::NullValue>();\n"
                     "    }} else if ((*it >= '0' && *it <= '9') || *it == '-') {{\n"
                     "      read<json>::op<Opts>(value.kind.template emplace<double>(), ctx, it, end);\n"
                     "    }} else if (*it == '\"') {{\n"
                     "      read<json>::op<Opts>(value.kind.template emplace<{0}::kind_oneof_case::string_value>(), ctx, it, end);\n"
                     "    }} else if (*it == 't' || *it == 'f') {{\n"
                     "      read<json>::op<Opts>(value.kind.template emplace<bool>(), ctx, it, end);\n"
                     "    }} else if (*it == '{{') {{\n"
                     "      read<json>::op<Opts>(value.kind.template emplace<{0}::kind_oneof_case::struct_value>().fields, ctx, it, end);\n"
                     "    }} else if (*it == '[') {{\n"
                     "      read<json>::op<Opts>(value.kind.template emplace<{0}::kind_oneof_case::list_value>().values, ctx, it, end);\n"
                     "    }}\n"
                     "  }}\n"
                     "}};\n"
                     "}} // namespace glz::detail\n\n",
                     // clang-format on
                     qualified_name, scope);
    } else if (descriptor.pb_name == "google.protobuf.Any") {
      fmt::format_to(
          target,
          "namespace glz::detail {{\n"
          "template <>\n"
          "struct to_json<{0}> {{\n"
          "  template <auto Opts, class B>"
          "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, B &b, auto &&ix) noexcept {{\n"
          "    if constexpr (requires {{ ctx.template get<hpp::proto::dynamic_serializer>(); }}) {{\n"
          "      auto &dyn_serializer = ctx.template get<hpp::proto::dynamic_serializer>();\n\n"
          "      if constexpr (!has_opening_handled(Opts)) {{\n"
          "        glz::detail::dump<'{{'>(b, ix);\n"
          "        if constexpr (Opts.prettify) {{\n"
          "          ctx.indentation_level += Opts.indentation_width;\n"
          "          glz::detail::dump<'\\n'>(b, ix);\n"
          "          glz::detail::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);\n"
          "        }}\n"
          "      }}\n"
          "      dyn_serializer.template to_json_any<Opts>(value, ctx, b, ix);\n"
          "    }} else {{\n"
          "      static_assert(!sizeof(value), \"JSON serialization for Any message requires `dynamic_serializer` in "
          "the context\");\n"
          "    }}\n"
          "  }}\n"
          "}};\n\n"
          "template <>\n"
          "struct from_json<{0}> {{\n"
          "  template <auto Options, class It, class End>\n"
          "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, It &&it, End &&end) {{\n"
          "    if constexpr (requires {{ ctx.template get<hpp::proto::dynamic_serializer>(); }}) {{\n"
          "      auto &dyn_serializer = ctx.template get<hpp::proto::dynamic_serializer>();\n"
          "      return dyn_serializer.template from_json_any<Options>(value, ctx, std::forward<It>(it), "
          "std::forward<End>(end));\n"
          "    }} else {{\n"
          "      static_assert(!sizeof(value),\n"
          "                    \"JSON deserialization for Any message requires `dynamic_serializer` in the "
          "context\");\n"
          "    }}\n"
          "  }}\n"
          "}};\n"
          "}} // namespace glz::detail\n",
          qualified_name);

    } else {
      fmt::format_to(target,
                     "template <>\n"
                     "struct glz::meta<{0}> {{\n"
                     "  using T = {0};\n"
                     "  static constexpr auto value = object(\n",
                     qualified_name);

      for (auto *f : descriptor.fields) {
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
      if (!descriptor.fields.empty()) {
        auto &content = file.content;
        content.resize(content.size() - 2);
      }

      fmt::format_to(target, ");\n}};\n\n");

      for (auto *m : descriptor.messages) {
        if (!m->is_map_entry) {
          process(*m, qualified_name);
        }
      }

      for (auto *e : descriptor.enums) {
        process(*e, qualified_name);
      }
    }
  }
  // NOLINTEND(misc-no-recursion,readability-function-cognitive-complexity)

  void process(field_descriptor_t &descriptor) {
    using enum google::protobuf::FieldDescriptorProto::Type;
    using enum google::protobuf::FieldDescriptorProto::Label;

    if (descriptor.is_cpp_optional && descriptor.proto.type != TYPE_BOOL) {
      // we remove operator! from hpp::optional<bool> to make the interface less confusing; however, this
      // make it unfulfilling the optional concept in glaze library; therefor, we need to apply as_optional_ref
      // as a workaround.
      fmt::format_to(target, "    \"{}\", &T::{},\n", descriptor.proto.json_name, descriptor.cpp_name);
    } else if (descriptor.proto.label == LABEL_REQUIRED) {
      auto type = descriptor.proto.type;
      if (type == TYPE_INT64 || type == TYPE_UINT64 || type == TYPE_FIXED64 || type == TYPE_SFIXED64 ||
          type == TYPE_SINT64) {
        fmt::format_to(target, "    \"{}\", glz::quoted_num<&T::{}>,\n", descriptor.proto.json_name,
                       descriptor.cpp_name);
      } else {
        fmt::format_to(target, "    \"{}\", &T::{},\n", descriptor.proto.json_name, descriptor.cpp_name);
      }
    } else {
      std::string name_and_default_value = descriptor.cpp_name;
      if (!descriptor.default_value_template_arg.empty()) {
        name_and_default_value += ", " + descriptor.default_value_template_arg;
      }
      fmt::format_to(target, "    \"{}\", hpp::proto::as_optional_ref<&T::{}>,\n", descriptor.proto.json_name,
                     name_and_default_value);
    }
  }

  void process(oneof_descriptor_t &descriptor) {
    if (descriptor.fields.size() > 1) {
      for (unsigned i = 0; i < descriptor.fields.size(); ++i) {
        fmt::format_to(target, "    \"{}\", hpp::proto::as_oneof_member<&T::{},{}>,\n",
                       descriptor.fields[i]->proto.json_name, descriptor.cpp_name, i + 1);
      }
    } else {
      process(*descriptor.fields[0]);
    }
  }

  void process(enum_descriptor_t &descriptor, const std::string &scope) {
    auto qualified_name = !scope.empty() ? scope + "::" + descriptor.cpp_name : descriptor.cpp_name;

    if (qualified_name != "google::protobuf::NullValue") {
      fmt::format_to(target,
                     "template <>\n"
                     "struct glz::meta<{0}> {{\n"
                     "  using enum {0};\n"
                     "  static constexpr auto value = enumerate(\n",
                     qualified_name);

      indent_num += 4;
      std::size_t index = 0;
      for (const auto &e : descriptor.proto.value) {
        const char *sep = (index++ == descriptor.proto.value.size() - 1) ? ");" : ",";
        fmt::format_to(target, "{0}\"{1}\", {1}{2}\n", indent(), resolve_keyword(e.name), sep);
      }

      indent_num -= 4;
      fmt::format_to(target, "}};\n\n", indent());
    } else {
      fmt::format_to(target,
                     "namespace glz::detail {{\n"
                     "template <>\n"
                     "struct to_json<{0}> {{\n"
                     "  template <auto Opts>\n"
                     "  GLZ_ALWAYS_INLINE static void op(auto &&, auto&& ...args) {{\n"
                     "    write<json>::template op<Opts>(std::monostate{{}}, std::forward<decltype(args)>(args)...);\n"
                     "  }}\n"
                     "}};\n\n"
                     "template <>\n"
                     "struct from_json<{0}> {{\n"
                     "  template <auto Opts>\n"
                     "  GLZ_ALWAYS_INLINE static void op(auto &value, auto&& ...args) {{\n"
                     "    read<json>::template op<Opts>(std::monostate{{}}, std::forward<decltype(args)>(args)...);\n"
                     "    value = {0}::NULL_VALUE;\n"
                     "  }}\n"
                     "}};\n"
                     "}}\n\n",
                     qualified_name);
    }
  }
};

struct desc_hpp_generator : code_generator {
  using code_generator::code_generator;

  void process(file_descriptor_t &descriptor) {
    auto path = descriptor.proto.name;
    gen_file_header(path);
    file.name = path.substr(0, path.size() - 5) + "desc.hpp";

    fmt::format_to(target, "#pragma once\n"
                           "#include <hpp_proto/dynamic_serializer.hpp>\n\n");

    for (const auto &d : descriptor.proto.dependency) {
      fmt::format_to(target, "#include \"{}.desc.hpp\"\n", basename(d));
    }

    const auto *const ns = "hpp::proto::file_descriptors";
    fmt::format_to(target, "\nnamespace {} {{\n\n", ns);

    std::vector<uint8_t> buf;
    (void)hpp::proto::write_proto(descriptor.proto, buf);

    fmt::format_to(target,
                   "using namespace std::literals::string_view_literals;\n"
                   "constexpr file_descriptor_pb _desc_{}{{\"{}\"sv}};\n\n",
                   descriptor.cpp_name, to_hex(buf));

    fmt::format_to(target, "inline auto desc_set_{}(){{\n", descriptor.cpp_name);
    const auto &dependency_names = descriptor.get_dependency_names();
    fmt::format_to(target, "  return std::array<file_descriptor_pb, {}> {{\n", dependency_names.size());
    for (const auto &p : dependency_names) {
      fmt::format_to(target, "    _desc_{},\n", p);
    }

    fmt::format_to(target,
                   "  }};\n"
                   "}}\n"
                   "}} //{}\n",
                   ns);
  }
};

void mark_map_entries(hpp_gen_descriptor_pool &pool) {
  for (auto &f : pool.fields) {
    using enum google::protobuf::FieldDescriptorProto::Type;
    if (!f.proto.type_name.empty() && (f.proto.type) == TYPE_MESSAGE) {
      auto *m = pool.message_map[f.proto.type_name];
      if (m->is_map_entry) {
        f.map_fields[0] = m->fields[0];
        f.map_fields[1] = m->fields[1];
      }
    }
  }
}

void split(std::string_view str, char deliminator, auto &&callback) {
  std::string_view::iterator pos = str.begin();
  while (pos < str.end()) {
    std::string_view::iterator next_pos = std::find(pos, str.end(), deliminator);
    callback(std::string_view{&*pos, static_cast<std::string_view::size_type>(next_pos - pos)});
    pos = next_pos + (next_pos == str.end() ? 0 : 1);
  }
}

int main(int argc, const char **argv) {
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  plugin_name = argv[0];
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  std::vector<char> request_data;

  auto read_file = [&request_data](auto &&strm) {
    std::copy(std::istreambuf_iterator<char>(strm), std::istreambuf_iterator<char>(), std::back_inserter(request_data));
  };

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  if (argc <= 2) {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
#endif
    read_file(std::cin);
  } else if (std::string_view("--input") == argv[1]) {
    read_file(std::ifstream(argv[2], std::ios::binary));
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  gpb::compiler::CodeGeneratorRequest request;

  if (auto ec = hpp::proto::read_proto(request, request_data); !ec.ok()) {
    (void)fputs("hpp decode error", stderr);
    return 1;
  }

  plugin_parameters = request.parameter;

  split(request.parameter, ',', [&request_data](auto opt) {
    auto equal_sign_pos = opt.find("=");
    auto opt_key = opt.substr(0, equal_sign_pos);
    auto opt_value = equal_sign_pos != std::string_view::npos ? opt.substr(equal_sign_pos + 1) : std::string_view{};

    if (opt_key == "top_directory") {
      top_directory = opt_value;
    } else if (opt_key == "root_namespace") {
      root_namespace = opt_value;
      if (!root_namespace.ends_with("::")) {
        root_namespace += "::";
      }
    } else if (opt_key == "non_owning") {
      non_owning_mode = true;
    } else if (opt_key == "proto2_explicit_presence") {
      proto2_explicit_presences.emplace_back(opt_value);
    } else if (opt_key == "export_request") {
      std::ofstream out{std::string(opt_value), std::ios::binary};
      std::copy(request_data.begin(), request_data.end(), std::ostreambuf_iterator<char>(out));
    }
  });

  if (proto2_explicit_presences.empty()) {
    proto2_explicit_presences.emplace_back(".");
  }

  // remove all source info
  for (auto &f : request.proto_file) {
    f.source_code_info.reset();
  }

  hpp_gen_descriptor_pool pool(request.proto_file);
  mark_map_entries(pool);

  gpb::compiler::CodeGeneratorResponse response;
  response.supported_features = (uint64_t)gpb::compiler::CodeGeneratorResponse::Feature::FEATURE_PROTO3_OPTIONAL;

  for (auto &f : pool.files) {
    f.resolve_dependencies(pool.file_map);
  }

  for (const auto &file_name : request.file_to_generate) {
    auto itr = pool.file_map.find(file_name);
    assert(itr != pool.file_map.end());
    auto &descriptor = *(itr->second);

    msg_code_generator msg_code(response.file);
    msg_code.resolve_message_dependencies(pool);
    msg_code.process(descriptor);

    hpp_meta_generator hpp_meta_code(response.file);
    hpp_meta_code.process(descriptor);

    glaze_meta_generator glz_meta_code(response.file);
    glz_meta_code.process(descriptor);

    if (!descriptor.messages.empty()) {
      desc_hpp_generator desc_hpp_code(response.file);
      desc_hpp_code.process(descriptor);
    }
  }

  std::vector<char> data;
  if (auto ec = hpp::proto::write_proto(response, data); !ec.ok()) {
    (void)fputs("hpp encode error", stderr);
    return 1;
  }

#ifdef _WIN32
  _setmode(_fileno(stdout), _O_BINARY);
#endif
  std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));

  return 0;
}