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
#include <iostream>
#include <numeric>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace gpb = google::protobuf;

gpb::compiler::CodeGeneratorRequest request;

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

std::string resolve_keyword(std::string_view name) {
  if (keywords.count(name) > 0) {
    return std::string(name) + "_";
  }
  return std::string(name);
}

std::string qualified_cpp_name(std::string_view name) {
  std::string result;
  auto append_component = [&result](std::string_view comp) {
    result += "::";
    result += resolve_keyword(comp);
  };

  std::size_t i = 0;
  std::size_t j;
  while ((j = name.find('.', i)) != std::string_view::npos) {
    if (j > 0)
      append_component(name.substr(i, j - i));
    i = j + 1;
  }
  append_component(name.substr(i));
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

std::string basename(const std::string &name) { return name.substr(0, name.find_last_of('.')); }

std::vector<std::string_view> split(std::string_view range, std::string_view separator) {
  std::vector<std::string_view> result;

  std::size_t j = 0;
  while ((j = range.find(separator)) != std::string_view::npos) {
    result.push_back(range.substr(0, j));
    range = range.substr(j + separator.size());
  }
  result.push_back(range.substr(0, j));
  return result;
}

std::size_t replace_all(std::string &inout, std::string_view what, std::string_view with) {
  std::size_t count{};
  for (std::string::size_type pos{}; inout.npos != (pos = inout.find(what.data(), pos, what.length()));
       pos += with.length(), ++count) {
    inout.replace(pos, what.length(), with.data(), with.length());
  }
  return count;
}

struct ext_generic_descriptor_t;
struct ext_field_descriptor_t;
struct ext_enum_descriptor_t;
struct ext_message_descriptor_t;
struct ext_file_descriptor_t;
struct ext_oneof_descriptor_t;

std::unordered_map<std::string_view, gpb::FileDescriptorProto *> proto_files;

struct ext_descriptor_visitor {
  virtual void visit(ext_field_descriptor_t &) {}
  virtual void visit(ext_oneof_descriptor_t &) {}
  virtual void visit(ext_enum_descriptor_t &) {}
  virtual void visit(ext_message_descriptor_t &) = 0;
  virtual void visit(ext_file_descriptor_t &) = 0;
  virtual void visit(ext_generic_descriptor_t &) {}
};

struct ext_generic_descriptor_t {
  ext_generic_descriptor_t *parent = nullptr;
  std::string cpp_name;
  std::string qualified_name;

  ext_generic_descriptor_t() = default;

  ext_generic_descriptor_t(ext_generic_descriptor_t *parent, const std::string &name)
      : parent(parent), cpp_name(resolve_keyword(name)) {}

  virtual void accept(ext_descriptor_visitor &visitor) { visitor.visit(*this); }
};

struct ext_field_descriptor_t : ext_generic_descriptor_t {
  const gpb::FieldDescriptorProto *proto;
  std::string cpp_field_type;
  std::string qualified_cpp_field_type;
  bool is_recursive = false;
  std::string cpp_meta_type = "void";
  std::string default_value;
  struct ext_message_descriptor_t *field_type_ext = nullptr;

  ext_field_descriptor_t(ext_generic_descriptor_t *parent_extra, const gpb::FieldDescriptorProto &descriptor)
      : ext_generic_descriptor_t(parent_extra, *descriptor.name), proto(&descriptor) {
    qualified_name = parent_extra->qualified_name + "::" + cpp_name;
    set_cpp_type();
    set_default_value();
  }

  void set_cpp_type() {
    using enum google::protobuf::FieldDescriptorProto::Type;
    if (proto->type) {
      switch (*proto->type) {
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
        cpp_field_type = "std::string";
        break;
      case TYPE_MESSAGE:
      case TYPE_ENUM:
        if (proto->type_name.has_value()) {

          auto cpp_name_range = split(*proto->type_name, ".");
          auto parent_name_range = split(parent->qualified_name, "::");

          auto mismatch_itr = std::mismatch(cpp_name_range.begin(), cpp_name_range.end(), parent_name_range.begin(),
                                            parent_name_range.end())
                                  .first;

          qualified_cpp_field_type = fmt::format("{}", fmt::join(cpp_name_range, "::"));
          cpp_field_type = fmt::format("{}", fmt::join(mismatch_itr, cpp_name_range.end(), "::"));

          is_recursive = cpp_field_type.size() == 0;
          if (is_recursive) {
            cpp_field_type = std::string{cpp_name_range.back()};
          }
        }
        break;
      case TYPE_BYTES:
        cpp_field_type = "hpp::proto::bytes";
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
      case TYPE_GROUP:
        break;
      }
    }
  }

  void set_default_value() {
    using enum gpb::FieldDescriptorProto::Type;

    if (proto->default_value.has_value()) {
      if (proto->type.value() == TYPE_STRING || proto->type.value() == TYPE_BYTES)
        default_value = fmt::format("\"{}\"_hppproto_s", cpp_escape(proto->default_value.value()));
      else if (proto->type.value() == TYPE_ENUM)
        default_value = fmt::format("{}::{}", qualified_cpp_field_type, proto->default_value.value());
      else if (proto->type.value() == TYPE_DOUBLE || proto->type.value() == TYPE_FLOAT) {
        if (proto->default_value.value() == "nan") {
          default_value = fmt::format("std::numeric_limits<{}>::quiet_NaN()", cpp_field_type);
        } else if (proto->default_value.value() == "inf") {
          default_value = fmt::format("std::numeric_limits<{}>::infinity()", cpp_field_type);
        } else if (proto->default_value.value() == "-inf") {
          default_value = fmt::format("-std::numeric_limits<{}>::infinity()", cpp_field_type);
        } else if (proto->type.value() == TYPE_FLOAT) {
          if (proto->default_value.value().find('.') == std::string::npos &&
              proto->default_value.value().find('e') == std::string::npos)
            default_value = proto->default_value.value() + ".0f";
          else
            default_value = proto->default_value.value() + "f";
        } else {
          default_value = fmt::format("double({})", proto->default_value.value());
        }

        const char *wrap_type = proto->type.value() == TYPE_DOUBLE ? "DOUBLE" : "FLOAT";

        default_value = fmt::format("HPP_PROTO_WRAP_{}({})", wrap_type, default_value);
      } else {
        std::string_view type = cpp_field_type;
        std::string suffix;
        if (type[0] == 'u')
          suffix = "U";

        if (type.substr(type.size() - 4, 2) == "64")
          suffix += "LL";

        if (proto->default_value.value() == "-9223372036854775808")
          default_value = "-9223372036854775807LL-1";
        else
          default_value = fmt::format("{}{}", proto->default_value.value(), suffix);
      }
    }
  }
  void accept(ext_descriptor_visitor &visitor) override { visitor.visit(*this); }
};

struct ext_oneof_descriptor_t : ext_generic_descriptor_t {
  const gpb::OneofDescriptorProto *proto;
  std::vector<ext_field_descriptor_t *> members;

  ext_oneof_descriptor_t(const gpb::OneofDescriptorProto &descriptor)
      : ext_generic_descriptor_t(nullptr, *descriptor.name), proto(&descriptor) {}
  void accept(ext_descriptor_visitor &visitor) override { visitor.visit(*this); }
};

struct ext_enum_descriptor_t : ext_generic_descriptor_t {
  const gpb::EnumDescriptorProto *proto;

  ext_enum_descriptor_t(ext_generic_descriptor_t *msg_extra, const gpb::EnumDescriptorProto &descriptor)
      : ext_generic_descriptor_t(msg_extra, *descriptor.name), proto(&descriptor) {
    qualified_name = msg_extra->qualified_name + "::" + cpp_name;
  }

  void accept(ext_descriptor_visitor &visitor) override { visitor.visit(*this); }
};

struct ext_message_descriptor_t : ext_generic_descriptor_t {
  const gpb::DescriptorProto *proto;
  std::vector<ext_message_descriptor_t> nested_types;
  std::vector<ext_enum_descriptor_t> enums;
  std::vector<ext_field_descriptor_t> regular_fields;
  std::vector<ext_oneof_descriptor_t> oneof_fields;
  std::vector<ext_generic_descriptor_t *> fields;
  std::vector<ext_field_descriptor_t> extensions;

  std::set<std::string> declared_types;
  std::set<std::string> dependencies;
  std::set<std::string> forward_declarations;

  bool is_map_entry() const {
    return proto->options.has_value() && proto->options->map_entry.has_value() && proto->options->map_entry.value();
  }

  ext_message_descriptor_t(ext_generic_descriptor_t *parent_extra, const gpb::DescriptorProto &descriptor)
      : ext_generic_descriptor_t(parent_extra, *descriptor.name), proto(&descriptor) {
    qualified_name = parent_extra->qualified_name + "::" + cpp_name;

    for (auto &type : descriptor.enum_type) {
      if (type.name.has_value()) {
        enums.emplace_back(this, type);
        declared_types.insert(type.name.value());
      }
    }

    for (auto &type : descriptor.nested_type) {
      if (type.name.has_value()) {
        auto &nested = nested_types.emplace_back(this, type);
        declared_types.insert(type.name.value());
      }
    }

    std::unordered_map<std::string, ext_field_descriptor_t *> fields_table;

    oneof_fields.reserve(descriptor.oneof_decl.size());
    for (auto &field : descriptor.oneof_decl) {
      oneof_fields.emplace_back(field);
    }

    regular_fields.reserve(descriptor.field.size());
    for (auto &field : descriptor.field) {
      if (field.name.has_value()) {
        regular_fields.emplace_back(this, field);
      }
    }

    extensions.reserve(descriptor.extension.size());
    for (auto &field : descriptor.extension) {
      if (field.name.has_value()) {
        extensions.emplace_back(this, field);
      }
    }

    fields.reserve(regular_fields.size());

    for (auto &f : regular_fields) {
      fields_table[f.qualified_cpp_field_type] = &f;
      if (f.proto->oneof_index.has_value()) {
        auto &oneof_field = oneof_fields[f.proto->oneof_index.value()];
        oneof_field.members.push_back(&f);
        if (oneof_field.members.size() == 1)
          fields.push_back(&oneof_field);
      } else {
        fields.push_back(&f);
      }
    }

    for (auto &ext_type : nested_types) {
      if (ext_type.is_map_entry()) {
        fields_table[ext_type.qualified_name]->field_type_ext = &ext_type;
      }
    }

    for (auto &field : oneof_fields) {
      if (field.members.size() == 1) {
        std::string_view field_name = field.cpp_name;
        if (field_name[0] == '_' && field_name.substr(1) == field.members[0]->cpp_name)
          field.cpp_name = field.members[0]->cpp_name;
      }
    }
  }

  void accept(ext_descriptor_visitor &visitor) override { visitor.visit(*this); }

  void resolve_dependency_cycle() {
    auto nh = dependencies.extract(dependencies.begin());
    auto &dep = nh.value();
    forward_declarations.insert(std::move(nh));

    for (auto &f : regular_fields) {
      if (f.cpp_field_type == dep)
        f.is_recursive = true;
    }
  }
};

struct ext_file_descriptor_t : ext_generic_descriptor_t {
  const gpb::FileDescriptorProto *proto;
  int syntax;
  std::vector<ext_message_descriptor_t> messages;
  std::vector<ext_enum_descriptor_t> enums;
  std::set<std::string> declared_types;
  std::set<std::string> imported_packages;
  std::vector<ext_field_descriptor_t> extensions;

  ext_file_descriptor_t(const gpb::FileDescriptorProto &descriptor)
      : ext_generic_descriptor_t(nullptr, *descriptor.name), proto(&descriptor) {

    if (descriptor.package.has_value()) {
      qualified_name = qualified_cpp_name(descriptor.package.value());
    }

    if (descriptor.syntax.has_value() && descriptor.syntax.value() == "proto3")
      syntax = 3;
    else
      syntax = 2;

    for (auto &type : descriptor.enum_type) {
      if (type.name.has_value())
        enums.emplace_back(this, type);
    }

    for (auto &type : descriptor.message_type) {
      if (type.name.has_value()) {
        messages.emplace_back(this, type);
        declared_types.insert(type.name.value());
      }
    }

    extensions.reserve(descriptor.extension.size());
    for (auto &field : descriptor.extension) {
      if (field.name.has_value()) {
        extensions.emplace_back(this, field);
      }
    }
  }
  void accept(ext_descriptor_visitor &visitor) override { visitor.visit(*this); }
};

struct dependency_tracker : ext_descriptor_visitor {
  std::unordered_set<std::string> imported_packages;

  bool is_imported_type(const std::string &type_name) {
    for (auto &imported : imported_packages) {
      if (type_name.starts_with(imported))
        return true;
    }
    return false;
  }

  void visit(ext_message_descriptor_t &descriptor) override {
    for (auto m : descriptor.nested_types)
      m.accept(*this);

    for (auto &field : descriptor.regular_fields) {
      using enum google::protobuf::FieldDescriptorProto::Type;
      auto proto = field.proto;
      if (proto->type.has_value() && (proto->type.value() == TYPE_MESSAGE || proto->type.value() == TYPE_ENUM)) {

        std::string name = field.cpp_field_type.substr(0, field.cpp_field_type.find(':'));
        if (name != descriptor.cpp_name)
          descriptor.dependencies.insert(name);
      }
    }

    for (auto &m : descriptor.nested_types) {
      for (auto itr = m.dependencies.begin(); itr != m.dependencies.end();) {
        auto dep = *itr;

        if (descriptor.declared_types.contains(dep)) {
          ++itr;
        } else {
          descriptor.dependencies.insert(dep);
          itr = m.dependencies.erase(itr);
        }
      }
    }
  }

  void visit(ext_file_descriptor_t &descriptor) override {
    for (auto &d : descriptor.proto->dependency)
      imported_packages.insert(proto_files[d]->name.value() + ".");

    for (auto &m : descriptor.messages)
      m.accept(*this);

    for (auto &m : descriptor.messages) {
      for (auto itr = m.dependencies.begin(); itr != m.dependencies.end();) {
        auto dep = *itr;
        if (descriptor.declared_types.contains(dep)) {
          ++itr;
        } else {
          itr = m.dependencies.erase(itr);
        }
      }
    }
  }
};

std::vector<ext_message_descriptor_t *> order_messages(std::vector<ext_message_descriptor_t> &messages) { // input
  std::vector<ext_message_descriptor_t *> resolved_messages;
  std::vector<ext_message_descriptor_t *> unresolved_messages;
  resolved_messages.reserve(messages.size());
  unresolved_messages.reserve(messages.size());
  std::set<std::string> resolved_message_names;

  for (auto &m : messages) {
    if (m.dependencies.size() == 0) {
      resolved_messages.push_back(&m);
      resolved_message_names.insert(m.cpp_name);
    } else {
      unresolved_messages.push_back(&m);
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
      auto x = *(unresolved_messages.rbegin());
      x->resolve_dependency_cycle();
    }
  }
  return resolved_messages;
}

struct code_generator : ext_descriptor_visitor {
  std::size_t indent_num = 0;

  gpb::compiler::CodeGeneratorResponse::File &file;
  std::back_insert_iterator<std::string> target;
  code_generator(std::vector<gpb::compiler::CodeGeneratorResponse::File> &files)
      : file(files.emplace_back()), target(file.content.emplace()) {}

  std::string_view indent() {
    static std::string spaces(128, ' ');
    while (indent_num > spaces.size())
      spaces.resize(spaces.size() * 2);
    return std::string_view{spaces.data(), indent_num};
  }
};

struct msg_code_generator : code_generator {
  int syntax;
  using code_generator::code_generator;

  std::string_view field_type_wrapper(ext_field_descriptor_t &descriptor) {
    const gpb::FieldDescriptorProto *proto = descriptor.proto;
    bool is_recursive = descriptor.is_recursive;
    if (proto->label.has_value()) {
      auto label = proto->label.value();
      using enum gpb::FieldDescriptorProto::Label;
      using enum gpb::FieldDescriptorProto::Type;
      if (label == LABEL_REPEATED)
        return "std::vector";
      if (is_recursive)
        return "hpp::proto::heap_based_optional";
      if (label == LABEL_OPTIONAL && proto->type.value() == TYPE_MESSAGE)
        return "std::optional";
      if (label == LABEL_OPTIONAL && proto->type.value() == TYPE_ENUM && !proto->default_value.has_value())
        return "std::optional";
      if ((syntax == 2 && label == LABEL_OPTIONAL) ||
          (syntax == 3 && (proto->type.value() == TYPE_MESSAGE ||
                           (proto->proto3_optional.has_value() && proto->proto3_optional.value()))))
        return "hpp::proto::optional";
    }
    return "";
  }

  std::string field_type(ext_field_descriptor_t &descriptor) {

    auto type_ext = descriptor.field_type_ext;
    if (type_ext && type_ext->is_map_entry()) {

      return fmt::format("hpp::proto::flat_map<{},{}>", type_ext->regular_fields[0].cpp_field_type,
                         type_ext->regular_fields[1].cpp_field_type);
    }

    auto wrapper = field_type_wrapper(descriptor);

    if (wrapper == "std::vector" && descriptor.cpp_field_type == "bool") {
      return fmt::format("std::vector<hpp::proto::boolean>");
    } else if (wrapper == "hpp::proto::optional" && descriptor.default_value.size()) {
      return fmt::format("hpp::proto::optional<{},{}>", descriptor.cpp_field_type, descriptor.default_value);
    } else if (wrapper.size()) {
      return fmt::format("{}<{}>", wrapper, descriptor.cpp_field_type);
    }
    return std::string(descriptor.cpp_field_type);
  }

  void visit(ext_field_descriptor_t &descriptor) override {
    std::string attribute;
    // if (descriptor.proto->options.has_value()) {
    //   if (descriptor.proto->options->deprecated) {
    //     attribute = "[[ deprecated ]] ";
    //   }
    // }
    std::string_view initializer = " = {}";
    if (field_type_wrapper(descriptor).size())
      initializer = "";
    fmt::format_to(target, "{}{}{} {}{};\n", indent(), attribute, field_type(descriptor), descriptor.cpp_name,
                   initializer);
  }

  void visit(ext_oneof_descriptor_t &descriptor) override {

    if (descriptor.members.size() > 1) {
      std::string types;

      fmt::format_to(target, "{}enum {}_oneof_case : int {{\n", indent(), descriptor.cpp_name);
      indent_num += 2;
      int index = 1;
      for (auto &f : descriptor.members) {
        const char *sep = (index != descriptor.members.size()) ? "," : "";
        fmt::format_to(target, "{}{} = {}{}\n", indent(), f->cpp_name, index++, sep);
      }
      indent_num -= 2;
      fmt::format_to(target, "{}}};\n\n", indent());

      for (auto &f : descriptor.members) {
        types += (", " + f->cpp_field_type);
      }
      fmt::format_to(target, "{}std::variant<std::monostate{}> {};\n", indent(), types, descriptor.cpp_name);
    } else {
      auto f = descriptor.members[0];
      std::string attribute;
      // if (f->proto->options.has_value()) {
      //   if (f->proto->options->deprecated) {
      //     attribute = "[[ deprecated ]] ";
      //   }
      // }

      fmt::format_to(target, "{}{}std::optional<{}> {};\n", indent(), attribute, f->cpp_field_type, f->cpp_name);
    }
  }

  void visit(ext_enum_descriptor_t &descriptor) override {
    fmt::format_to(target, "{}enum class {} {{\n", indent(), descriptor.cpp_name);
    indent_num += 2;
    int index = 0;
    for (auto &e : descriptor.proto->value) {
      char sep = (index++ == descriptor.proto->value.size() - 1) ? ' ' : ',';
      fmt::format_to(target, "{}{} = {}{}\n", indent(), resolve_keyword(*e.name), *e.number, sep);
    }

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());
  }

  void visit(ext_message_descriptor_t &descriptor) override {
    if (descriptor.is_map_entry())
      return;
    for (auto &fwd : descriptor.forward_declarations) {
      fmt::format_to(target, "{}struct {};\n", indent(), fwd);
    }

    std::string attribute;
    // if (descriptor.proto->options.has_value()) {
    //   if (descriptor.proto->options->deprecated) {
    //     attribute = "[[ deprecated ]] ";
    //   }
    // }

    fmt::format_to(target, "{}struct {}{} {{\n", indent(), attribute, descriptor.cpp_name);
    indent_num += 2;

    for (auto &e : descriptor.enums)
      e.accept(*this);

    for (auto m : order_messages(descriptor.nested_types))
      m->accept(*this);

    for (auto &f : descriptor.fields)
      f->accept(*this);

    for (auto &f : descriptor.extensions) {
      fmt::format_to(target, "\n{}constexpr auto {}();\n", indent(), f.cpp_name);
    }

    if (descriptor.proto->extension_range.size()) {
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
                     "{0}auto get_extension(auto meta) const {{\n"
                     "{0}  return meta.read(extensions);\n"
                     "{0}}}\n"
                     "{0}template<typename Meta>"
                     "{0}auto set_extension(Meta meta, typename Meta::set_value_type &&value) {{\n"
                     "{0}  return meta.write(extensions, std::forward<typename Meta::set_value_type>(value));\n"
                     "{0}}}\n"
                     "{0}bool has_extension(auto meta) const {{\n"
                     "{0}  return meta.element_of(extensions);\n"
                     "{0}}}\n",
                     indent(), descriptor.cpp_name);
    }
    fmt::format_to(target,
                   "\n{0}bool operator == (const {1}&) const = default;\n"
                   "#ifndef HPP_PROTO_DISABLE_THREEWAY_COMPARITOR\n"
                   "\n{0}auto operator <=> (const {1}&) const = default;\n"
                   "#endif\n",
                   indent(), descriptor.cpp_name);

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());
  }

  void visit(ext_file_descriptor_t &descriptor) override {

    syntax = descriptor.syntax;
    auto file_name = descriptor.proto->name.value();
    file.name = file_name.substr(0, file_name.size() - 5) + "msg.hpp";
    fmt::format_to(target, "#pragma once\n\n"
                           "#include <hpp_proto/msg_base.h>\n");

    for (auto &d : descriptor.proto->dependency)
      fmt::format_to(target, "#include <{}.msg.hpp>\n", basename(d));

    auto ns = descriptor.qualified_name;
    if (ns.starts_with("::"))
      ns = ns.substr(2);

    fmt::format_to(target, "\nnamespace {} {{\n\n", ns);
    fmt::format_to(target, "{}using hpp::proto::literals::operator \"\"_hppproto_s;\n", indent());

    for (auto &e : descriptor.enums)
      e.accept(*this);

    for (auto &m : order_messages(descriptor.messages))
      m->accept(*this);

    fmt::format_to(target, "}} // namespace {}\n", ns);
  }
};

bool is_numeric(enum gpb::FieldDescriptorProto::Type type) {
  using enum gpb::FieldDescriptorProto::Type;
  return type != TYPE_MESSAGE || type != TYPE_ENUM || type != TYPE_STRING || type != TYPE_STRING || type != TYPE_GROUP;
}

struct hpp_meta_generateor : code_generator {
  int syntax;
  using code_generator::code_generator;
  std::size_t prefix_size;

  void visit(ext_file_descriptor_t &descriptor) override {
    auto file_name = descriptor.proto->name.value();
    file.name = file_name.substr(0, file_name.size() - 5) + "pb.hpp";
    syntax = descriptor.syntax;
    fmt::format_to(target,
                   "#pragma once\n\n"
                   "#include <hpp_proto/hpp_proto.h>\n"
                   "#include <{}.msg.hpp>\n",
                   basename(descriptor.proto->name.value()));
    for (auto &d : descriptor.proto->dependency)
      fmt::format_to(target, "#include <{}.pb.hpp>\n", basename(d));

    fmt::format_to(target, "\n");

    prefix_size = descriptor.qualified_name.size() + 2;
    auto ns = descriptor.qualified_name;
    if (ns.starts_with("::"))
      ns = ns.substr(2);
    fmt::format_to(target,
                   "\nnamespace {} {{\n\n"
                   "using namespace zpp::bits::literals;\n\n",
                   ns);

    for (auto &m : order_messages(descriptor.messages))
      m->accept(*this);

    for (auto &f : descriptor.extensions)
      f.accept(*this);

    fmt::format_to(target, "}} // namespace {}\n", ns);
  }

  void visit(ext_message_descriptor_t &descriptor) override {
    auto name = descriptor.qualified_name.substr(prefix_size);
    fmt::format_to(target, "auto pb_meta(const {} &) -> std::tuple<\n", name);
    indent_num += 2;

    for (auto &f : descriptor.fields)
      f->accept(*this);

    if (descriptor.proto->extension_range.size()) {
      fmt::format_to(target, "{}hpp::proto::field_meta<UINT32_MAX>", indent());
    } else if (descriptor.regular_fields.size()) {
      auto &content = file.content.value();
      content.resize(content.size() - 2);
    }
    indent_num -= 2;

    fmt::format_to(target, ">;\n\n");

    fmt::format_to(target, "auto serialize(const {}&) -> zpp::bits::members<{}>;\n\n", name,
                   descriptor.fields.size() + (descriptor.proto->extension_range.size() ? 1 : 0));

    if (descriptor.fields.size() > 50) {
      std::vector<int> v(descriptor.fields.size());
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
                     name, args);
    }

    auto package_and_name = descriptor.qualified_name.substr(2);
    replace_all(package_and_name, "::", ".");

    fmt::format_to(target,
                   "inline const char* pb_url(const {}&) {{ return "
                   "\"type.googleapis.com/{}\"; }}\n\n",
                   name, package_and_name);

    for (auto &f : descriptor.extensions)
      f.accept(*this);

    for (auto &m : descriptor.nested_types) {
      if (!m.is_map_entry())
        m.accept(*this);
    }
  }

  void visit(ext_field_descriptor_t &descriptor) override {
    std::string_view rule = "defaulted";
    auto proto = descriptor.proto;
    using enum gpb::FieldDescriptorProto::Label;

    if (proto->label.has_value()) {
      auto label = proto->label.value();
      bool numeric = is_numeric(proto->type.value());

      if ((syntax == 2 && label == LABEL_OPTIONAL) ||
          (syntax == 3 && proto->proto3_optional.has_value() && proto->proto3_optional.value()))
        rule = "explicit_presence";
      else if (syntax == 2 && label == LABEL_REPEATED && numeric) {
        auto &options = proto->options;
        if (!options.has_value() || !options->packed.has_value() || !options->packed.value()) {
          rule = "unpacked_repeated";
        }
      }
    }

    if (descriptor.field_type_ext && descriptor.field_type_ext->is_map_entry()) {
      descriptor.cpp_meta_type =
          fmt::format("hpp::proto::map_entry<{}, {}>", descriptor.field_type_ext->regular_fields[0].cpp_meta_type,
                      descriptor.field_type_ext->regular_fields[1].cpp_meta_type);
    }

    std::string default_value;

    if (rule == "defaulted") {
      default_value = descriptor.default_value;
    }

    std::string type_and_default_value;
    if (descriptor.cpp_meta_type != "void" || default_value.size()) {
      type_and_default_value = fmt::format(", {}", descriptor.cpp_meta_type);
      if (default_value.size()) {
        fmt::format_to(std::back_inserter(type_and_default_value), ", {}", default_value);
      }
    }

    if (!proto->extendee.has_value()) {
      fmt::format_to(target, "{}hpp::proto::field_meta<{}, hpp::proto::encoding_rule::{}{}>,\n", indent(),
                     proto->number.value(), rule, type_and_default_value);
    } else {
      std::string_view extension_prefix;
      if (proto->label.has_value() && proto->label.value() == LABEL_REPEATED)
        extension_prefix = "repeated_";
      type_and_default_value = fmt::format(
          ", {}, {}", descriptor.cpp_meta_type == "void" ? descriptor.cpp_field_type : descriptor.cpp_meta_type,
          descriptor.cpp_field_type);

      if (descriptor.default_value.size()) {
        type_and_default_value += ", " + descriptor.default_value;
      }

      fmt::format_to(target,
                     "{0}constexpr auto {1}() {{\n"
                     "{0}  return hpp::proto::{2}extension_meta<{3}, {4}, "
                     "hpp::proto::encoding_rule::{5}{6}>{{}};\n"
                     "{0}}}\n\n",
                     indent(), descriptor.qualified_name.substr(prefix_size), extension_prefix,
                     qualified_cpp_name(descriptor.proto->extendee.value()), proto->number.value(), rule,
                     type_and_default_value);
    }
  }

  void visit(ext_oneof_descriptor_t &descriptor) override {

    if (descriptor.members.size() > 1) {
      std::string types;
      std::string sep;
      for (auto &f : descriptor.members) {
        types += (sep + f->cpp_field_type);
        sep = ",";
      }
      fmt::format_to(target, "{}std::tuple<\n", indent());
      indent_num += 2;
      for (auto &f : descriptor.members)
        f->accept(*this);

      indent_num -= 2;
      if (descriptor.members.size()) {
        auto &content = file.content.value();
        content.resize(content.size() - 2);
      }
      fmt::format_to(target, ">,\n");
    } else {
      descriptor.members[0]->accept(*this);
    }
  }

  void visit(ext_enum_descriptor_t &descriptor) override {
    fmt::format_to(target, "{}enum class {} {{\n", indent(), descriptor.cpp_name);
    indent_num += 2;
    int index = 0;
    for (auto &e : descriptor.proto->value) {
      char sep = (index++ == descriptor.proto->value.size() - 1) ? ' ' : ',';
      fmt::format_to(target, "{}{} = {}{}\n", indent(), resolve_keyword(*e.name), *e.number, sep);
    }

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());
  }
};

struct glaze_meta_generator : code_generator {
  using code_generator::code_generator;
  std::size_t prefix_size;

  void visit(ext_file_descriptor_t &descriptor) override {
    auto file_name = descriptor.proto->name.value();
    file.name = file_name.substr(0, file_name.size() - 5) + "glz.hpp";
    fmt::format_to(target, "#pragma once\n\n"
                           "#include <hpp_proto/hpp_proto_json.h>\n");

    for (auto &d : descriptor.proto->dependency)
      fmt::format_to(target, "#include <{}.glz.hpp>\n", basename(d));

    fmt::format_to(target, "#include <{}.msg.hpp>\n\n", basename(descriptor.proto->name.value()));

    // fmt::format_to(target, "\n");
    prefix_size = descriptor.qualified_name.size() + 2;

    for (auto &m : descriptor.messages)
      m.accept(*this);

    for (auto &e : descriptor.enums)
      e.accept(*this);
  }

  void visit(ext_message_descriptor_t &descriptor) override {
    auto name = descriptor.qualified_name.substr(prefix_size);
    fmt::format_to(target,
                   "template <>\n"
                   "struct glz::meta<{0}> {{\n"
                   "  using T = {0};\n"
                   "  static constexpr auto value = object(\n",
                   descriptor.qualified_name.substr(2));

    for (auto &f : descriptor.fields)
      f->accept(*this);

    if (descriptor.fields.size()) {
      auto &content = file.content.value();
      content.resize(content.size() - 2);
    }

    fmt::format_to(target, ");\n}};\n\n");

    for (auto &m : descriptor.nested_types) {
      if (!m.is_map_entry())
        m.accept(*this);
    }

    for (auto &e : descriptor.enums)
      e.accept(*this);
  }

  void visit(ext_field_descriptor_t &descriptor) override {
    using enum google::protobuf::FieldDescriptorProto::Type;
    auto type = *descriptor.proto->type;
    if (type == TYPE_INT64 || type == TYPE_UINT64 || type == TYPE_FIXED64 || type == TYPE_SFIXED64 || type == TYPE_SINT64) {
      fmt::format_to(target, "    \"{}\", [](auto &&self) -> auto& {{ return hpp::proto::wrap_int64(self.{}); }},\n",
                     descriptor.proto->json_name.value(), descriptor.cpp_name);
    } else {
      fmt::format_to(target, "    \"{}\", &T::{},\n", descriptor.proto->json_name.value(), descriptor.cpp_name);
    }
  }

  void visit(ext_oneof_descriptor_t &descriptor) override {
    if (descriptor.members.size() > 1) {
      for (unsigned i = 0; i < descriptor.members.size(); ++i) {
        fmt::format_to(target,
                       "    \"{}\", [](auto &&self) -> auto {{ return hpp::proto::wrap_oneof<{}>(self.{}); }},\n",
                       descriptor.members[i]->proto->json_name.value(), i+1, descriptor.cpp_name);
      }
    } else {
      descriptor.members[0]->accept(*this);
    }
  }

  void visit(ext_enum_descriptor_t &descriptor) override {
    fmt::format_to(target,
                   "template <>\n"
                   "struct glz::meta<{0}> {{\n"
                   "  using enum {0};\n"
                   "  static constexpr auto value = enumerate(\n",
                   descriptor.qualified_name.substr(2));

    indent_num += 4;
    int index = 0;
    for (auto &e : descriptor.proto->value) {
      const char *sep = (index++ == descriptor.proto->value.size() - 1) ? ");" : ",";
      fmt::format_to(target, "{0}\"{1}\", {1}{2}\n", indent(), resolve_keyword(*e.name), sep);
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

  if (hpp::proto::failure(hpp::proto::in{request_data}(request))) {
    fputs("hpp decode error", stderr);
    return 1;
  }

  for (auto &file : request.proto_file) {
    proto_files[file.name.value()] = &file;
  }

  gpb::compiler::CodeGeneratorResponse response;
  response.supported_features = (uint64_t)gpb::compiler::CodeGeneratorResponse::Feature::FEATURE_PROTO3_OPTIONAL;

  for (const auto &file_name : request.file_to_generate) {
    ext_file_descriptor_t descriptor(*proto_files[file_name]);
    dependency_tracker tracker;
    descriptor.accept(tracker);

    msg_code_generator msg_code(response.file);
    descriptor.accept(msg_code);
    hpp_meta_generateor hpp_meta_code(response.file);
    descriptor.accept(hpp_meta_code);
    glaze_meta_generator glz_meta_code(response.file);
    descriptor.accept(glz_meta_code);
  }

  std::vector<char> data;
  if (hpp::proto::failure(hpp::proto::out{data}(response))) {
    fputs("hpp encode error", stderr);
    return 1;
  }
  std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));

  return 0;
}