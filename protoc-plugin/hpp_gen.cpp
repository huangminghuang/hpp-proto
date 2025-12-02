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
#include <filesystem>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fstream>
#include <google/protobuf/compiler/plugin.pb.hpp>
#include <hpp_proto/descriptor_pool.hpp>
#include <hpp_proto/hpp_options.pb.hpp>
#include <iostream>
#include <numeric>
#include <set>
#include <unordered_map>
#include <unordered_set>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

// NOLINTBEGIN(cert-err58-cpp)
const std::unordered_set<std::string_view> keywords = {
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
namespace {

// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

std::string resolve_keyword(std::string_view name) {
  if (keywords.contains(name)) {
    return std::string(name) + "_";
  }
  return std::string(name);
}

///
/// Constructs a fully qualified C++ name from a given protobuf name
/// ,replacing '.' with '::' to adhere to C++ naming
/// conventions. The namespace prefix is prepended only when the name
/// is started with a dot(.).  Each segment of the name is processed
/// to resolve any C++ keywords.
///
/// @param namespace_prefix The namespace prefix to prepend to the name when name is staring with dot.
/// @param name The name to be qualified, using '.' as a separator.
/// @return A string representing the fully qualified C++ name.
///
std::string make_qualified_cpp_name(const std::string &namespace_prefix, std::string_view name) {
  std::string result;
  std::size_t i = 0;
  std::size_t j = 0;
  if (name == ".") {
    return namespace_prefix;
  }
  while ((j = name.find('.', i)) != std::string_view::npos) {
    if (j == 0) {
      if (!namespace_prefix.empty()) {
        result += namespace_prefix;
        if (!namespace_prefix.ends_with("::")) {
          result += "::";
        }
      }
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

constexpr std::size_t cpp_escaped_len(char c) {
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
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
  return cpp_escaped_len_table[static_cast<unsigned char>(c)];
}
// Calculates the length of the C-style escaped version of 'src'.
// Assumes that non-printable characters are escaped using octal sequences,
// and that UTF-8 bytes are not handled specially.
inline std::size_t cpp_escaped_len(std::string_view src) {
  std::size_t len = 0;
  for (const char c : src) {
    len += cpp_escaped_len(c);
  }
  return len;
}

const char *cpp_escape(char c) {
  static const char *const escapedChars[256] = {
      "\\\\000", "\\\\001", "\\\\002", "\\\\003", "\\\\004", "\\\\005", "\\\\006", "\\\a",    "\\\b",    "\\\t",
      "\\\n",    "\\\v",    "\\\f",    "\\\r",    "\\\\016", "\\\\017", "\\\\020", "\\\\021", "\\\\022", "\\\\023",
      "\\\\024", "\\\\025", "\\\\026", "\\\\027", "\\\\030", "\\\\031", "\\\\032", "\\\\033", "\\\\034", "\\\\035",
      "\\\\036", "\\\\037", " ",       "!",       "\\\"",    "#",       "$",       "%",       "&",       "\\\'",
      "(",       ")",       "*",       "+",       ",",       "-",       ".",       "/",       "0",       "1",
      "2",       "3",       "4",       "5",       "6",       "7",       "8",       "9",       ":",       ";",
      "<",       "=",       ">",       "\\\?",    "@",       "A",       "B",       "C",       "D",       "E",
      "F",       "G",       "H",       "I",       "J",       "K",       "L",       "M",       "N",       "O",
      "P",       "Q",       "R",       "S",       "T",       "U",       "V",       "W",       "X",       "Y",
      "Z",       "[",       "\\\\",    "]",       "^",       "_",       "`",       "a",       "b",       "c",
      "d",       "e",       "f",       "g",       "h",       "i",       "j",       "k",       "l",       "m",
      "n",       "o",       "p",       "q",       "r",       "s",       "t",       "u",       "v",       "w",
      "x",       "y",       "z",       "{",       "|",       "}",       "~",       "\\\\177", "\\\\200", "\\\\201",
      "\\\\202", "\\\\203", "\\\\204", "\\\\205", "\\\\206", "\\\\207", "\\\\210", "\\\\211", "\\\\212", "\\\\213",
      "\\\\214", "\\\\215", "\\\\216", "\\\\217", "\\\\220", "\\\\221", "\\\\222", "\\\\223", "\\\\224", "\\\\225",
      "\\\\226", "\\\\227", "\\\\230", "\\\\231", "\\\\232", "\\\\233", "\\\\234", "\\\\235", "\\\\236", "\\\\237",
      "\\\\240", "\\\\241", "\\\\242", "\\\\243", "\\\\244", "\\\\245", "\\\\246", "\\\\247", "\\\\250", "\\\\251",
      "\\\\252", "\\\\253", "\\\\254", "\\\\255", "\\\\256", "\\\\257", "\\\\260", "\\\\261", "\\\\262", "\\\\263",
      "\\\\264", "\\\\265", "\\\\266", "\\\\267", "\\\\270", "\\\\271", "\\\\272", "\\\\273", "\\\\274", "\\\\275",
      "\\\\276", "\\\\277", "\\\\300", "\\\\301", "\\\\302", "\\\\303", "\\\\304", "\\\\305", "\\\\306", "\\\\307",
      "\\\\310", "\\\\311", "\\\\312", "\\\\313", "\\\\314", "\\\\315", "\\\\316", "\\\\317", "\\\\320", "\\\\321",
      "\\\\322", "\\\\323", "\\\\324", "\\\\325", "\\\\326", "\\\\327", "\\\\330", "\\\\331", "\\\\332", "\\\\333",
      "\\\\334", "\\\\335", "\\\\336", "\\\\337", "\\\\340", "\\\\341", "\\\\342", "\\\\343", "\\\\344", "\\\\345",
      "\\\\346", "\\\\347", "\\\\350", "\\\\351", "\\\\352", "\\\\353", "\\\\354", "\\\\355", "\\\\356", "\\\\357",
      "\\\\360", "\\\\361", "\\\\362", "\\\\363", "\\\\364", "\\\\365", "\\\\366", "\\\\367", "\\\\370", "\\\\371",
      "\\\\372", "\\\\373", "\\\\374", "\\\\375", "\\\\376", "\\\\377"};
  return escapedChars[static_cast<unsigned char>(c)]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

std::string cpp_escape(std::string_view src) {
  const std::size_t escaped_len = cpp_escaped_len(src);
  if (escaped_len == src.size()) {
    return {src.data(), src.size()};
  }
  std::string result;
  result.reserve(escaped_len);

  for (const char c : src) {
    result += cpp_escape(c);
  }
  return result;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::string basename(const std::string &name, const std::string &directory_prefix = "") {
  std::string result = name.substr(0, name.find_last_of('.'));
  if (!directory_prefix.empty()) {
    result = directory_prefix + "/" + result;
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

std::array<char, 4> to_hex_literal(::hpp::proto::concepts::byte_type auto c) {
  static const char qmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  const auto uc = static_cast<unsigned char>(c);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
  return {'\\', 'x', qmap[uc >> 4U], qmap[uc & 0x0FU]};
}

std::string to_hex_literal(::hpp::proto::concepts::contiguous_byte_range auto const &data) {
  std::string result;
  result.resize(data.size() * 4);
  std::size_t index = 0;
  for (auto b : data) {
    std::ranges::copy(to_hex_literal(b), &result[index]);
    index += 4;
  }
  return result;
}
} // namespace
struct hpp_addons {
  using traits_type = ::hpp::proto::default_traits;
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

  static ::hpp::proto::optional<std::string> namespace_prefix;

  template <typename Derived>
  struct field_descriptor {
    std::string cpp_name;
    std::string cpp_field_type;
    std::string qualified_cpp_field_type;
    std::string cpp_meta_type = "void";
    std::string default_value;
    std::string default_value_template_arg;

    bool is_recursive = false;
    bool is_cpp_optional = false;
    bool is_closed_enum = false;
    bool is_foreign = false;

    field_descriptor(const Derived &self, [[maybe_unused]] const auto &inherited_options)
        : cpp_name(resolve_keyword(self.proto().name)) {
      set_cpp_type(self.proto());
      set_default_value(self.proto());
    }

    void set_cpp_type(const FieldDescriptorProto &proto) {
      using enum google::protobuf::FieldDescriptorProto_::Type;
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
        cpp_field_type = "std::int64_t";
        qualified_cpp_field_type = "std::int64_t";
        cpp_meta_type = "::hpp::proto::vint64_t";
        break;
      case TYPE_UINT64:
        cpp_field_type = "std::uint64_t";
        qualified_cpp_field_type = "std::uint64_t";
        cpp_meta_type = "::hpp::proto::vuint64_t";
        break;
      case TYPE_INT32:
        cpp_field_type = "std::int32_t";
        qualified_cpp_field_type = "std::int32_t";
        cpp_meta_type = "::hpp::proto::vint64_t";
        break;
      case TYPE_FIXED64:
        cpp_field_type = "std::uint64_t";
        qualified_cpp_field_type = "std::uint64_t";
        break;
      case TYPE_FIXED32:
        cpp_field_type = "std::uint32_t";
        qualified_cpp_field_type = "std::uint32_t";
        break;
      case TYPE_BOOL:
        cpp_field_type = "bool";
        qualified_cpp_field_type = "bool";
        cpp_meta_type = "bool";
        break;
      case TYPE_STRING:
        cpp_field_type = "typename Traits::string_t";
        qualified_cpp_field_type = cpp_field_type;
        break;
      case TYPE_GROUP:
      case TYPE_MESSAGE:
      case TYPE_ENUM:
        break;
      case TYPE_BYTES:
        cpp_field_type = "typename Traits::bytes_t";
        qualified_cpp_field_type = cpp_field_type;
        break;
      case TYPE_UINT32:
        cpp_field_type = "std::uint32_t";
        qualified_cpp_field_type = cpp_field_type;
        cpp_meta_type = "::hpp::proto::vuint32_t";
        break;
      case TYPE_SFIXED32:
        cpp_field_type = "std::int32_t";
        qualified_cpp_field_type = cpp_field_type;
        break;
      case TYPE_SFIXED64:
        cpp_field_type = "std::int64_t";
        qualified_cpp_field_type = cpp_field_type;
        break;
      case TYPE_SINT32:
        cpp_field_type = "std::int32_t";
        qualified_cpp_field_type = cpp_field_type;
        cpp_meta_type = "::hpp::proto::vsint32_t";
        break;
      case TYPE_SINT64:
        cpp_field_type = "std::int64_t";
        qualified_cpp_field_type = cpp_field_type;
        cpp_meta_type = "::hpp::proto::vsint64_t";
        break;
      }
    }

    void set_default_value(const FieldDescriptorProto &proto) {
      using enum google::protobuf::FieldDescriptorProto_::Type;
      using enum google::protobuf::FieldDescriptorProto_::Label;

      if (!proto.default_value.empty()) {
        if (proto.type == TYPE_STRING) {
          set_string_default_value(proto);
        } else if (proto.type == TYPE_BYTES) {
          set_bytes_default_value(proto);
        } else if (proto.type == TYPE_ENUM) {
          // set_enum_default_value(proto);
        } else if (proto.type == TYPE_DOUBLE || proto.type == TYPE_FLOAT) {
          set_float_default_value(proto);
        } else {
          set_integer_default_value(proto);
        }
      }
    }

    void set_bytes_default_value(const FieldDescriptorProto &proto) {
      if (!proto.default_value.empty()) {

        default_value_template_arg =
            fmt::format("::hpp::proto::bytes_literal<\"{}\">{{}}", cpp_escape(proto.default_value));
        default_value = default_value_template_arg;
      }
    }

    void set_string_default_value(const FieldDescriptorProto &proto) {
      if (!proto.default_value.empty()) {
        std::string escaped = cpp_escape(proto.default_value);
        default_value = fmt::format("\"{}\"", escaped);
        default_value_template_arg = fmt::format("::hpp::proto::string_literal<\"{}\">{{}}", escaped);
      }
    }

    void set_enum_default_value(const FieldDescriptorProto &proto) {
      default_value = fmt::format("{}::{}", cpp_field_type, proto.default_value);
      default_value_template_arg = fmt::format("{}::{}", qualified_cpp_field_type, proto.default_value);
    }

    void set_integer_default_value(const FieldDescriptorProto &proto) {
      const std::string_view typename_view = cpp_field_type;
      std::string suffix;
      if (typename_view.size() > 6 && typename_view[5] == 'u') {
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

    void set_float_default_value(const FieldDescriptorProto &proto) {
      using enum google::protobuf::FieldDescriptorProto_::Type;
      if (proto.default_value == "nan") {
        default_value = fmt::format("std::numeric_limits<{}>::quiet_NaN()", cpp_field_type);
      } else if (proto.default_value == "inf") {
        default_value = fmt::format("std::numeric_limits<{}>::infinity()", cpp_field_type);
      } else if (proto.default_value == "-inf") {
        default_value = fmt::format("-std::numeric_limits<{}>::infinity()", cpp_field_type);
      } else if (proto.type == TYPE_FLOAT) {
        if (proto.default_value.find('.') == std::string::npos && proto.default_value.find('e') == std::string::npos) {
          default_value = proto.default_value + ".0F";
        } else {
          default_value = proto.default_value + "F";
        }
      } else {
        default_value = fmt::format("double({})", proto.default_value);
      }

      const char *wrap_type = (proto.type == TYPE_DOUBLE) ? "DOUBLE" : "FLOAT";

      default_value_template_arg = fmt::format("HPP_PROTO_WRAP_{}({})", wrap_type, default_value);
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
    std::string cpp_name;
    std::vector<int> sorted_values;
    std::string qualified_name;
    bool continuous = true;

    explicit enum_descriptor(Derived &self, [[maybe_unused]] const auto &inherited_options)
        : cpp_name(resolve_keyword(self.proto().name)) {
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
    std::string cpp_name;

    explicit oneof_descriptor(Derived &self, [[maybe_unused]] const auto &inherited_options)
        : cpp_name(resolve_keyword(self.proto().name)) {}
  };

  template <typename Derived>
  struct message_descriptor {
    std::string pb_name;
    std::string cpp_name;
    std::vector<void *> used_by_fields;
    std::set<Derived *> dependencies;
    std::set<Derived *> forward_messages;
    std::string qualified_name;
    std::string no_namespace_qualified_name;
    bool has_recursive_map_field = false;
    bool has_non_map_nested_message = false;

    explicit message_descriptor(Derived &self, [[maybe_unused]] const auto &inherited_options)
        : pb_name(self.proto().name), cpp_name(resolve_keyword(self.proto().name)),
          has_non_map_nested_message(std::ranges::any_of(self.proto().nested_type, [](const DescriptorProto &submsg) {
            return !submsg.options.has_value() || !submsg.options->map_entry;
          })) {}
  };

  template <typename Derived>
  struct file_descriptor {
    std::vector<std::string> dependency_names;

    std::string syntax;
    std::string cpp_namespace;
    std::string cpp_name;
    std::string namespace_prefix;

    explicit file_descriptor(Derived &self)
        : syntax(self.proto().syntax.empty() ? std::string{"proto2"} : self.proto().syntax),
          cpp_name(self.proto().name) {
      ::hpp::proto::hpp_file_opts opts;
      if (self.options().get_extension(opts).ok()) {
        if (opts.value.namespace_prefix.has_value()) {
          namespace_prefix = opts.value.namespace_prefix.value();
        } else if (hpp_addons::namespace_prefix.has_value()) {
          namespace_prefix = *hpp_addons::namespace_prefix;
        }
        cpp_namespace = make_qualified_cpp_name(namespace_prefix, "." + self.proto().package);
        std::replace_if(cpp_name.begin(), cpp_name.end(), [](unsigned char c) { return std::isalnum(c) == 0; }, '_');
        cpp_name = resolve_keyword(cpp_name);
      }
    }

    // NOLINTBEGIN(misc-no-recursion)
    const std::vector<std::string> &get_dependency_names() {
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
        dependency_names.push_back(cpp_name);
      }
      return dependency_names;
    }
    // NOLINTEND(misc-no-recursion)
  };
};

hpp::proto::optional<std::string> hpp_addons::namespace_prefix;
using hpp_gen_descriptor_pool = ::hpp::proto::descriptor_pool<hpp_addons>;
using traits_type = typename hpp_gen_descriptor_pool::traits_type;
using CodeGeneratorResponse = google::protobuf::compiler::CodeGeneratorResponse<traits_type>;

const static std::map<std::string, std::string> well_known_codecs = {{"google.protobuf.Duration", "duration_codec"},
                                                                     {"google.protobuf.Timestamp", "timestamp_codec"},
                                                                     {"google.protobuf.FieldMask", "field_mask_codec"}};

struct code_generator {

  static std::filesystem::path plugin_name;
  static std::string plugin_parameters;
  static std::vector<std::string> proto2_explicit_presences;
  static std::string directory_prefix;
  std::size_t indent_num = 0;
  typename CodeGeneratorResponse::File &file;
  std::back_insert_iterator<std::string> target;

  using message_descriptor_t = hpp_gen_descriptor_pool::message_descriptor_t;
  using enum_descriptor_t = hpp_gen_descriptor_pool::enum_descriptor_t;
  using oneof_descriptor_t = hpp_gen_descriptor_pool::oneof_descriptor_t;
  using field_descriptor_t = hpp_gen_descriptor_pool::field_descriptor_t;
  using file_descriptor_t = hpp_gen_descriptor_pool::file_descriptor_t;

  static message_descriptor_t *parent_message_of(auto *desc) { return desc->parent_message(); }

  explicit code_generator(std::vector<typename CodeGeneratorResponse::File> &files)
      : file(files.emplace_back()), target(file.content) {}

  ~code_generator() = default;
  code_generator(const code_generator &) = delete;
  code_generator(code_generator &&) = delete;
  code_generator &operator=(const code_generator &) = delete;
  code_generator &operator=(code_generator &&) = delete;

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
    for (auto &f : descriptor.fields()) {
      if (f.cpp_field_type == dep) {
        f.is_recursive = true;
      }
    }
    for (auto &m : descriptor.messages()) {
      mark_field_recursive(m, dep);
    }
  }
  // NOLINTEND(misc-no-recursion)

  static message_descriptor_t *resolve_container_dependency_cycle(std::vector<message_descriptor_t *> &unresolved) {
    // First, find the dependency which used the by repeated field
    for (auto *depended : unresolved) {
      std::map<message_descriptor_t *, bool> used_by_messages;
      for (auto *f : depended->used_by_fields) {
        auto *field = static_cast<field_descriptor_t *>(f);
        auto *message = parent_message_of(field);
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
    }
    // find the dependency which used the by map field
    for (auto *depended : unresolved) {
      std::map<message_descriptor_t *, bool> used_by_messages;
      for (auto *f : depended->used_by_fields) {
        auto *field = static_cast<field_descriptor_t *>(f);
        auto *message = parent_message_of(field);
        if (std::ranges::find(unresolved, message) != unresolved.end() || message->is_map_entry()) {
          used_by_messages[message] |= !(message->is_map_entry());
          field->is_recursive = true;
        }
      }

      for (auto [m, no_non_map_usage] : used_by_messages) {
        if (!no_non_map_usage) {
          m->parent_message()->has_recursive_map_field = true;
          m->parent_message()->dependencies.erase(depended);
          m->parent_message()->forward_messages.insert(depended);
          return m->parent_message();
        }
      }
    }
    return nullptr;
  }

  static void resolve_dependency_cycle(message_descriptor_t &descriptor) {
    message_descriptor_t *dep = *descriptor.dependencies.begin();
    descriptor.forward_messages.insert(descriptor.dependencies.extract(descriptor.dependencies.begin()));
    mark_field_recursive(descriptor, dep->cpp_name);
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
        std::set<message_descriptor_t *> sorted_resolved_messages{resolved_messages.begin(), resolved_messages.end()};
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
        message_descriptor_t *to_be_resolved = resolve_container_dependency_cycle(unresolved_messages);
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
    fmt::format_to(target,
                   "// clang-format off\n"
                   "// Generated by the protocol buffer compiler.  DO NOT EDIT!\n"
                   "// NO CHECKED-IN PROTOBUF GENCODE\n"
                   "// generation command line:\n"
                   "//    protoc --plugin=protoc-gen-hpp=/path/to/{}\n"
                   "//           --hpp_out {}:${{out_dir}}\n"
                   "//           {}\n\n",
                   plugin_name.filename().string(), plugin_parameters, file);
  }

  static auto dependencies(file_descriptor_t &descriptor) {
    return descriptor.proto().dependency |
           std::views::filter([](const auto &dep) { return dep != "hpp_proto/hpp_options.proto"; });
  }
};

std::filesystem::path code_generator::plugin_name;
std::string code_generator::plugin_parameters;
std::vector<std::string> code_generator::proto2_explicit_presences;
std::string code_generator::directory_prefix;

struct msg_code_generator : code_generator {
  std::string syntax;
  std::string out_of_class_data;
  std::back_insert_iterator<std::string> out_of_class_target;
  using FieldDescriptorProto = google::protobuf::FieldDescriptorProto<traits_type>;

  explicit msg_code_generator(std::vector<CodeGeneratorResponse::File> &files)
      : code_generator(files), out_of_class_target(out_of_class_data) {}

  static std::string namespace_prefix_of(const auto &d) { return d.parent_file()->namespace_prefix; }

  static void set_field_cpp_type(field_descriptor_t &field, std::string_view relative_type_name, bool is_nested) {
    using enum FieldDescriptorProto::Type;
    auto type = field.proto().type;
    if (type == TYPE_ENUM) {
      field.qualified_cpp_field_type = field.enum_field_type_descriptor()->qualified_name;
    } else {
      field.qualified_cpp_field_type = field.message_field_type_descriptor()->qualified_name;
    }

    if (field.is_foreign) {
      field.cpp_field_type = field.qualified_cpp_field_type;
    } else if (field.is_recursive) {
      // only the last component of the type_name should be used
      field.cpp_field_type = field.message_field_type_descriptor()->cpp_name;
    } else if (is_nested) {
      field.cpp_field_type = make_qualified_cpp_name("", relative_type_name);
      ;
    } else {
      // only the components excluding the common ancestor should be used
      const auto num_components = std::ranges::count(relative_type_name, '.');
      std::string_view v = field.qualified_cpp_field_type;
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
  static void resolve_field_dependency(hpp_gen_descriptor_pool &pool, std::string_view field_message_name,
                                       field_descriptor_t &field) {
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
        resolve_field_dependency(pool, field_message_name, value_field);
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
    set_field_cpp_type(field, relative_field_type, common_ancestor.size() == field_message_name.size());

    // If the common ancestor equals dependee_name, the field's type is a nested enum of the enclosing message or a
    // file level enum. If the common ancestor equals dependent_name, the field's type is a nested message of the
    // parent message. In either case there is no external dependency to record, so return.
    if (dependee_name.size() == common_ancestor.size() || dependent_name.size() == common_ancestor.size()) {
      return;
    }
    message_descriptor_t *dependent_msg = pool.get_message_descriptor(dependent_name);
    message_descriptor_t *dependee_msg = pool.get_message_descriptor(dependee_name);

    if (dependent_msg != nullptr && dependee_msg != nullptr &&
        dependent_msg->parent_file() == dependee_msg->parent_file()) {
      dependent_msg->dependencies.insert(dependee_msg);
    }
  }

  static void resolve_message_field(hpp_gen_descriptor_pool &pool, field_descriptor_t &field) {
    auto *parent = field.parent_message();
    if (parent == nullptr || !parent->is_map_entry()) {
      resolve_field_dependency(pool, field.qualified_parent_name(), field);
    }
    auto *field_type_msg = field.message_field_type_descriptor();
    field_type_msg->used_by_fields.push_back(&field);
  }

  static void resolve_enum_field(hpp_gen_descriptor_pool &pool, field_descriptor_t &field) {
    resolve_field_dependency(pool, field.qualified_parent_name(), field);
    auto *enum_d = field.enum_field_type_descriptor();
    if (enum_d != nullptr) {
      field.is_closed_enum = enum_d->is_closed();
      if (!field.proto().default_value.empty()) {
        field.set_enum_default_value(field.proto());
      } else if (field.proto().label == FieldDescriptorProto::Label::LABEL_OPTIONAL) {
        std::string proto_default_value = resolve_keyword(enum_d->proto().value[0].name);
        field.default_value = fmt::format("{}::{}", field.cpp_field_type, proto_default_value);
        field.default_value_template_arg = fmt::format("{}::{}", field.qualified_cpp_field_type, proto_default_value);
      }
    }
  }

  static void resolve_enum_qualified_name(enum_descriptor_t &desc, std::string_view scope) {
    desc.qualified_name = fmt::format("{}{}", scope, desc.cpp_name);
  }

  static void resolve_message_qualified_name(message_descriptor_t &msg, std::string_view namespace_prefix,
                                             std::string_view scope) {
    msg.qualified_name = fmt::format("{}{}{}<Traits>", namespace_prefix, scope, msg.cpp_name);
    msg.no_namespace_qualified_name = msg.qualified_name.substr(namespace_prefix.size());

    std::string nested_scope = fmt::format("{}{}_::", scope, msg.cpp_name);

    for (auto &nested_msg : msg.messages()) {
      resolve_message_qualified_name(nested_msg, namespace_prefix, nested_scope);
    }

    std::string nested_enum_scope = fmt::format("{}{}", namespace_prefix, nested_scope);
    for (auto &nested_enum : msg.enums()) {
      resolve_enum_qualified_name(nested_enum, nested_enum_scope);
    }
  }

  static void resolve_message_dependencies(hpp_gen_descriptor_pool &pool) {
    for (auto &file : pool.files()) {
      for (auto &msg : file.messages()) {
        resolve_message_qualified_name(msg, file.cpp_namespace + "::", "");
      }
      for (auto &desc : file.enums()) {
        resolve_enum_qualified_name(desc, file.cpp_namespace + "::");
      }
    }

    for (auto &field : pool.fields()) {
      using enum FieldDescriptorProto::Type;
      switch (field.proto().type) {
      case TYPE_MESSAGE:
      case TYPE_GROUP:
        resolve_message_field(pool, field);
        break;
      case TYPE_ENUM:
        resolve_enum_field(pool, field);
        break;
      default:
        break;
      };
    }
  }

  void process(file_descriptor_t &descriptor) {
    syntax = descriptor.syntax;
    auto file_name = descriptor.proto().name;
    gen_file_header(file_name);
    file.name = file_name.substr(0, file_name.size() - 5) + "msg.hpp";
    fmt::format_to(target, "#pragma once\n\n"
                           "#include <hpp_proto/field_types.hpp>\n");

    for (const auto &d : dependencies(descriptor)) {
      fmt::format_to(target, "#include \"{}.msg.hpp\"\n", basename(d, directory_prefix));
    }
    fmt::format_to(target, "// @@protoc_insertion_point(includes)\n\n");

    const auto &ns = descriptor.cpp_namespace;
    if (!ns.empty()) {
      fmt::format_to(target,
                     "\nnamespace {} {{\n"
                     "//NOLINTBEGIN(performance-enum-size)\n\n",
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
      fmt::format_to(target,
                     "// NOLINTEND(performance-enum-size)\n"
                     "}} // namespace {}\n"
                     "// clang-format on\n",
                     ns);
    }
  }

  static std::string_view field_type_wrapper(field_descriptor_t &descriptor) {
    const auto &proto = descriptor.proto();
    using enum FieldDescriptorProto::Label;
    using enum FieldDescriptorProto::Type;
    if (proto.label == LABEL_REPEATED) {
      return "Traits::template repeated_t";
    }
    if (proto.type == TYPE_GROUP || proto.type == TYPE_MESSAGE) {
      if (descriptor.is_recursive) {
        return "Traits::template optional_recursive_t";
      } else if (descriptor.is_cpp_optional) {
        return "std::optional";
      }
    } else if (descriptor.is_cpp_optional) {
      return "::hpp::proto::optional";
    }
    return "";
  }

  static std::string field_type(field_descriptor_t &descriptor) {
    if (descriptor.is_map_entry()) {
      auto *type_desc = descriptor.message_field_type_descriptor();
      return fmt::format("Traits::template map_t<{}, {}>", type_desc->fields().front().cpp_field_type,
                         type_desc->fields()[1].cpp_field_type);
    }

    auto wrapper = field_type_wrapper(descriptor);

    if (wrapper == "::hpp::proto::optional" && !descriptor.default_value_template_arg.empty()) {
      return fmt::format("::hpp::proto::optional<{0}, {1}>", descriptor.cpp_field_type,
                         descriptor.default_value_template_arg);
    } else if (!wrapper.empty()) {
      return fmt::format("{}<{}>", wrapper, descriptor.cpp_field_type);
    }
    return descriptor.cpp_field_type;
  }

  void set_presence_rule(field_descriptor_t &descriptor) const {
    using enum FieldDescriptorProto::Type;
    using enum FieldDescriptorProto::Label;
    std::string qualified_name = std::string{descriptor.qualified_parent_name()} + "." + descriptor.proto().name;

    descriptor.is_cpp_optional =
        (syntax != "proto2" || proto2_explicit_presences.empty())
            ? descriptor.explicit_presence()
            : (descriptor.proto().label == LABEL_OPTIONAL &&
               (descriptor.proto().type == TYPE_MESSAGE || descriptor.proto().type == TYPE_GROUP ||
                std::ranges::any_of(proto2_explicit_presences, [&qualified_name](const auto &s) {
                  return qualified_name.starts_with(std::string_view{s}.substr(1));
                })));
  }

  void process(field_descriptor_t &descriptor) {
    set_presence_rule(descriptor);
    std::string initializer = " = {}";
    using enum FieldDescriptorProto::Type;

    if (field_type_wrapper(descriptor).size() > 1 || descriptor.proto().type == TYPE_STRING ||
        descriptor.proto().type == TYPE_BYTES) {
      initializer = "";
    } else if (!descriptor.default_value.empty()) {
      initializer = " = " + descriptor.default_value;
    }
    fmt::format_to(target, "{}{} {}{};\n", indent(), field_type(descriptor), descriptor.cpp_name, initializer);
  }

  void process(oneof_descriptor_t &descriptor, std::int32_t number) {
    auto fields = descriptor.fields();
    if (number != fields[0].proto().number) {
      return;
    }

    if (fields.size() > 1) {
      std::string types;

      fmt::format_to(target,
                     "{0}// NOLINTNEXTLINE(cppcoreguidelines-use-enum-class)\n"
                     "{0}enum {1}_oneof_case : int {{\n",
                     indent(), descriptor.cpp_name);
      indent_num += 2;
      std::size_t index = 1;
      for (auto &f : fields) {
        const char *sep = (index != fields.size()) ? "," : "";
        fmt::format_to(target, "{}{} = {}{}\n", indent(), f.cpp_name, index++, sep);
      }
      indent_num -= 2;
      fmt::format_to(target, "{}}};\n\n", indent());
      fmt::format_to(target,
                     "{}static constexpr std::array<std::uint32_t, {}> {}_oneof_numbers{{\n"
                     "{}  0U",
                     indent(), fields.size() + 1, descriptor.cpp_name, indent());

      for (auto &f : fields) {
        fmt::format_to(target, ", {}U", f.proto().number);
        types += (", " + f.cpp_field_type);
      }
      fmt::format_to(target, "}};\n");
      fmt::format_to(target, "{}std::variant<std::monostate{}> {};\n", indent(), types, descriptor.cpp_name);
    } else {
      auto &f = fields[0];
      std::string attribute;

      fmt::format_to(target, "{}{}std::optional<{}> {};\n", indent(), attribute, f.cpp_field_type, f.cpp_name);
    }
  }

  void process(enum_descriptor_t &descriptor) {
    fmt::format_to(target, "{}enum class {} {{\n", indent(), descriptor.cpp_name);
    indent_num += 2;
    std::size_t index = 0;
    for (const auto &e : descriptor.proto().value) {
      char sep = (index++ == descriptor.proto().value.size() - 1) ? ' ' : ',';
      fmt::format_to(target, "{}{} = {}{}\n", indent(), resolve_keyword(e.name), e.number, sep);
    }

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());

    fmt::format_to(target, "{}constexpr bool is_valid({} value){{\n", indent(), descriptor.cpp_name);
    if (descriptor.sorted_values.empty()) {
      fmt::format_to(target, "{}  return false;\n", indent());
    } else {
      fmt::format_to(target, "{}  int v = static_cast<int>(value);\n", indent());
      if (descriptor.continuous) {
        fmt::format_to(target, "{}  return v >= {} && v <= {};\n", indent(), descriptor.sorted_values.front(),
                       descriptor.sorted_values.back());
      } else {
        fmt::format_to(target,
                       "{0}  constexpr std::array<int, {1}> valid_values{{{2}}};\n"
                       "{0}  return std::ranges::any_of(valid_values, [v](int u){{ return u==v; }});\n",
                       indent(), descriptor.proto().value.size(), fmt::join(descriptor.sorted_values, ","));
      }
    }
    fmt::format_to(target, "{}}}\n\n", indent());
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
      fmt::format_to(target,
                     "{0}template <typename Traits>\n"
                     "{0}struct {1};\n",
                     indent(), fwd->cpp_name);
    }

    if (!descriptor.enums().empty() || descriptor.has_non_map_nested_message) {
      fmt::format_to(target, "{}namespace {}_ {{\n", indent(), descriptor.cpp_name);
      indent_num += 2;
      for (auto &e : descriptor.enums()) {
        process(e);
      }

      for (auto *m : order_messages(descriptor.messages())) {
        process(*m, descriptor.pb_name);
      }

      indent_num -= 2;
      fmt::format_to(target, "{}}} //namespace {}_\n\n", indent(), descriptor.cpp_name);
    }

    fmt::format_to(target,
                   "{0}template <typename Traits = ::hpp::proto::default_traits>\n"
                   "{0}struct {1} {{\n",
                   indent(), descriptor.cpp_name);
    indent_num += 2;
    fmt::format_to(target, "{}using hpp_proto_traits_type = Traits;\n", indent());
    for (auto &e : descriptor.enums()) {
      fmt::format_to(target, "{}using {} = {};\n", indent(), e.cpp_name, e.qualified_name);
    }

    if (well_known_codecs.contains(descriptor.pb_name)) {
      fmt::format_to(target, "\n{}constexpr static bool glaze_reflect = false;\n\n", indent());
    }

    for (auto &m : descriptor.messages()) {
      if (!m.is_map_entry()) {
        fmt::format_to(target, "{0}using {1} = {2}_::{1}<Traits>;\n\n", indent(), m.cpp_name, descriptor.cpp_name);
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
      fmt::format_to(target, "\n{}struct {};\n", indent(), f.cpp_name);
    }

    if (descriptor.proto().extension_range.empty()) {
      fmt::format_to(target,
                     "\n"
                     "{0}[[no_unique_address]] ::hpp::proto::pb_unknown_fields<Traits> unknown_fields_;",
                     indent());
    } else {
      fmt::format_to(target,
                     "\n"
                     "{0}::hpp::proto::pb_extensions<Traits> unknown_fields_;\n\n"
                     "{0}[[nodiscard]] ::hpp::proto::status get_extension(auto &ext, "
                     "::hpp::proto::concepts::is_option_type auto && "
                     "...option) const {{\n"
                     "{0}  return ext.get_from(*this, std::forward<decltype(option)>(option)...);\n"
                     "{0}}}\n"
                     "{0}[[nodiscard]] auto set_extension(const auto &ext,\n"
                     "{0}                                 ::hpp::proto::concepts::is_option_type auto &&...option) {{\n"
                     "{0}  return ext.set_to(*this, std::forward<decltype(option)>(option)...);\n"
                     "{0}}}\n"
                     "{0}[[nodiscard]] bool has_extension(const auto &ext) const {{\n"
                     "{0}  return ext.in(*this);\n"
                     "{0}}}\n",
                     indent(), descriptor.cpp_name);
    }

    fmt::format_to(target, "\n{0}bool operator == (const {1}&) const = default;\n", indent(), descriptor.cpp_name);

    indent_num -= 2;
    fmt::format_to(target, "{}}};\n\n", indent());
    std::string_view qualified_name = descriptor.no_namespace_qualified_name;
    fmt::format_to(out_of_class_target,
                   "template <typename Traits>\n"
                   "constexpr auto message_type_url(const {0}{1}&) {{ return "
                   "::hpp::proto::string_literal<\"type.googleapis.com/{2}\">{{}}; }}\n",
                   qualified_name.ends_with('>') ? "" : "typename ", qualified_name, descriptor.pb_name);
  }

  // NOLINTEND(misc-no-recursion,readability-function-cognitive-complexity)
};

struct hpp_meta_generator : code_generator {
  std::string syntax;
  using code_generator::code_generator;

  void process(file_descriptor_t &descriptor) {
    auto file_name = descriptor.proto().name;
    gen_file_header(file_name);
    file.name = file_name.substr(0, file_name.size() - 5) + "pb.hpp";

    syntax = descriptor.syntax;
    fmt::format_to(target,
                   "#pragma once\n\n"
                   "#include <hpp_proto/pb_serializer.hpp>\n"
                   "#include \"{}.msg.hpp\"\n",
                   basename(descriptor.proto().name, directory_prefix));
    for (const auto &d : descriptor.proto().dependency) {
      if (d != "hpp_proto/hpp_options.proto") {
        fmt::format_to(target, "#include \"{}.pb.hpp\"\n", basename(d, directory_prefix));
      }
    }

    fmt::format_to(target, "\n");

    auto package = descriptor.proto().package;
    auto ns = make_qualified_cpp_name(descriptor.namespace_prefix, "." + package);

    if (!ns.empty()) {
      fmt::format_to(target, "\nnamespace {} {{\n\n", ns);
    }

    for (auto &m : descriptor.messages()) {
      process(m, package);
    }

    for (auto &f : descriptor.extensions()) {
      format_extension(f);
    }

    if (!ns.empty()) {
      fmt::format_to(target, "}} // namespace {}\n", ns);
    }

    fmt::format_to(target, "// clang-format on\n");
  }

  // NOLINTBEGIN(misc-no-recursion)
  void process(message_descriptor_t &descriptor, const std::string &pb_scope) {
    std::string pb_name = descriptor.proto().name;
    if (!pb_scope.empty()) {
      pb_name = pb_scope + "." + pb_name;
    }

    auto &qualified_name = descriptor.no_namespace_qualified_name;

    fmt::format_to(target,
                   "{0}template <typename Traits>\n"
                   "{0}auto pb_meta(const {1}<Traits> &) -> std::tuple<\n",
                   indent(), descriptor.cpp_name);
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
      fmt::format_to(target, "{}::hpp::proto::field_meta<UINT32_MAX, &{}::unknown_fields_>", indent(), qualified_name);
    }
    indent_num -= 2;

    fmt::format_to(target, ">;\n\n");

    if (descriptor.has_non_map_nested_message) {
      fmt::format_to(target, "{}namespace {}_ {{\n", indent(), descriptor.cpp_name);
      indent_num += 2;

      for (auto &m : descriptor.messages()) {
        if (!m.is_map_entry()) {
          process(m, pb_name);
        }
      }
      indent_num -= 2;
      fmt::format_to(target, "{}}} //namespace {}_\n\n", indent(), descriptor.cpp_name);
    }

    for (auto &f : descriptor.extensions()) {
      format_extension(f);
    }
  }

  static std::vector<std::string_view> meta_options(const field_descriptor_t &descriptor) {
    std::vector<std::string_view> options;
    using enum google::protobuf::FieldDescriptorProto_::Label;
    if (descriptor.is_cpp_optional || descriptor.is_required()) {
      options.emplace_back("::hpp::proto::field_option::explicit_presence");
    } else if (descriptor.is_packed()) {
      options.emplace_back("::hpp::proto::field_option::is_packed");
    }

    if (descriptor.is_delimited()) {
      options.emplace_back("::hpp::proto::field_option::group");
    } else if (descriptor.requires_utf8_validation()) {
      options.emplace_back("::hpp::proto::field_option::utf8_validation");
    } else if (descriptor.is_closed_enum) {
      options.emplace_back("::hpp::proto::field_option::closed_enum");
    } else if (options.empty()) {
      options.emplace_back("::hpp::proto::field_option::none");
    }
    return options;
  }
  // NOLINTEND(misc-no-recursion)
  // NOLINTBEGIN(readability-function-cognitive-complexity)
  void process(field_descriptor_t &descriptor, std::size_t oneof_index) {
    auto options = meta_options(descriptor);
    auto proto = descriptor.proto();
    using enum google::protobuf::FieldDescriptorProto_::Label;
    using enum google::protobuf::FieldDescriptorProto_::Type;

    if (descriptor.is_map_entry()) {
      auto get_meta_type = [](const auto &field) {
        return field.cpp_meta_type == "void" ? field.qualified_cpp_field_type : field.cpp_meta_type;
      };
      auto *type_desc = descriptor.message_field_type_descriptor();
      descriptor.cpp_meta_type =
          fmt::format("::hpp::proto::map_entry<{}, {}, {}, {}>", get_meta_type(type_desc->fields()[0]),
                      get_meta_type(type_desc->fields()[1]), fmt::join(meta_options(type_desc->fields()[0]), " | "),
                      fmt::join(meta_options(type_desc->fields()[1]), " | "));
    }

    std::string default_value;

    if (options[0] == "::hpp::proto::field_option::none" || descriptor.is_closed_enum) {
      default_value = descriptor.default_value_template_arg;
    }

    std::string type_and_default_value;
    if (descriptor.cpp_meta_type != "void" || !default_value.empty()) {
      type_and_default_value = fmt::format(", {}", descriptor.cpp_meta_type);
      if (!default_value.empty()) {
        fmt::format_to(std::back_inserter(type_and_default_value), ", {}", default_value);
      }
    }

    auto cpp_name = (descriptor.parent_message() == nullptr)
                        ? descriptor.cpp_name
                        : descriptor.parent_message()->cpp_name + "<Traits>::" + descriptor.cpp_name;

    if (descriptor.extendee_descriptor() == nullptr) {
      std::string access = (oneof_index == 0) ? "&" + cpp_name : std::to_string(oneof_index);

      fmt::format_to(target, "{}::hpp::proto::field_meta<{}, {}, {}{}>,\n", indent(), proto.number, access,
                     fmt::join(options, " | "), type_and_default_value);
    }
  }

  void format_extension(code_generator::field_descriptor_t &descriptor) {

    auto cpp_name = (descriptor.parent_message() == nullptr)
                        ? descriptor.cpp_name
                        : descriptor.parent_message()->cpp_name + "<Traits>::" + descriptor.cpp_name;

    using enum google::protobuf::FieldDescriptorProto_::Label;
    using enum google::protobuf::FieldDescriptorProto_::Type;
    auto proto = descriptor.proto();
    auto extendee_template = std::string_view{descriptor.extendee_descriptor()->qualified_name};
    extendee_template =
        extendee_template.substr(0, extendee_template.size() - sizeof("<Traits>") + 1); // remove the trailing <Traits>

    auto default_value = descriptor.default_value_template_arg;
    if (default_value.empty()) {
      default_value = "std::monostate{}";
    }

    auto field_value_type = descriptor.cpp_field_type;
    bool is_repeated = proto.label == LABEL_REPEATED;

    auto get_result_type =
        is_repeated ? fmt::format("typename Traits::template repeated_t<{}>", field_value_type) : field_value_type;

    const char *extra_crtp_arg = "";
    if (proto.type == TYPE_MESSAGE || proto.type == TYPE_GROUP || proto.type == TYPE_STRING ||
        proto.type == TYPE_BYTES || is_repeated || descriptor.parent_message() != nullptr) {
      const char *default_traits = "";
      if (descriptor.parent_message() == nullptr) {
        extra_crtp_arg = "<Traits>";
        default_traits = " = ::hpp::proto::default_traits";
      }
      fmt::format_to(target, "{0}template <typename Traits{1}>\n", indent(), default_traits);
    }

    std::string initializer = " = {}";

    if (!descriptor.default_value.empty()) {
      initializer = " = " + descriptor.default_value;
    }

    fmt::format_to(target,
                   "{0}struct {1}\n"
                   "{0}    : ::hpp::proto::extension_base<{1}{2}, {3}> {{\n"
                   "{0}  using value_type={4};\n"
                   "{0}  value_type value{5};\n"
                   "{0}  using pb_meta = std::tuple<::hpp::proto::field_meta<{6}, &{1}{2}::value, {7}, {8}, {9}>>;\n"
                   "{0}}};\n\n",
                   indent(), cpp_name, extra_crtp_arg, extendee_template, get_result_type, initializer, proto.number,
                   fmt::join(meta_options(descriptor), " | "), descriptor.cpp_meta_type, default_value);
  }

  // NOLINTEND(readability-function-cognitive-complexity)

  void process(oneof_descriptor_t &descriptor, message_descriptor_t &parent) {
    auto fields = descriptor.fields();
    if (fields.size() > 1) {
      std::string types;
      std::string sep;
      for (auto &f : fields) {
        types += (sep + f.cpp_field_type);
        sep = ",";
      }
      fmt::format_to(target, "{}::hpp::proto::oneof_field_meta<\n", indent());
      indent_num += 2;
      fmt::format_to(target, "{}&{}::{},\n", indent(), parent.no_namespace_qualified_name, descriptor.cpp_name);
      std::size_t i = 0;
      for (auto &f : fields) {
        process(f, ++i);
      }

      indent_num -= 2;
      if (!fields.empty()) {
        auto &content = file.content;
        content.resize(content.size() - 2);
      }
      fmt::format_to(target, ">,\n");
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
    file.name = file_name.substr(0, file_name.size() - 5) + "glz.hpp";

    std::string sole_message_name;
    if (descriptor.messages().size() == 1) {
      sole_message_name = descriptor.messages().front().pb_name;
    }

    if (sole_message_name != "google.protobuf.Any") {
      fmt::format_to(target, "#pragma once\n\n"
                             "#include <hpp_proto/json_serializer.hpp>\n");

      for (const auto &d : descriptor.proto().dependency) {
        fmt::format_to(target, "#include \"{}.glz.hpp\"\n", basename(d, directory_prefix));
      }

      fmt::format_to(target, "#include \"{}.msg.hpp\"\n\n", basename(descriptor.proto().name, directory_prefix));

      if (!sole_message_name.empty() && well_known_codecs.contains(sole_message_name)) {
        fmt::format_to(target, "#include <hpp_proto/{}.hpp>\n\n", well_known_codecs.at(sole_message_name));
      }
    } else {
      fmt::format_to(target,
                     "#pragma once\n\n"
                     "#include <hpp_proto/dynamic_message_json.hpp>\n\n"
                     "#include \"{}.msg.hpp\"\n\n",
                     basename(descriptor.proto().name, directory_prefix));
    }

    for (auto &m : descriptor.messages()) {
      process(m);
    }

    for (auto &e : descriptor.enums()) {
      process(e);
    }

    fmt::format_to(target, "// clang-format on\n");
  }

  // NOLINTBEGIN(misc-no-recursion,readability-function-cognitive-complexity)
  void process(message_descriptor_t &descriptor) {
    auto qualified_name = descriptor.qualified_name;

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
                     "  GLZ_ALWAYS_INLINE static void op(auto &value, auto&& ...args) {{\n"
                     "    parse<JSON>::template op<{1}>(value.value, "
                     "std::forward<decltype(args)>(args)...);\n"
                     "  }}\n"
                     "}};\n"
                     "}} // namespace glz\n\n",
                     qualified_name, opts);
    } else if (well_known_codecs.contains(descriptor.pb_name)) {
      fmt::format_to(target,
                     "template <typename Traits>\n"
                     "struct hpp::proto::json_codec<{0}> {{\n"
                     "  using type = ::hpp::proto::{1};\n"
                     "}};\n\n",
                     qualified_name, well_known_codecs.at(descriptor.pb_name));
    } else if (descriptor.pb_name == "google.protobuf.Value") {
      fmt::format_to(target,
                     // clang-format off
                     "namespace glz {{\n"
                     "template <typename Traits>\n"
                     "struct to<JSON, {0}> {{\n"
                     "  template <auto Opts>\n"
                     "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&b, auto &&ix) {{\n"
                     "    std::visit(\n"
                     "        [&ctx, &b, &ix](auto &v) {{\n"
                     "          using type = std::decay_t<decltype(v)>;\n"
                     "          if constexpr (std::same_as<type, {1}::ListValue<Traits>>) {{\n"
                     "            serialize<JSON>::template op<Opts>(v.values, ctx, b, ix);\n"
                     "          }} else if constexpr (std::same_as<type, {1}::Struct<Traits>>) {{\n"
                     "            serialize<JSON>::template op<Opts>(v.fields, ctx, b, ix);\n"
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
                     "      parse<JSON>::op<Opts>(value.kind.template emplace<{0}::kind_oneof_case::string_value>(), ctx, it, end);\n"
                     "    }} else if (*it == 't' || *it == 'f') {{\n"
                     "      parse<JSON>::op<Opts>(value.kind.template emplace<bool>(), ctx, it, end);\n"
                     "    }} else if (*it == '{{') {{\n"
                     "      parse<JSON>::op<Opts>(value.kind.template emplace<{0}::kind_oneof_case::struct_value>().fields, ctx, it, end);\n"
                     "    }} else if (*it == '[') {{\n"
                     "      parse<JSON>::op<Opts>(value.kind.template emplace<{0}::kind_oneof_case::list_value>().values, ctx, it, end);\n"
                     "    }}\n"
                     "  }}\n"
                     "}};\n"
                     "}} // namespace glz\n\n",
                     // clang-format on
                     qualified_name, descriptor.parent_file()->cpp_namespace);
    } else if (descriptor.pb_name == "google.protobuf.Any") {
      fmt::format_to(
          target,
          "namespace glz {{\n"
          "template <typename Traits>\n"
          "struct to<JSON, {0}> {{\n"
          "  template <auto Opts>"
          "  GLZ_ALWAYS_INLINE static void op(auto &&value, ::hpp::proto::concepts::is_json_context auto &ctx, auto &b, auto &ix) {{\n"
          "    any_message_json_serializer::to_json<Opts>(value, ctx, b, ix);\n"
          "  }}\n"
          "}};\n\n"
          "template <typename Traits>\n"
          "struct from<JSON, {0}> {{\n"
          "  template <auto Opts>\n"
          "  GLZ_ALWAYS_INLINE static void op(auto &&value, ::hpp::proto::concepts::is_json_context auto &ctx, auto &it, auto &end) {{\n"
          "    any_message_json_serializer::from_json<Opts>(value, ctx, it, end);\n"
          "  }}\n"
          "}};\n"
          "}} // namespace glz\n",
          qualified_name);
    } else if (descriptor.pb_name == "google.protobuf.Struct") {
      fmt::format_to(
          target, "namespace glz {{\n"
                  "\n"
                  "template <typename Traits>\n"
                  "struct to<JSON, google::protobuf::Struct<Traits>> {{\n"
                  "  template <auto Opts>\n"
                  "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&b, auto &&ix) {{\n"
                  "    using fields_t = std::remove_cvref_t<decltype(value.fields)>;\n"
                  "    to<JSON, fields_t>::template op<Opts>(value.fields, ctx, b, ix);\n"
                  "  }}\n"
                  "}};\n"
                  "\n"
                  "template <typename Traits>\n"
                  "struct from<JSON, google::protobuf::Struct<Traits>> {{\n"
                  "  template <auto Options>\n"
                  "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&it, auto &&end) {{\n"
                  "    using fields_t = std::remove_cvref_t<decltype(value.fields)>;\n"
                  "    from<JSON, fields_t>::template op<Options>(value.fields, ctx, it, end);\n"
                  "  }}\n"
                  "}};\n"
                  "}} // namespace glz\n");
    } else if (descriptor.pb_name == "google.protobuf.ListValue") {
      fmt::format_to(
          target, "namespace glz {{\n"
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
                  "  template <auto Options>\n"
                  "  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &&ctx, auto &&it, auto &&end) {{\n"
                  "    using values_t = std::remove_cvref_t<decltype(value.values)>;\n"
                  "    from<JSON, values_t>::template op<Options>(value.values, ctx, it, end);\n"
                  "  }}\n"
                  "}};\n"
                  "}} // namespace glz\n");
    } else {
      fmt::format_to(target,
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

      fmt::format_to(target, ");\n}};\n\n");

      for (auto &m : descriptor.messages()) {
        if (!m.is_map_entry()) {
          process(m);
        }
      }

      for (auto &e : descriptor.enums()) {
        process(e);
      }
    }
  }
  // NOLINTEND(misc-no-recursion,readability-function-cognitive-complexity)

  void process(field_descriptor_t &descriptor) {
    using FieldDescriptorProto = google::protobuf::FieldDescriptorProto<traits_type>;
    using enum FieldDescriptorProto::Type;
    using enum FieldDescriptorProto::Label;

    if (descriptor.is_cpp_optional && descriptor.proto().type != TYPE_BOOL) {
      // we remove operator! from hpp::optional<bool> to make the interface less confusing; however, this
      // make it unfulfilling the optional concept in glaze library; therefor, we need to apply as_optional_ref
      // as a workaround.
      fmt::format_to(target, "    \"{}\", &T::{},\n", descriptor.proto().json_name, descriptor.cpp_name);
    } else if (descriptor.proto().label == LABEL_REQUIRED) {
      auto type = descriptor.proto().type;
      if (type == TYPE_INT64 || type == TYPE_UINT64 || type == TYPE_FIXED64 || type == TYPE_SFIXED64 ||
          type == TYPE_SINT64) {
        fmt::format_to(target, "    \"{}\", glz::quoted_num<&T::{}>,\n", descriptor.proto().json_name,
                       descriptor.cpp_name);
      } else {
        fmt::format_to(target, "    \"{}\", &T::{},\n", descriptor.proto().json_name, descriptor.cpp_name);
      }
    } else {
      std::string name_and_default_value = descriptor.cpp_name;
      if (!descriptor.default_value_template_arg.empty()) {
        name_and_default_value += ", " + descriptor.default_value_template_arg;
      }
      fmt::format_to(target, "    \"{}\", ::hpp::proto::as_optional_ref<&T::{}>,\n", descriptor.proto().json_name,
                     name_and_default_value);
    }
  }

  void process(oneof_descriptor_t &descriptor) {
    auto fields = descriptor.fields();
    if (fields.size() > 1) {
      for (unsigned i = 0; i < fields.size(); ++i) {
        fmt::format_to(target, "    \"{}\", ::hpp::proto::as_oneof_member<&T::{},{}>,\n", fields[i].proto().json_name,
                       descriptor.cpp_name, i + 1);
      }
    } else {
      process(fields[0]);
    }
  }

  void process(enum_descriptor_t &descriptor) {

    if (descriptor.cpp_name != "NullValue" || descriptor.parent_file()->proto().package != "google.protobuf") {
      fmt::format_to(target,
                     "template <>\n"
                     "struct glz::meta<{0}> {{\n"
                     "  using enum {0};\n"
                     "  static constexpr auto value = enumerate(\n",
                     descriptor.qualified_name);

      indent_num += 4;
      std::size_t index = 0;
      for (const auto &e : descriptor.proto().value) {
        const char *sep = (index++ == descriptor.proto().value.size() - 1) ? ");" : ",";
        fmt::format_to(target, "{0}\"{1}\", {1}{2}\n", indent(), resolve_keyword(e.name), sep);
      }

      indent_num -= 4;
      fmt::format_to(target, "}};\n\n", indent());
    } else {
      fmt::format_to(
          target,
          "namespace glz {{\n"
          "template <>\n"
          "struct to<JSON, {0}> {{\n"
          "  template <auto Opts>\n"
          "  GLZ_ALWAYS_INLINE static void op(auto &&, auto&& ...args) {{\n"
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
    file.name = path.substr(0, path.size() - 5) + "desc.hpp";

    fmt::format_to(target, "#pragma once\n"
                           "#include <hpp_proto/file_descriptor_pb.hpp>\n\n");

    for (const auto &d : descriptor.proto().dependency) {
      fmt::format_to(target, "#include \"{}.desc.hpp\"\n", basename(d, directory_prefix));
    }

    const auto *const ns = "hpp::proto::file_descriptors";
    fmt::format_to(target, "\nnamespace {} {{\n\n", ns);

    std::vector<std::uint8_t> buf;
    (void)::hpp::proto::write_proto(descriptor.proto(), buf);

    fmt::format_to(target,
                   "using namespace std::literals::string_view_literals;\n"
                   "constexpr file_descriptor_pb _desc_{}{{\n"
                   "  \"{}\"sv\n"
                   "}};\n\n",
                   descriptor.cpp_name, to_hex_literal(buf));

    fmt::format_to(target, "inline auto desc_set_{}(){{\n", descriptor.cpp_name);
    const auto &dependency_names = descriptor.get_dependency_names();
    fmt::format_to(target, "  return distinct_file_descriptor_pb_array{{\n");
    for (const auto &p : dependency_names) {
      fmt::format_to(target, "    _desc_{},\n", p);
    }

    fmt::format_to(target,
                   "  }};\n"
                   "}}\n"
                   "}} // namespace {}\n"
                   "// clang-format on\n",
                   ns);
  }
};

struct service_generator : code_generator {
  using code_generator::code_generator;

  void process(file_descriptor_t &descriptor) {
    if (descriptor.proto().service.empty()) {
      return;
    }

    auto path = descriptor.proto().name;
    gen_file_header(path);
    file.name = path.substr(0, path.size() - 5) + "service.hpp";

    for (const auto &d : descriptor.proto().dependency) {
      fmt::format_to(target, "#include \"{}.pb.hpp\"\n", basename(d, directory_prefix));
    }

    fmt::format_to(target, "#include \"{}.pb.hpp\"\n\n", basename(descriptor.proto().name, directory_prefix));

    auto package = descriptor.proto().package;
    auto ns = make_qualified_cpp_name(descriptor.namespace_prefix, "." + package);

    if (!ns.empty()) {
      fmt::format_to(target, "\nnamespace {} {{\n\n", ns);
    }

    for (const auto &s : descriptor.proto().service) {
      if (s.method.empty()) {
        continue;
      }

      fmt::format_to(target, "namespace {} {{\n", s.name);
      auto proto_service_name = package.empty() ? s.name : package + "." + s.name;
      std::string methods;
      std::size_t ordinal = 0;
      for (const auto &m : s.method) {
        methods += fmt::format("{},", m.name);
        const int rpc_type = (m.server_streaming ? 2 : 0) + (m.client_streaming ? 1 : 0);
        fmt::format_to(target,
                       "  struct {} {{\n"
                       "    constexpr static const char* method_name = \"/{}/{}\";\n"
                       "    constexpr static bool client_streaming = {};\n"
                       "    constexpr static bool server_streaming = {};\n"
                       "    constexpr static int rpc_type = {};\n"
                       "    constexpr static auto ordinal = {};\n"
                       "    template <typename Traits>\n"
                       "    using request_t = {}<Traits>;\n"
                       "    template <typename Traits>\n"
                       "    using response_t = {}<Traits>;\n"
                       "  }};\n",
                       m.name, proto_service_name, m.name, m.client_streaming, m.server_streaming, rpc_type, ordinal++,
                       make_qualified_cpp_name(descriptor.namespace_prefix, m.input_type),
                       make_qualified_cpp_name(descriptor.namespace_prefix, m.output_type));
      }
      // remove trailing comma
      methods.pop_back();
      fmt::format_to(target,
                     "  using _methods = std::tuple<{}>;\n"
                     "}}; // namespace {}\n\n",
                     methods, s.name);
    }

    fmt::format_to(target, "}} // namespace {}\n", ns);
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
int main(int argc, const char **argv) {
  std::span<const char *> args{argv, static_cast<std::size_t>(argc)};
  code_generator::plugin_name = args[0];
  std::vector<char> request_data;

  auto read_file = [&request_data](auto &&strm) {
    std::copy(std::istreambuf_iterator<char>(strm), std::istreambuf_iterator<char>(), std::back_inserter(request_data));
  };

#ifdef _WIN32
  _setmode(_fileno(stdin), _O_BINARY);
#endif

  using namespace std::string_view_literals;

  if (args.size() == 2) {
    read_file(std::ifstream(args[1], std::ios_base::binary));
  } else {
    read_file(std::cin);
  }

  google::protobuf::compiler::CodeGeneratorRequest<traits_type> request;

  if (auto ec = ::hpp::proto::read_proto(request, request_data); !ec.ok()) {
    (void)fputs("hpp decode error", stderr);
    return 1;
  }

  code_generator::plugin_parameters = request.parameter;

  split(request.parameter, ',', [&request_data](auto opt) {
    auto equal_sign_pos = opt.find("=");
    auto opt_key = opt.substr(0, equal_sign_pos);
    auto opt_value = equal_sign_pos != std::string_view::npos ? opt.substr(equal_sign_pos + 1) : std::string_view{};

    if (opt_key == "directory_prefix") {
      code_generator::directory_prefix = opt_value;
    } else if (opt_key == "namespace_prefix") {
      hpp_addons::namespace_prefix = make_qualified_cpp_name("", opt_value);
    } else if (opt_key == "proto2_explicit_presence") {
      code_generator::proto2_explicit_presences.emplace_back(opt_value);
    } else if (opt_key == "export_request") {
      std::ofstream out{std::string(opt_value), std::ios::binary};
      std::ranges::copy(request_data, std::ostreambuf_iterator<char>(out));
    }
  });

  if (code_generator::proto2_explicit_presences.empty()) {
    code_generator::proto2_explicit_presences.emplace_back(".");
  }

  hpp_gen_descriptor_pool pool(
      google::protobuf::FileDescriptorSet<>{.file = std::move(request.proto_file), .unknown_fields_ = {}});

  CodeGeneratorResponse response;
  using enum CodeGeneratorResponse::Feature;
  response.supported_features =
      static_cast<std::uint64_t>(FEATURE_PROTO3_OPTIONAL) | static_cast<std::uint64_t>(FEATURE_SUPPORTS_EDITIONS);

  response.minimum_edition = static_cast<int32_t>(google::protobuf::Edition::EDITION_PROTO2);
  response.maximum_edition = static_cast<int32_t>(google::protobuf::Edition::EDITION_2024);

  for (const auto &file_name : request.file_to_generate) {
    auto &descriptor = *pool.get_file_descriptor(file_name);

    msg_code_generator msg_code(response.file);
    msg_code.resolve_message_dependencies(pool);
    msg_code.process(descriptor);

    hpp_meta_generator hpp_meta_code(response.file);
    hpp_meta_code.process(descriptor);

    glaze_meta_generator glz_meta_code(response.file);
    glz_meta_code.process(descriptor);

    if (!descriptor.messages().empty()) {
      desc_hpp_generator desc_hpp_code(response.file);
      desc_hpp_code.process(descriptor);
    }

    service_generator service_code(response.file);
    service_code.process(descriptor);
  }

  std::vector<char> data;
  if (auto ec = ::hpp::proto::write_proto(response, data); !ec.ok()) {
    (void)fputs("hpp encode error", stderr);
    return 1;
  }

#ifdef _WIN32
  _setmode(_fileno(stdout), _O_BINARY);
#endif
  std::ranges::copy(data, std::ostreambuf_iterator<char>(std::cout));

  return 0;
}
