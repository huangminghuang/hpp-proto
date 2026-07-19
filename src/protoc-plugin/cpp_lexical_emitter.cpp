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

#include "cpp_lexical_emitter.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <system_error>
#include <unordered_set>

namespace hpp_proto::protoc::cpp {
namespace {

// NOLINTBEGIN(cert-err58-cpp)
const std::unordered_set<std::string_view> cpp_keywords = {
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

constexpr int decimal_radix = 10;
constexpr int hexadecimal_radix = 16;
constexpr int octal_radix = 8;
constexpr auto byte_value_count = static_cast<std::size_t>(std::numeric_limits<unsigned char>::max()) + 1U;
constexpr auto first_non_ascii = static_cast<unsigned char>(0x7f);

[[nodiscard]] constexpr unsigned char as_unsigned(char value) { return static_cast<unsigned char>(value); }

[[nodiscard]] constexpr bool is_ascii_digit(unsigned char byte) { return byte >= '0' && byte <= '9'; }

[[nodiscard]] constexpr bool is_ascii_alpha(unsigned char byte) {
  return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z');
}

[[nodiscard]] constexpr bool is_identifier_start(unsigned char byte) { return byte == '_' || is_ascii_alpha(byte); }

[[nodiscard]] constexpr bool is_identifier_continue(unsigned char byte) {
  return byte == '_' || is_ascii_alpha(byte) || is_ascii_digit(byte);
}

[[nodiscard]] std::string safe_identifier(std::string_view name) {
  return cpp_keywords.contains(name) ? std::format("{}_", name) : std::string{name};
}

[[nodiscard]] lexical_error error(lexical_errc code, std::string message) {
  return {.code = code, .message = std::move(message)};
}

[[nodiscard]] bool is_reserved_cpp_identifier(std::string_view name) {
  return name.contains("__") || (name.size() > 1U && name.front() == '_' && name[1] >= 'A' && name[1] <= 'Z');
}

[[nodiscard]] std::expected<identifier, lexical_error> file_namespace_component(std::string_view component,
                                                                                std::string_view proto_file) {
  if (component.empty()) {
    return std::unexpected(error(lexical_errc::invalid_file_descriptor_name,
                                 std::format("invalid protobuf file path for descriptor name: {}", proto_file)));
  }

  std::string spelling;
  spelling.reserve(component.size() + 1U);
  for (const char character : component) {
    const auto byte = as_unsigned(character);
    spelling.push_back(is_identifier_continue(byte) ? character : '_');
  }
  if (is_ascii_digit(as_unsigned(spelling.front()))) {
    spelling.insert(spelling.begin(), '_');
  }

  auto identifier = identifier::from_protobuf_namespace(spelling);
  if (!identifier.has_value() || is_reserved_cpp_identifier(identifier->view())) {
    return std::unexpected(
        error(lexical_errc::invalid_file_descriptor_name,
              std::format("protobuf file path component '{}' does not produce a usable C++ descriptor namespace in {}",
                          component, proto_file)));
  }
  return identifier;
}

[[nodiscard]] std::expected<identifier, lexical_error> file_namespace_override(std::string_view name,
                                                                               std::string_view proto_file) {
  auto identifier = identifier::from_protobuf_namespace(name);
  if (!identifier.has_value() || is_reserved_cpp_identifier(identifier->view())) {
    return std::unexpected(error(
        lexical_errc::invalid_file_descriptor_name,
        std::format("file_descriptor_name '{}' is not a usable C++ namespace identifier for {}", name, proto_file)));
  }
  return identifier;
}

[[nodiscard]] bool is_unsafe_header_byte(unsigned char byte) {
  return byte == '"' || byte == '\r' || byte == '\n' || byte < static_cast<unsigned char>(' ');
}

[[nodiscard]] std::expected<std::string, lexical_error> normalized_header_path(std::string_view path) {
  if (path.empty()) {
    return std::unexpected(error(lexical_errc::invalid_include_path, "generated include path must not be empty"));
  }

  std::string result;
  result.reserve(path.size());
  for (const char value : path) {
    const auto byte = as_unsigned(value);
    if (is_unsafe_header_byte(byte)) {
      return std::unexpected(
          error(lexical_errc::invalid_include_path, "generated include path contains an unsafe byte"));
    }
    result.push_back(byte == '\\' ? '/' : static_cast<char>(byte));
  }
  return result;
}

struct parsed_integer {
  std::uint64_t magnitude{};
  bool negative{};
};

[[nodiscard]] std::expected<parsed_integer, lexical_error> parse_integer(std::string_view value, bool allow_sign) {
  if (value.empty()) {
    return std::unexpected(error(lexical_errc::invalid_numeric_literal, "integer literal must not be empty"));
  }

  parsed_integer result;
  if (value.front() == '-' || value.front() == '+') {
    if (!allow_sign) {
      return std::unexpected(error(lexical_errc::invalid_numeric_literal, "unsigned literal must not have a sign"));
    }
    result.negative = value.front() == '-';
    value.remove_prefix(1);
  }
  if (value.empty()) {
    return std::unexpected(error(lexical_errc::invalid_numeric_literal, "integer literal has no digits"));
  }

  int base = decimal_radix;
  if (value.starts_with("0x") || value.starts_with("0X")) {
    base = hexadecimal_radix;
    value.remove_prefix(2);
  } else if (value.size() > 1 && value.front() == '0') {
    base = octal_radix;
    value.remove_prefix(1);
  }
  if (value.empty()) {
    return std::unexpected(error(lexical_errc::invalid_numeric_literal, "integer radix prefix has no digits"));
  }

  const auto *const first = std::to_address(value.begin());
  const auto *const last = std::to_address(value.end());
  const auto parsed = std::from_chars(first, last, result.magnitude, base);
  if (parsed.ec != std::errc{} || parsed.ptr != last) {
    return std::unexpected(error(lexical_errc::invalid_numeric_literal, "invalid integer literal"));
  }
  return result;
}

template <std::floating_point Float>
[[nodiscard]] bool valid_float_spelling(std::string_view value) {
  if (value.empty()) {
    return false;
  }

  Float parsed{};
  const auto *const first = std::to_address(value.begin());
  const auto *const last = std::to_address(value.end());
  const auto result = std::from_chars(first, last, parsed, std::chars_format::general);
  return result.ec == std::errc{} && result.ptr == last && std::isfinite(parsed);
}

struct escape_entry {
  std::array<char, 4> data{};
  unsigned char size{};
};

constexpr char octal_digit(unsigned int digit) { return static_cast<char>(static_cast<unsigned int>('0') + digit); }

constexpr escape_entry short_escape(char escaped) { return {.data = {'\\', escaped}, .size = 2}; }

constexpr escape_entry make_escape_entry(unsigned char byte) {
  switch (byte) {
  case '\a':
    return short_escape('a');
  case '\b':
    return short_escape('b');
  case '\t':
    return short_escape('t');
  case '\n':
    return short_escape('n');
  case '\v':
    return short_escape('v');
  case '\f':
    return short_escape('f');
  case '\r':
    return short_escape('r');
  case '"':
    return short_escape('"');
  case '\'':
    return short_escape('\'');
  case '\\':
    return short_escape('\\');
  case '?':
    return short_escape('?');
  default:
    break;
  }

  constexpr auto first_printable = static_cast<unsigned char>(' ');
  if (byte < first_printable || byte >= first_non_ascii) {
    constexpr auto unsigned_octal_radix = static_cast<unsigned int>(octal_radix);
    constexpr unsigned int high_place = unsigned_octal_radix * unsigned_octal_radix;
    const auto value = static_cast<unsigned int>(byte);
    return {
        .data = {'\\', octal_digit(value / high_place),
                 octal_digit((value / unsigned_octal_radix) % unsigned_octal_radix),
                 octal_digit(value % unsigned_octal_radix)},
        .size = 4,
    };
  }

  return {.data = {static_cast<char>(byte)}, .size = 1};
}

consteval auto make_escape_table() {
  std::array<escape_entry, byte_value_count> table{};
  std::size_t byte = 0;
  for (auto &entry : table) {
    entry = make_escape_entry(static_cast<unsigned char>(byte));
    ++byte;
  }
  return table;
}

constexpr auto escape_table = make_escape_table();

[[nodiscard]] const escape_entry &escape_for(unsigned char byte) {
  // Every unsigned-char value has a table entry.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
  return escape_table[byte];
}

} // namespace

std::expected<identifier, lexical_error> identifier::from_proto(std::string_view name) {
  if (name.empty() || !is_identifier_start(static_cast<unsigned char>(name.front())) ||
      !std::ranges::all_of(name.substr(1), [](char byte) { return is_identifier_continue(as_unsigned(byte)); })) {
    return std::unexpected(error(lexical_errc::invalid_identifier, std::format("invalid C++ identifier: {}", name)));
  }
  if (is_reserved_cpp_identifier(name)) {
    return std::unexpected(
        error(lexical_errc::invalid_identifier,
              std::format("protobuf identifier '{}' is reserved by C++; rename the protobuf declaration", name)));
  }
  return identifier{safe_identifier(name)};
}

std::expected<identifier, lexical_error> identifier::from_protobuf_namespace(std::string_view name) {
  if (name.empty() || !is_identifier_start(static_cast<unsigned char>(name.front())) ||
      !std::ranges::all_of(name.substr(1), [](char byte) { return is_identifier_continue(as_unsigned(byte)); })) {
    return std::unexpected(error(lexical_errc::invalid_identifier, std::format("invalid C++ identifier: {}", name)));
  }
  return identifier{cpp_keywords.contains(name) ? std::format("{}_", name) : std::string{name}};
}

identifier identifier::append_word(const identifier &word) const {
  std::string spelling = spelling_;
  if (!spelling.ends_with('_')) {
    spelling.push_back('_');
  }
  spelling += word.str();
  return identifier{std::move(spelling)};
}

identifier identifier::disambiguated_with(const identifier &word) const {
  if (spelling_.ends_with('_')) {
    return append_word(word);
  }
  std::string spelling = spelling_;
  spelling.push_back('_');
  return identifier{std::move(spelling)};
}

std::expected<qualified_name, lexical_error> qualified_name::from_dotted(std::string_view name) {
  if (name.empty()) {
    return qualified_name{};
  }

  std::string result;
  std::size_t begin = 0;
  while (begin <= name.size()) {
    const auto end = name.find('.', begin);
    const auto segment = name.substr(begin, end == std::string_view::npos ? name.size() - begin : end - begin);
    auto parsed = identifier::from_proto(segment);
    if (!parsed.has_value()) {
      return std::unexpected(error(lexical_errc::invalid_qualified_name, parsed.error().message));
    }
    if (!result.empty()) {
      result += "::";
    }
    result += parsed->str();
    if (end == std::string_view::npos) {
      break;
    }
    begin = end + 1;
  }
  return qualified_name{std::move(result)};
}

std::expected<qualified_name, lexical_error> qualified_name::from_proto(const qualified_name &namespace_prefix,
                                                                        std::string_view name) {
  if (name == ".") {
    return namespace_prefix;
  }

  const bool absolute = name.starts_with('.');
  if (absolute) {
    name.remove_prefix(1);
  }
  auto parsed = from_dotted(name);
  if (!parsed.has_value()) {
    return parsed;
  }
  if (!absolute || namespace_prefix.empty()) {
    return parsed;
  }
  if (parsed->empty()) {
    return namespace_prefix;
  }
  return qualified_name{std::format("{}::{}", namespace_prefix.view(), parsed->view())};
}

qualified_name qualified_name::append(const identifier &segment) const {
  if (empty()) {
    return qualified_name{segment.str()};
  }
  return qualified_name{std::format("{}::{}", view(), segment.view())};
}

qualified_name qualified_name::append(const qualified_name &suffix) const {
  if (empty()) {
    return suffix;
  }
  if (suffix.empty()) {
    return *this;
  }
  return qualified_name{std::format("{}::{}", view(), suffix.view())};
}

std::expected<file_descriptor_name, lexical_error>
file_descriptor_name::from_proto_file(std::string_view proto_file,
                                      std::optional<std::string_view> final_component_override) {
  if (proto_file.empty() || proto_file.starts_with('/') || proto_file.ends_with('/') ||
      !proto_file.ends_with(".proto")) {
    return std::unexpected(error(lexical_errc::invalid_file_descriptor_name,
                                 std::format("invalid protobuf file path for descriptor name: {}", proto_file)));
  }

  auto root = qualified_name::from_dotted("hpp_proto.file_descriptors");
  if (!root.has_value()) {
    return std::unexpected(root.error());
  }

  auto descriptor_namespace = std::move(*root);
  std::size_t begin = 0;
  while (begin < proto_file.size()) {
    const auto separator = proto_file.find('/', begin);
    const bool final_component = separator == std::string_view::npos;
    const auto component = proto_file.substr(begin, final_component ? proto_file.size() - begin : separator - begin);

    auto identifier = final_component && final_component_override.has_value()
                          ? file_namespace_override(*final_component_override, proto_file)
                          : file_namespace_component(component, proto_file);
    if (!identifier.has_value()) {
      return std::unexpected(identifier.error());
    }
    descriptor_namespace = descriptor_namespace.append(*identifier);
    if (final_component) {
      break;
    }
    begin = separator + 1U;
  }

  auto descriptor_identifier = identifier::from_protobuf_namespace("file_descriptor_");
  auto descriptor_set_identifier = identifier::from_protobuf_namespace("file_descriptor_set");
  if (!descriptor_identifier.has_value() || !descriptor_set_identifier.has_value()) {
    return std::unexpected(
        error(lexical_errc::invalid_file_descriptor_name, "invalid generator-owned file descriptor identifier"));
  }
  return file_descriptor_name{std::move(descriptor_namespace), std::move(*descriptor_identifier),
                              std::move(*descriptor_set_identifier)};
}

qualified_name file_descriptor_name::qualified_descriptor_name() const {
  return namespace_name_.append(descriptor_identifier_);
}

qualified_name file_descriptor_name::qualified_descriptor_set_name() const {
  return namespace_name_.append(descriptor_set_identifier_);
}

string_literal_bytes::string_literal_bytes(std::string_view bytes) {
  std::size_t size = 2;
  for (const char value : bytes) {
    const auto byte = as_unsigned(value);
    size += escape_for(byte).size;
  }
  spelling_.reserve(size);
  spelling_.push_back('"');
  for (const char value : bytes) {
    const auto byte = as_unsigned(value);
    const auto &entry = escape_for(byte);
    spelling_.append(entry.data.data(), entry.size);
  }
  spelling_.push_back('"');
}

std::expected<include_path, lexical_error> include_path::from_proto_file(std::string_view proto_file,
                                                                         std::string_view directory_prefix,
                                                                         std::string_view generated_suffix) {
  const auto extension = proto_file.find_last_of('.');
  if (extension == std::string_view::npos) {
    return std::unexpected(error(lexical_errc::invalid_include_path, "protobuf file name has no extension"));
  }

  std::string path;
  path.reserve(directory_prefix.size() + proto_file.size() + generated_suffix.size() + 3);
  if (!directory_prefix.empty()) {
    path += directory_prefix;
    path.push_back('/');
  }
  path.append(proto_file.substr(0, extension));
  path += generated_suffix;

  auto normalized = normalized_header_path(path);
  if (!normalized.has_value()) {
    return std::unexpected(normalized.error());
  }
  return include_path{std::format("\"{}\"", *normalized)};
}

std::expected<numeric_literal, lexical_error> numeric_literal::signed_integer(std::string_view value,
                                                                              integer_width width) {
  auto parsed = parse_integer(value, true);
  if (!parsed.has_value() || (width != integer_width::bits32 && width != integer_width::bits64)) {
    return std::unexpected(error(lexical_errc::invalid_numeric_literal, "invalid signed integer literal"));
  }
  const auto bit_width = static_cast<unsigned int>(std::to_underlying(width));
  const auto sign_bit = std::uint64_t{1} << (bit_width - 1U);
  const auto maximum = sign_bit - 1U;
  if ((!parsed->negative && parsed->magnitude > maximum) || (parsed->negative && parsed->magnitude > sign_bit)) {
    return std::unexpected(error(lexical_errc::invalid_numeric_literal, "signed integer literal is out of range"));
  }
  if (parsed->negative && parsed->magnitude == sign_bit) {
    return numeric_literal{width == integer_width::bits64 ? "-9223372036854775807LL-1" : "-2147483647-1"};
  }
  return numeric_literal{std::format("{}{}", value, width == integer_width::bits64 ? "LL" : "")};
}

std::expected<numeric_literal, lexical_error> numeric_literal::unsigned_integer(std::string_view value,
                                                                                integer_width width) {
  auto parsed = parse_integer(value, false);
  if (!parsed.has_value() || (width != integer_width::bits32 && width != integer_width::bits64) ||
      (width == integer_width::bits32 && parsed->magnitude > std::numeric_limits<std::uint32_t>::max())) {
    return std::unexpected(error(lexical_errc::invalid_numeric_literal, "invalid unsigned integer literal"));
  }
  return numeric_literal{std::format("{}{}", value, width == integer_width::bits64 ? "ULL" : "U")};
}

std::expected<numeric_literal, lexical_error> numeric_literal::floating(std::string_view value, bool is_float) {
  if (value == "nan") {
    return numeric_literal{std::format("std::numeric_limits<{}>::quiet_NaN()", is_float ? "float" : "double")};
  }
  if (value == "inf" || value == "-inf") {
    return numeric_literal{std::format("{}std::numeric_limits<{}>::infinity()", value.starts_with('-') ? "-" : "",
                                       is_float ? "float" : "double")};
  }
  const bool valid_spelling = is_float ? valid_float_spelling<float>(value) : valid_float_spelling<double>(value);
  if (!valid_spelling) {
    return std::unexpected(error(lexical_errc::invalid_numeric_literal, "invalid floating-point literal"));
  }
  const bool integral_spelling = !value.contains('.') && !value.contains('e') && !value.contains('E');
  if (integral_spelling) {
    return numeric_literal{std::format("{}.0{}", value, is_float ? "F" : "")};
  }
  if (!is_float) {
    return numeric_literal{std::format("static_cast<double>({})", value)};
  }
  return numeric_literal{std::format("{}F", value)};
}

std::expected<numeric_literal, lexical_error> numeric_literal::boolean(std::string_view value) {
  if (value != "true" && value != "false") {
    return std::unexpected(error(lexical_errc::invalid_numeric_literal, "invalid boolean literal"));
  }
  return numeric_literal{std::string{value}};
}

comment_text::comment_text(std::string_view text) {
  for (const char value : text) {
    const auto byte = as_unsigned(value);
    if (byte == '\r') {
      spelling_ += "\\r";
    } else if (byte == '\n') {
      spelling_ += "\\n";
    } else if (byte == '\\') {
      // A backslash immediately before the generated newline would splice the
      // next source line into this line comment during translation phase 2.
      spelling_ += "\\134";
    } else if (byte == '?') {
      // Keep legacy trigraph extensions from turning question-question-slash into a backslash.
      spelling_ += "\\077";
    } else if (byte < static_cast<unsigned char>(' ') || byte >= first_non_ascii) {
      const auto entry = make_escape_entry(byte);
      spelling_.append(entry.data.data(), entry.size);
    } else {
      spelling_.push_back(static_cast<char>(byte));
    }
  }
}

} // namespace hpp_proto::protoc::cpp
