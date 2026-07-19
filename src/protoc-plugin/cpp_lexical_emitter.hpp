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

#pragma once

#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace hpp_proto::protoc::cpp {

enum class lexical_errc : std::uint8_t {
  invalid_identifier,
  invalid_qualified_name,
  invalid_include_path,
  invalid_file_descriptor_name,
  invalid_numeric_literal,
};

enum class integer_width : std::uint8_t {
  bits32 = 32,
  bits64 = 64,
};

struct lexical_error {
  lexical_errc code;
  std::string message;
};

class identifier {
public:
  [[nodiscard]] static std::expected<identifier, lexical_error> from_proto(std::string_view name);
  // Matches google::protobuf::compiler::cpp::ResolveKeyword for namespace
  // components: only exact C++ keywords receive a trailing underscore.
  [[nodiscard]] static std::expected<identifier, lexical_error> from_protobuf_namespace(std::string_view name);

  // Join generator-owned identifier words with exactly one underscore.
  [[nodiscard]] identifier append_word(const identifier &word) const;

  // Preserve the generator's trailing-underscore disambiguator where it is
  // readable. Conflicts with the resulting public name are diagnosed.
  [[nodiscard]] identifier disambiguated_with(const identifier &word) const;

  [[nodiscard]] std::string_view view() const noexcept { return spelling_; }
  [[nodiscard]] const std::string &str() const noexcept { return spelling_; }

  auto operator<=>(const identifier &) const = default;

private:
  explicit identifier(std::string spelling) : spelling_(std::move(spelling)) {}

  std::string spelling_;
};

class qualified_name {
public:
  qualified_name() = default;

  [[nodiscard]] static std::expected<qualified_name, lexical_error> from_dotted(std::string_view name);
  [[nodiscard]] static std::expected<qualified_name, lexical_error> from_proto(const qualified_name &namespace_prefix,
                                                                               std::string_view name);
  [[nodiscard]] qualified_name append(const identifier &segment) const;
  [[nodiscard]] qualified_name append(const qualified_name &suffix) const;

  [[nodiscard]] std::string_view view() const noexcept { return spelling_; }
  [[nodiscard]] const std::string &str() const noexcept { return spelling_; }
  [[nodiscard]] bool empty() const noexcept { return spelling_.empty(); }

  auto operator<=>(const qualified_name &) const = default;

private:
  explicit qualified_name(std::string spelling) : spelling_(std::move(spelling)) {}

  std::string spelling_;
};

class file_descriptor_name {
public:
  [[nodiscard]] static std::expected<file_descriptor_name, lexical_error>
  from_proto_file(std::string_view proto_file, std::optional<std::string_view> final_component_override = std::nullopt);

  [[nodiscard]] const qualified_name &namespace_name() const noexcept { return namespace_name_; }
  [[nodiscard]] const identifier &descriptor_identifier() const noexcept { return descriptor_identifier_; }
  [[nodiscard]] const identifier &descriptor_set_identifier() const noexcept { return descriptor_set_identifier_; }
  [[nodiscard]] qualified_name qualified_descriptor_name() const;
  [[nodiscard]] qualified_name qualified_descriptor_set_name() const;

private:
  file_descriptor_name(qualified_name namespace_name, identifier descriptor_identifier,
                       identifier descriptor_set_identifier)
      : namespace_name_(std::move(namespace_name)), descriptor_identifier_(std::move(descriptor_identifier)),
        descriptor_set_identifier_(std::move(descriptor_set_identifier)) {}

  qualified_name namespace_name_;
  identifier descriptor_identifier_;
  identifier descriptor_set_identifier_;
};

class string_literal_bytes {
public:
  explicit string_literal_bytes(std::string_view bytes);

  [[nodiscard]] std::string_view view() const noexcept { return spelling_; }
  [[nodiscard]] const std::string &str() const noexcept { return spelling_; }

private:
  std::string spelling_;
};

class include_path {
public:
  [[nodiscard]] static std::expected<include_path, lexical_error>
  from_proto_file(std::string_view proto_file, std::string_view directory_prefix, std::string_view generated_suffix);

  [[nodiscard]] std::string_view view() const noexcept { return spelling_; }
  [[nodiscard]] const std::string &str() const noexcept { return spelling_; }

private:
  explicit include_path(std::string spelling) : spelling_(std::move(spelling)) {}

  std::string spelling_;
};

class numeric_literal {
public:
  [[nodiscard]] static std::expected<numeric_literal, lexical_error> signed_integer(std::string_view value,
                                                                                    integer_width width);
  [[nodiscard]] static std::expected<numeric_literal, lexical_error> unsigned_integer(std::string_view value,
                                                                                      integer_width width);
  [[nodiscard]] static std::expected<numeric_literal, lexical_error> floating(std::string_view value, bool is_float);
  [[nodiscard]] static std::expected<numeric_literal, lexical_error> boolean(std::string_view value);

  [[nodiscard]] std::string_view view() const noexcept { return spelling_; }
  [[nodiscard]] const std::string &str() const noexcept { return spelling_; }

private:
  explicit numeric_literal(std::string spelling) : spelling_(std::move(spelling)) {}

  std::string spelling_;
};

class comment_text {
public:
  explicit comment_text(std::string_view text);

  [[nodiscard]] std::string_view view() const noexcept { return spelling_; }

private:
  std::string spelling_;
};

namespace detail {
struct source_fragment_access;
}

class source_fragment {
public:
  source_fragment() = default;

  template <std::size_t Size>
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
  explicit source_fragment(const char (&source)[Size]) : source_(source, Size - 1U) {}

  [[nodiscard]] static source_fragment spaces(std::size_t count) { return source_fragment{std::string(count, ' ')}; }

  [[nodiscard]] std::string_view view() const noexcept { return source_; }
  [[nodiscard]] bool empty() const noexcept { return source_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return source_.size(); }
  [[nodiscard]] bool contains(std::string_view value) const noexcept { return source_.contains(value); }
  [[nodiscard]] bool starts_with(std::string_view value) const noexcept { return source_.starts_with(value); }
  [[nodiscard]] bool ends_with(std::string_view value) const noexcept { return source_.ends_with(value); }
  [[nodiscard]] source_fragment substr(std::size_t offset, std::size_t count = std::string_view::npos) const {
    return source_fragment{std::string{std::string_view{source_}.substr(offset, count)}};
  }

  source_fragment &append(const source_fragment &suffix) {
    source_ += suffix.source_;
    return *this;
  }

private:
  explicit source_fragment(std::string source) : source_(std::move(source)) {}

  friend struct detail::source_fragment_access;

  std::string source_;
};

template <typename T>
concept lexical_value =
    std::same_as<std::remove_cvref_t<T>, identifier> || std::same_as<std::remove_cvref_t<T>, qualified_name> ||
    std::same_as<std::remove_cvref_t<T>, string_literal_bytes> || std::same_as<std::remove_cvref_t<T>, include_path> ||
    std::same_as<std::remove_cvref_t<T>, numeric_literal> || std::same_as<std::remove_cvref_t<T>, comment_text> ||
    std::same_as<std::remove_cvref_t<T>, source_fragment>;

template <lexical_value T>
[[nodiscard]] std::string_view render_argument(const T &value) noexcept {
  return value.view();
}

template <typename T>
concept source_integer =
    std::integral<std::remove_cvref_t<T>> && !std::same_as<std::remove_cvref_t<T>, char> &&
    !std::same_as<std::remove_cvref_t<T>, signed char> && !std::same_as<std::remove_cvref_t<T>, unsigned char> &&
    !std::same_as<std::remove_cvref_t<T>, wchar_t> && !std::same_as<std::remove_cvref_t<T>, char8_t> &&
    !std::same_as<std::remove_cvref_t<T>, char16_t> && !std::same_as<std::remove_cvref_t<T>, char32_t>;

template <source_integer T>
[[nodiscard]] T render_argument(const T &value) noexcept {
  return value;
}

template <typename T>
concept source_argument = lexical_value<T> || source_integer<T>;

template <typename T>
using rendered_argument_t = decltype(render_argument(std::declval<T>()));

namespace detail {
struct source_fragment_access {
  template <source_argument... Args>
  [[nodiscard]] static source_fragment format(std::format_string<rendered_argument_t<Args>...> source_template,
                                              Args &&...args) {
    return source_fragment{std::format(source_template, render_argument(std::forward<Args>(args))...)};
  }
};
} // namespace detail

template <typename Output, source_argument... Args>
auto emit_to(Output output, std::format_string<rendered_argument_t<Args>...> source_template, Args &&...args) {
  return std::format_to(output, source_template, render_argument(std::forward<Args>(args))...);
}

template <source_argument... Args>
[[nodiscard]] source_fragment format(std::format_string<rendered_argument_t<Args>...> source_template, Args &&...args) {
  return detail::source_fragment_access::format(source_template, std::forward<Args>(args)...);
}

} // namespace hpp_proto::protoc::cpp
