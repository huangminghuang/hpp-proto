#include "cpp_lexical_emitter.hpp"

#include <array>
#include <boost/ut.hpp>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>

namespace cpp = hpp_proto::protoc::cpp;
using namespace boost::ut;
using namespace std::string_view_literals;

static_assert(cpp::source_argument<cpp::identifier>);
static_assert(cpp::source_argument<cpp::qualified_name>);
static_assert(cpp::source_argument<cpp::string_literal_bytes>);
static_assert(cpp::source_argument<cpp::include_path>);
static_assert(cpp::source_argument<cpp::numeric_literal>);
static_assert(cpp::source_argument<cpp::source_fragment>);
static_assert(!cpp::source_argument<std::string>);
static_assert(!cpp::source_argument<std::string_view>);
static_assert(!cpp::source_argument<const char *>);
static_assert(!cpp::source_argument<char>);
static_assert(!cpp::source_argument<signed char>);
static_assert(!cpp::source_argument<unsigned char>);
static_assert(!cpp::source_argument<float>);
static_assert(!cpp::source_argument<double>);

namespace {

constexpr auto byte_value_count = static_cast<std::size_t>(std::numeric_limits<unsigned char>::max()) + 1U;
constexpr auto first_non_ascii = static_cast<unsigned char>(0x7f);
constexpr unsigned int octal_radix = 8;
constexpr unsigned int octal_high_place = octal_radix * octal_radix;

constexpr auto cpp_keywords = std::to_array<std::string_view>({
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
});

std::string expected_byte_literal(unsigned char byte) {
  switch (byte) {
  case '\a':
    return R"("\a")";
  case '\b':
    return R"("\b")";
  case '\t':
    return R"("\t")";
  case '\n':
    return R"("\n")";
  case '\v':
    return R"("\v")";
  case '\f':
    return R"("\f")";
  case '\r':
    return R"("\r")";
  case '"':
    return R"("\"")";
  case '\'':
    return R"("\'")";
  case '\\':
    return R"("\\")";
  case '?':
    return R"("\?")";
  default:
    break;
  }

  if (byte >= static_cast<unsigned char>(' ') && byte < first_non_ascii) {
    return std::string{'"'} + static_cast<char>(byte) + '"';
  }

  constexpr auto octal_digits = std::to_array<char>({'0', '1', '2', '3', '4', '5', '6', '7'});
  return {'"',
          '\\',
          octal_digits.at(byte / octal_high_place),
          octal_digits.at((byte / octal_radix) % octal_radix),
          octal_digits.at(byte % octal_radix),
          '"'};
}

} // namespace

const suite cpp_lexical_emitter_tests = [] {
  "string_literal_escapes_every_byte_unambiguously"_test = [] {
    for (std::size_t value = 0; value < byte_value_count; ++value) {
      const auto byte = static_cast<unsigned char>(value);
      const std::array input = {static_cast<char>(byte)};
      expect(eq(cpp::string_literal_bytes{std::string_view{input}}.str(), expected_byte_literal(byte)))
          << "byte " << value;
    }

    constexpr std::array control_followed_by_digit = {'\x01', '2'};
    expect(eq(cpp::string_literal_bytes{std::string_view{control_followed_by_digit}}.str(), R"("\0012")"sv));
    constexpr std::array non_ascii_followed_by_digit = {'\xc3', '\xa9', '7'};
    expect(eq(cpp::string_literal_bytes{std::string_view{non_ascii_followed_by_digit}}.str(), R"("\303\2517")"sv));
  };

  "identifiers_and_qualified_names_own_keyword_mapping"_test = [] {
    expect(eq(cpp::identifier::from_proto("field")->view(), "field"sv));
    expect(eq(cpp::identifier::from_proto("namespace")->view(), "namespace_"sv));
    expect(
        eq(cpp::identifier::from_proto("switch")->append_word(cpp::identifier::from_proto("oneof_case").value()).view(),
           "switch_oneof_case"sv));
    expect(eq(
        cpp::identifier::from_proto("class")->disambiguated_with(cpp::identifier::from_proto("nested").value()).view(),
        "class_nested"sv));
    expect(eq(cpp::identifier::from_proto("Message")
                  ->disambiguated_with(cpp::identifier::from_proto("nested").value())
                  .view(),
              "Message_"sv));
    expect(eq(cpp::identifier::from_proto("pb_Type")->view(), "pb_Type"sv));
    expect(eq(cpp::identifier::from_proto("foo_pb_bar")->view(), "foo_pb_bar"sv));
    expect(eq(cpp::identifier::from_proto("class_nested")->view(), "class_nested"sv));
    expect(eq(cpp::identifier::from_proto("switch_oneof_case")->view(), "switch_oneof_case"sv));
    expect(eq(cpp::identifier::from_proto("switch_oneof_numbers")->view(), "switch_oneof_numbers"sv));
    expect(!cpp::identifier::from_proto("bad-name").has_value());
    expect(!cpp::identifier::from_proto("9field").has_value());

    const auto prefix = cpp::qualified_name::from_dotted("outer.namespace").value();
    expect(eq(prefix.view(), "outer::namespace_"sv));
    expect(eq(cpp::qualified_name::from_proto(prefix, ".pkg.class")->view(), "outer::namespace_::pkg::class_"sv));
    expect(eq(cpp::qualified_name::from_proto(prefix, "relative.Type")->view(), "relative::Type"sv));
    expect(!cpp::qualified_name::from_dotted("outer..inner").has_value());

    for (const auto keyword : cpp_keywords) {
      const auto identifier = cpp::identifier::from_proto(keyword);
      expect(identifier.has_value());
      expect(identifier->view().ends_with('_')) << keyword;
    }
  };

  "include_paths_are_header_names_not_string_literals"_test = [] {
    expect(eq(cpp::include_path::from_proto_file("foo/bar.proto", "generated", ".pb.hpp")->view(),
              R"("generated/foo/bar.pb.hpp")"sv));
    expect(eq(cpp::include_path::from_proto_file("foo\\bar.proto", "generated\\dir", ".pb.hpp")->view(),
              R"("generated/dir/foo/bar.pb.hpp")"sv));
    expect(!cpp::include_path::from_proto_file("foo\nbar.proto", "", ".pb.hpp").has_value());
    expect(!cpp::include_path::from_proto_file("foo\"bar.proto", "", ".pb.hpp").has_value());
  };

  "file_descriptor_names_use_a_fixed_root_and_path_namespaces"_test = [] {
    const auto nested = cpp::file_descriptor_name::from_proto_file("foo/bar.proto").value();
    expect(eq(nested.namespace_name().view(), "hpp_proto::file_descriptors::foo::bar_proto"sv));
    expect(eq(nested.qualified_descriptor_name().view(),
              "hpp_proto::file_descriptors::foo::bar_proto::file_descriptor_"sv));
    expect(eq(nested.qualified_descriptor_set_name().view(),
              "hpp_proto::file_descriptors::foo::bar_proto::file_descriptor_set"sv));

    const auto flat = cpp::file_descriptor_name::from_proto_file("foo_bar.proto").value();
    expect(eq(flat.namespace_name().view(), "hpp_proto::file_descriptors::foo_bar_proto"sv));
    expect(nested.qualified_descriptor_name() != flat.qualified_descriptor_name());

    const auto dash = cpp::file_descriptor_name::from_proto_file("file-name.proto").value();
    const auto underscore = cpp::file_descriptor_name::from_proto_file("file_name.proto").value();
    expect(dash.qualified_descriptor_name() == underscore.qualified_descriptor_name());

    const auto overridden = cpp::file_descriptor_name::from_proto_file("file-name.proto", "file_dash_proto").value();
    expect(eq(overridden.namespace_name().view(), "hpp_proto::file_descriptors::file_dash_proto"sv));
    expect(overridden.qualified_descriptor_name() != underscore.qualified_descriptor_name());

    const auto keyword = cpp::file_descriptor_name::from_proto_file("class/value.proto").value();
    expect(eq(keyword.namespace_name().view(), "hpp_proto::file_descriptors::class_::value_proto"sv));

    expect(!cpp::file_descriptor_name::from_proto_file("not-a-proto.txt").has_value());
    expect(!cpp::file_descriptor_name::from_proto_file("foo/bar.proto", "bad-name").has_value());
  };

  "numeric_literals_preserve_cpp_type_rules"_test = [] {
    using enum cpp::integer_width;
    expect(eq(cpp::numeric_literal::signed_integer("-2147483648", bits32)->view(), "-2147483647-1"sv));
    expect(
        eq(cpp::numeric_literal::signed_integer("-9223372036854775808", bits64)->view(), "-9223372036854775807LL-1"sv));
    expect(eq(cpp::numeric_literal::unsigned_integer("4294967295", bits32)->view(), "4294967295U"sv));
    expect(eq(cpp::numeric_literal::unsigned_integer("18446744073709551615", bits64)->view(),
              "18446744073709551615ULL"sv));
    expect(eq(cpp::numeric_literal::unsigned_integer("0xFFFFFFFF", bits32)->view(), "0xFFFFFFFFU"sv));
    expect(eq(cpp::numeric_literal::unsigned_integer("0xFFFFFFFFFFFFFFFF", bits64)->view(), "0xFFFFFFFFFFFFFFFFULL"sv));
    expect(eq(cpp::numeric_literal::signed_integer("-0x80000000", bits32)->view(), "-2147483647-1"sv));
    expect(
        eq(cpp::numeric_literal::signed_integer("-0x8000000000000000", bits64)->view(), "-9223372036854775807LL-1"sv));
    expect(eq(cpp::numeric_literal::floating("1", true)->view(), "1.0F"sv));
    expect(eq(cpp::numeric_literal::floating("-0", true)->view(), "-0.0F"sv));
    expect(eq(cpp::numeric_literal::floating("-0", false)->view(), "-0.0"sv));
    expect(eq(cpp::numeric_literal::floating("1e-9", true)->view(), "1e-9F"sv));
    expect(eq(cpp::numeric_literal::floating("nan", false)->view(), "std::numeric_limits<double>::quiet_NaN()"sv));
    expect(eq(cpp::numeric_literal::floating("-inf", true)->view(), "-std::numeric_limits<float>::infinity()"sv));
    expect(eq(cpp::numeric_literal::boolean("true")->view(), "true"sv));
    expect(!cpp::numeric_literal::signed_integer("1; bad()", bits32).has_value());
    expect(!cpp::numeric_literal::signed_integer("-0x", bits32).has_value());
    expect(!cpp::numeric_literal::signed_integer("+0X", bits32).has_value());
    expect(!cpp::numeric_literal::unsigned_integer("0x", bits32).has_value());
    expect(!cpp::numeric_literal::unsigned_integer("0X", bits64).has_value());
    expect(!cpp::numeric_literal::floating("nan(payload)", false).has_value());
    expect(!cpp::numeric_literal::floating("1e300", true).has_value());
    expect(!cpp::numeric_literal::floating("1e-50", true).has_value());
    expect(cpp::numeric_literal::floating("1e300", false).has_value());
  };

  "comment_text_cannot_end_the_generated_comment"_test = [] {
    expect(eq(cpp::comment_text{"line one\n#include <bad>\r\\"}.view(), R"(line one\n#include <bad>\r\134)"sv));
    constexpr std::array trigraph_like = {'?', '?', '/'};
    expect(eq(cpp::comment_text{std::string_view{trigraph_like}}.view(), R"(\077\077/)"sv));
    expect(!cpp::comment_text{"trailing\\"}.view().ends_with('\\'));
    for (std::size_t value = 0; value < byte_value_count; ++value) {
      const std::array input = {static_cast<char>(static_cast<unsigned char>(value))};
      const auto rendered = cpp::comment_text{std::string_view{input}};
      expect(!rendered.view().contains('\r')) << "byte " << value;
      expect(!rendered.view().contains('\n')) << "byte " << value;
      expect(!rendered.view().ends_with('\\')) << "byte " << value;
      for (const char output : rendered.view()) {
        const auto byte = static_cast<unsigned char>(output);
        expect(byte >= static_cast<unsigned char>(' ') && byte < first_non_ascii) << "byte " << value;
      }
    }
  };

  "typed_emitter_formats_only_source_arguments"_test = [] {
    std::string output;
    const auto name = cpp::identifier::from_proto("class").value();
    const cpp::string_literal_bytes literal{"value\n"};
    cpp::emit_to(std::back_inserter(output), "struct {} {{ static constexpr auto value = {}; }};", name, literal);
    expect(eq(output, R"(struct class_ { static constexpr auto value = "value\n"; };)"sv));
  };
};

// NOLINTNEXTLINE(bugprone-exception-escape)
int main() { return static_cast<int>(boost::ut::cfg<>.run({.report_errors = true})); }
