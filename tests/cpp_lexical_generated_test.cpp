#include "cpp_lexical_generated_test.desc.hpp"
#include "cpp_lexical_generated_test.glz.hpp"
#include "cpp_lexical_generated_test.msg.hpp"
#include "cpp_lexical_generated_test.service.hpp"

#include <boost/ut.hpp>
#include <cmath>
#include <concepts>
#include <string_view>
#include <type_traits>
#include <utility>

using namespace boost::ut;
using namespace std::string_view_literals;

using keyword_message = lexical::namespace_::class_<>;
using nested_keyword_message = lexical::namespace_::class_nested::struct_<>;
using keyword_enum = lexical::namespace_::concept_;
using float_defaults_message = lexical::namespace_::FloatDefaults<>;
using extension_names_message = lexical::namespace_::ExtensionNames<>;
using extension_container_message = lexical::namespace_::ExtensionContainer<>;
using nested_type_fields_message = lexical::namespace_::NestedTypeFields<>;
using multi_level_nested_enum_message = lexical::namespace_::MultiLevelNestedEnumField<>;
using cross_file_message = lexical::namespace_::CrossFileMessage<>;

static_assert(requires(keyword_message value) {
  value.delete_;
  value.switch_;
});
static_assert(keyword_enum::requires_ == keyword_enum{0});
static_assert(requires(nested_keyword_message value) { value.operator_; });
static_assert(std::same_as<std::remove_cvref_t<decltype(std::declval<cross_file_message>().value.value())>,
                           lexical::cross_file::CrossFileEnum>);
static_assert(
    std::same_as<std::remove_cvref_t<decltype(std::declval<nested_type_fields_message>().nested_message.value())>,
                 nested_type_fields_message::NestedMessage>);
static_assert(
    std::same_as<std::remove_cvref_t<decltype(std::declval<nested_type_fields_message>().nested_enum.value())>,
                 nested_type_fields_message::NestedEnum>);
static_assert(std::same_as<std::remove_cvref_t<decltype(std::declval<multi_level_nested_enum_message>().kind.value())>,
                           multi_level_nested_enum_message::Child::Kind>);
static_assert(std::is_class_v<extension_container_message::user_extension>);
using renamed_types_rpc = lexical::namespace_::namespace_::renamed_types;
static_assert(
    std::same_as<renamed_types_rpc::request_t<::hpp_proto::default_traits>, lexical::namespace_::OrdinaryRequest<>>);
static_assert(
    std::same_as<renamed_types_rpc::response_t<::hpp_proto::default_traits>, lexical::namespace_::Message<>::Nested>);
static_assert(requires(extension_names_message value) { value.ordinary_field; });
static_assert(std::string_view{glz::get<0>(glz::meta<keyword_enum>::value.value)} == "requires"sv);
static_assert(std::string_view{lexical::namespace_::namespace_::delete_::method_name} ==
              "/lexical.namespace.namespace/delete"sv);

const suite cpp_lexical_generated_tests = [] {
  "keyword_names_remain_usable"_test = [] {
    keyword_message value;
    value.delete_ = "safe";
    expect(eq(value.delete_.value(), "safe"sv));
  };

  "protoc_canonical_float_defaults_remain_usable"_test = [] {
    float_defaults_message value;
    expect(std::isinf(value.high.value()));
    expect(eq(value.low.value(), 0.0F));
    expect(std::signbit(value.negative_zero.value()));
  };
};

// NOLINTNEXTLINE(bugprone-exception-escape)
int main() { return static_cast<int>(boost::ut::cfg<>.run({.report_errors = true})); }
