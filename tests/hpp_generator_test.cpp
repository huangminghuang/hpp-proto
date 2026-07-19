#include "hpp_generator.hpp"

#include <algorithm>
#include <boost/ut.hpp>
#include <google/protobuf/descriptor.msg.hpp>
#include <hpp_proto/hpp_options.pb.hpp>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using hpp_proto::protoc::code_generator_request;
using hpp_proto::protoc::code_generator_response;
using hpp_proto::protoc::generator_options;
using hpp_proto::protoc::hpp_generator;
using file_descriptor = google::protobuf::FileDescriptorProto<>;
using message_descriptor = google::protobuf::DescriptorProto<>;
using field_descriptor = google::protobuf::FieldDescriptorProto<>;
using service_descriptor = google::protobuf::ServiceDescriptorProto<>;
using method_descriptor = google::protobuf::MethodDescriptorProto<>;

file_descriptor make_file(std::string_view name, std::string_view package = "generator_test") {
  file_descriptor result;
  result.name = name;
  result.package = package;
  result.syntax = "proto3";
  return result;
}

message_descriptor make_message(std::string_view name) {
  message_descriptor result;
  result.name = name;
  return result;
}

code_generator_request make_request(std::vector<file_descriptor> files, std::vector<std::string> files_to_generate) {
  code_generator_request result;
  result.proto_file = std::move(files);
  result.file_to_generate = std::move(files_to_generate);
  return result;
}

bool has_file(const code_generator_response &response, std::string_view name) {
  return std::ranges::any_of(response.file, [name](const auto &file) { return file.name == name; });
}

code_generator_request valid_request(std::string_view file_name = "valid.proto") {
  auto file = make_file(file_name);
  file.message_type.push_back(make_message("Valid"));
  return make_request({std::move(file)}, {std::string{file_name}});
}

code_generator_request generated_member_collision_request() {
  auto file = make_file("generated_member.proto");
  auto message = make_message("Example");
  field_descriptor field;
  field.name = "Traits";
  field.json_name = "Traits";
  field.number = 1;
  field.label = field_descriptor::Label::LABEL_OPTIONAL;
  field.type = field_descriptor::Type::TYPE_INT32;
  message.field.push_back(std::move(field));
  file.message_type.push_back(std::move(message));
  return make_request({std::move(file)}, {"generated_member.proto"});
}

code_generator_request rpc_method_collision_request() {
  auto file = make_file("rpc_method.proto");
  file.message_type.push_back(make_message("Request"));
  service_descriptor service;
  service.name = "ExampleService";
  method_descriptor method;
  method.name = "method_name";
  method.input_type = ".generator_test.Request";
  method.output_type = ".generator_test.Request";
  service.method.push_back(std::move(method));
  file.service.push_back(std::move(service));
  return make_request({std::move(file)}, {"rpc_method.proto"});
}

} // namespace

using namespace boost::ut;
using namespace std::string_view_literals;

const suite hpp_generator_tests = [] {
  "plugin_options_are_parsed_without_generator_state"_test = [] {
    auto parsed = hpp_proto::protoc::parse_plugin_options(
        "directory_prefix=generated,namespace_prefix=outer.inner,proto2_explicit_presence=.pkg.Message.field,"
        "preserve_proto_field_names,export_request=request.bin",
        "custom-protoc-gen-hpp");

    expect(parsed.has_value());
    expect(eq(parsed->generation.plugin_name.filename().string(), "custom-protoc-gen-hpp"sv));
    expect(eq(parsed->generation.directory_prefix, "generated"sv));
    expect(eq(parsed->generation.namespace_prefix->view(), "outer::inner"sv));
    expect(eq(parsed->generation.proto2_explicit_presences.size(), 1_u));
    expect(eq(parsed->generation.proto2_explicit_presences.front(), ".pkg.Message.field"sv));
    expect(parsed->generation.preserve_proto_field_names);
    expect(eq(parsed->export_request->string(), "request.bin"sv));

    auto defaults = hpp_proto::protoc::parse_plugin_options("");
    expect(defaults.has_value());
    expect(eq(defaults->generation.proto2_explicit_presences.size(), 1_u));
    expect(eq(defaults->generation.proto2_explicit_presences.front(), "."sv));
    expect(!hpp_proto::protoc::parse_plugin_options("namespace_prefix=outer..inner").has_value());
  };

  "generation_errors_are_response_errors_and_do_not_leak"_test = [] {
    const hpp_generator generator{generator_options{}};

    const auto collision = generator.generate(generated_member_collision_request());
    expect(collision.file.empty());
    expect(collision.error.contains("name 'Traits'"sv));
    expect(collision.error.contains("generated message member"sv));

    const auto valid = generator.generate(valid_request());
    expect(valid.error.empty());
    expect(has_file(valid, "valid.msg.hpp"sv));
    expect(has_file(valid, "valid.pb.hpp"sv));
    expect(has_file(valid, "valid.glz.hpp"sv));
    expect(has_file(valid, "valid.desc.hpp"sv));
  };

  "generator_options_are_isolated_between_instances"_test = [] {
    generator_options first_options;
    first_options.namespace_prefix = hpp_proto::protoc::cpp::qualified_name::from_dotted("first").value();
    generator_options second_options;
    second_options.namespace_prefix = hpp_proto::protoc::cpp::qualified_name::from_dotted("second").value();

    const auto first = hpp_generator{std::move(first_options)}.generate(valid_request("first.proto"));
    const auto second = hpp_generator{std::move(second_options)}.generate(valid_request("second.proto"));

    expect(first.error.empty());
    expect(second.error.empty());
    const auto &first_message = *std::ranges::find(first.file, "first.msg.hpp", &code_generator_response::File::name);
    const auto &second_message =
        *std::ranges::find(second.file, "second.msg.hpp", &code_generator_response::File::name);
    expect(first_message.content.contains("namespace first::generator_test"sv));
    expect(!first_message.content.contains("namespace second::generator_test"sv));
    expect(second_message.content.contains("namespace second::generator_test"sv));
    expect(!second_message.content.contains("namespace first::generator_test"sv));
  };

  "rpc_metadata_collisions_are_diagnosed_from_a_request"_test = [] {
    const hpp_generator generator{generator_options{}};
    const auto response = generator.generate(rpc_method_collision_request());
    expect(response.file.empty());
    expect(response.error.contains("RPC method 'method_name'"sv));
    expect(response.error.contains("method metadata API"sv));
  };

  "file_descriptor_collisions_are_diagnosed_from_a_request"_test = [] {
    auto dash = make_file("collision/file-name.proto", "");
    dash.message_type.push_back(make_message("DashFileMessage"));
    auto underscore = make_file("collision/file_name.proto", "");
    underscore.message_type.push_back(make_message("UnderscoreFileMessage"));

    const hpp_generator generator{generator_options{}};
    const auto response = generator.generate(make_request({std::move(dash), std::move(underscore)},
                                                          {"collision/file-name.proto", "collision/file_name.proto"}));
    expect(response.file.empty());
    expect(response.error.contains("generated C++ file descriptor declarations collide"sv));
    expect(response.error.contains("file_descriptor_name"sv));
  };

  "file_descriptor_name_overrides_are_generated_from_a_request"_test = [] {
    auto dash = make_file("cpp_lexical_file-name.proto", "lexical.file_dash");
    dash.message_type.push_back(make_message("DashName"));
    dash.options.emplace();
    hpp_proto::hpp_file_opts<> file_options;
    file_options.value.file_descriptor_name = "cpp_lexical_file_dash_proto";
    expect(dash.options->set_extension(file_options).ok());

    auto underscore = make_file("cpp_lexical_file_name.proto", "lexical.file_underscore");
    underscore.message_type.push_back(make_message("UnderscoreName"));

    const hpp_generator generator{generator_options{}};
    const auto response = generator.generate(make_request(
        {std::move(dash), std::move(underscore)}, {"cpp_lexical_file-name.proto", "cpp_lexical_file_name.proto"}));
    expect(response.error.empty());

    const auto dash_descriptor =
        std::ranges::find(response.file, "cpp_lexical_file-name.desc.hpp", &code_generator_response::File::name);
    const auto underscore_descriptor =
        std::ranges::find(response.file, "cpp_lexical_file_name.desc.hpp", &code_generator_response::File::name);
    expect(dash_descriptor != response.file.end());
    expect(underscore_descriptor != response.file.end());
    if (dash_descriptor != response.file.end()) {
      expect(dash_descriptor->content.contains(
          "hpp_proto::file_descriptors::cpp_lexical_file_dash_proto::file_descriptor_"sv));
    }
    if (underscore_descriptor != response.file.end()) {
      expect(underscore_descriptor->content.contains(
          "hpp_proto::file_descriptors::cpp_lexical_file_name_proto::file_descriptor_"sv));
    }
  };

  "path_and_flat_file_descriptor_names_are_distinct_from_a_request"_test = [] {
    auto nested = make_file("cpplexical/foo/bar.proto", "lexical.file_path");
    nested.message_type.push_back(make_message("PathName"));
    auto flat = make_file("cpplexical_foo_bar.proto", "lexical.file_flat");
    flat.message_type.push_back(make_message("FlatName"));

    const hpp_generator generator{generator_options{}};
    const auto response = generator.generate(
        make_request({std::move(nested), std::move(flat)}, {"cpplexical/foo/bar.proto", "cpplexical_foo_bar.proto"}));
    expect(response.error.empty());

    const auto nested_descriptor =
        std::ranges::find(response.file, "cpplexical/foo/bar.desc.hpp", &code_generator_response::File::name);
    const auto flat_descriptor =
        std::ranges::find(response.file, "cpplexical_foo_bar.desc.hpp", &code_generator_response::File::name);
    expect(nested_descriptor != response.file.end());
    expect(flat_descriptor != response.file.end());
    if (nested_descriptor != response.file.end()) {
      expect(nested_descriptor->content.contains(
          "hpp_proto::file_descriptors::cpplexical::foo::bar_proto::file_descriptor_"sv));
    }
    if (flat_descriptor != response.file.end()) {
      expect(flat_descriptor->content.contains(
          "hpp_proto::file_descriptors::cpplexical_foo_bar_proto::file_descriptor_"sv));
    }
  };

  "well_known_message_names_select_the_expected_generator_codec"_test = [] {
    auto file = make_file("well_known_collision.proto", "google.protobuf");
    file.syntax = "proto2";
    auto duration = make_message("Duration");
    field_descriptor ordinary_field;
    ordinary_field.name = "ordinary_field";
    ordinary_field.json_name = "ordinaryField";
    ordinary_field.number = 1;
    ordinary_field.label = field_descriptor::Label::LABEL_OPTIONAL;
    ordinary_field.type = field_descriptor::Type::TYPE_BOOL;
    duration.field.push_back(std::move(ordinary_field));
    file.message_type.push_back(std::move(duration));

    const hpp_generator generator{generator_options{}};
    const auto response = generator.generate(make_request({std::move(file)}, {"well_known_collision.proto"}));
    expect(response.error.empty());

    const auto message_header =
        std::ranges::find(response.file, "well_known_collision.msg.hpp", &code_generator_response::File::name);
    const auto glaze_header =
        std::ranges::find(response.file, "well_known_collision.glz.hpp", &code_generator_response::File::name);
    expect(message_header != response.file.end());
    expect(glaze_header != response.file.end());
    if (message_header != response.file.end()) {
      expect(message_header->content.contains("constexpr static bool glaze_reflect = false;"sv));
      expect(message_header->content.contains("::hpp_proto::optional<bool> ordinary_field;"sv));
    }
    if (glaze_header != response.file.end()) {
      expect(glaze_header->content.contains("using type = ::hpp_proto::duration_codec;"sv));
    }
  };

  "service_headers_are_emitted_only_for_files_with_services"_test = [] {
    auto without_service = make_file("without_service.proto");
    without_service.message_type.push_back(make_message("PlainMessage"));

    auto with_service = make_file("with_service.proto");
    with_service.message_type.push_back(make_message("Request"));
    service_descriptor service;
    service.name = "ExampleService";
    method_descriptor method;
    method.name = "Call";
    method.input_type = ".generator_test.Request";
    method.output_type = ".generator_test.Request";
    service.method.push_back(std::move(method));
    with_service.service.push_back(std::move(service));

    auto empty_package_service = make_file("empty_package_service.proto", "");
    empty_package_service.message_type.push_back(make_message("EmptyPackageRequest"));
    service_descriptor empty_service;
    empty_service.name = "EmptyPackageService";
    method_descriptor empty_method;
    empty_method.name = "Call";
    empty_method.input_type = ".EmptyPackageRequest";
    empty_method.output_type = ".EmptyPackageRequest";
    empty_service.method.push_back(std::move(empty_method));
    empty_package_service.service.push_back(std::move(empty_service));

    const hpp_generator generator{generator_options{}};
    const auto response = generator.generate(
        make_request({std::move(without_service), std::move(with_service), std::move(empty_package_service)},
                     {"without_service.proto", "with_service.proto", "empty_package_service.proto"}));
    expect(response.error.empty());
    expect(!has_file(response, "without_service.service.hpp"sv));
    expect(has_file(response, "with_service.service.hpp"sv));
    const auto empty_service_header =
        std::ranges::find(response.file, "empty_package_service.service.hpp", &code_generator_response::File::name);
    expect(empty_service_header != response.file.end());
    if (empty_service_header != response.file.end()) {
      expect(empty_service_header->content.contains("namespace EmptyPackageService {"sv));
      expect(empty_service_header->content.contains("/EmptyPackageService/Call"sv));
      expect(empty_service_header->content.contains("using request_t = EmptyPackageRequest<Traits>;"sv));
    }
  };
};

// NOLINTNEXTLINE(bugprone-exception-escape)
int main() { return static_cast<int>(boost::ut::cfg<>.run({.report_errors = true})); }
