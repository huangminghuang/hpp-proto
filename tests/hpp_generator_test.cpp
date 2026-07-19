#include "hpp_generator.hpp"

#include <algorithm>
#include <array>
#include <boost/ut.hpp>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <google/protobuf/descriptor.msg.hpp>
#include <hpp_proto/hpp_options.pb.hpp>
#include <iterator>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

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
using enum_descriptor = google::protobuf::EnumDescriptorProto<>;
using enum_value_descriptor = google::protobuf::EnumValueDescriptorProto<>;

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

#ifdef HPP_PROTOC_GEN_HPP_PATH
struct scoped_test_directory {
  explicit scoped_test_directory(std::filesystem::path path) : path(std::move(path)) {
    std::error_code error;
    std::filesystem::remove_all(this->path, error);
    std::filesystem::create_directories(this->path);
  }

  ~scoped_test_directory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }

  scoped_test_directory(const scoped_test_directory &) = delete;
  scoped_test_directory &operator=(const scoped_test_directory &) = delete;
  scoped_test_directory(scoped_test_directory &&) = delete;
  scoped_test_directory &operator=(scoped_test_directory &&) = delete;

  std::filesystem::path path;
};

bool write_request_file(const std::filesystem::path &path, const code_generator_request &request) {
  std::vector<char> data;
  if (!hpp_proto::write_binpb(request, data).ok()) {
    return false;
  }
  std::ofstream output{path, std::ios::binary};
  output.write(data.data(), static_cast<std::streamsize>(data.size()));
  return output.good();
}

std::optional<code_generator_response> read_response_file(const std::filesystem::path &path) {
  std::ifstream input{path, std::ios::binary};
  const std::vector<char> data{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
  code_generator_response response;
  if (!hpp_proto::read_binpb(response, data).ok()) {
    return std::nullopt;
  }
  return response;
}

enum class plugin_invocation : std::uint8_t { file, standard_input, version };

int invoke_plugin(const std::filesystem::path &request, const std::filesystem::path &response,
                  plugin_invocation invocation) {
  const auto child = ::fork();
  if (child < 0) {
    return -1;
  }
  if (child == 0) {
    constexpr int child_launch_error = 127;
    using file_handle = std::unique_ptr<std::FILE, decltype(&std::fclose)>;
    file_handle output{std::fopen(response.c_str(), "wb"), &std::fclose};
    if (output == nullptr || ::dup2(::fileno(output.get()), STDOUT_FILENO) < 0) {
      ::_exit(child_launch_error);
    }
    output.reset();

    if (invocation == plugin_invocation::standard_input) {
      file_handle input{std::fopen(request.c_str(), "rb"), &std::fclose};
      if (input == nullptr || ::dup2(::fileno(input.get()), STDIN_FILENO) < 0) {
        ::_exit(child_launch_error);
      }
      input.reset();
    }

    const std::filesystem::path plugin{HPP_PROTOC_GEN_HPP_PATH};
    auto plugin_argument = plugin.string();
    auto request_argument = request.string();
    std::string version_argument{"--version"};
    std::array arguments = {plugin_argument.data(), static_cast<char *>(nullptr), static_cast<char *>(nullptr)};
    if (invocation == plugin_invocation::version) {
      arguments[1] = version_argument.data();
    } else if (invocation == plugin_invocation::file) {
      arguments[1] = request_argument.data();
    }
    // The executable is fixed at build time and execv does not invoke a shell.
    ::execv(plugin.c_str(), arguments.data()); // flawfinder: ignore
    ::_exit(child_launch_error);
  }

  int status = 0;
  if (::waitpid(child, &status, 0) != child || !WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
}
#endif

} // namespace

using namespace boost::ut;
using namespace std::string_view_literals;

// NOLINTNEXTLINE(cppcoreguidelines-interfaces-global-init)
const suite hpp_generator_tests = [] {
#ifdef HPP_PROTOC_GEN_HPP_PATH
  "plugin_adapter_round_trips_binary_requests_from_file_and_stdin"_test = [] {
    const scoped_test_directory directory{std::filesystem::current_path() / "hpp_generator_cli_test_artifacts"};

    auto request = valid_request("cli_file.proto");
    const auto request_path = directory.path / "request.bin";
    const auto response_path = directory.path / "response.bin";
    const auto exported_path = directory.path / "exported.bin";
    request.parameter = "export_request=" + exported_path.string();
    expect(write_request_file(request_path, request));
    expect(eq(invoke_plugin(request_path, response_path, plugin_invocation::file), 0));

    const auto response = read_response_file(response_path);
    expect(response.has_value());
    if (response.has_value()) {
      expect(response->error.empty());
      expect(has_file(*response, "cli_file.msg.hpp"sv));
      expect(has_file(*response, "cli_file.pb.hpp"sv));
      expect(has_file(*response, "cli_file.glz.hpp"sv));
      expect(has_file(*response, "cli_file.desc.hpp"sv));
    }
    expect(std::filesystem::exists(exported_path));
    expect(eq(std::filesystem::file_size(exported_path), std::filesystem::file_size(request_path)));

    auto invalid_options = valid_request("invalid_options.proto");
    invalid_options.parameter = "namespace_prefix=outer..inner";
    const auto invalid_request_path = directory.path / "invalid_request.bin";
    const auto invalid_response_path = directory.path / "invalid_response.bin";
    expect(write_request_file(invalid_request_path, invalid_options));
    expect(eq(invoke_plugin(invalid_request_path, invalid_response_path, plugin_invocation::standard_input), 0));

    const auto invalid_response = read_response_file(invalid_response_path);
    expect(invalid_response.has_value());
    if (invalid_response.has_value()) {
      expect(invalid_response->file.empty());
      expect(invalid_response->error.contains("invalid C++ identifier"sv));
    }

    const auto version_path = directory.path / "version.txt";
    expect(eq(invoke_plugin({}, version_path, plugin_invocation::version), 0));
    std::ifstream version_input{version_path};
    const std::string version{std::istreambuf_iterator<char>{version_input}, std::istreambuf_iterator<char>{}};
    expect(version.starts_with("hpp-proto version "));

    const auto missing_path = directory.path / "missing.bin";
    expect(neq(invoke_plugin(missing_path, response_path, plugin_invocation::file), 0));

    const auto malformed_path = directory.path / "malformed.bin";
    {
      std::ofstream malformed{malformed_path, std::ios::binary};
      malformed << '\0';
    }
    expect(neq(invoke_plugin(malformed_path, response_path, plugin_invocation::file), 0));

    auto invalid_export = valid_request("invalid_export.proto");
    invalid_export.parameter = "export_request=" + directory.path.string();
    expect(write_request_file(request_path, invalid_export));
    expect(neq(invoke_plugin(request_path, response_path, plugin_invocation::file), 0));
  };
#endif

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

  "keyword_mapped_enum_and_rpc_collisions_are_diagnosed_from_requests"_test = [] {
    auto enum_file = make_file("enum_collision.proto");
    enum_descriptor enumeration;
    enumeration.name = "KeywordCollision";
    enum_value_descriptor keyword_value;
    keyword_value.name = "class";
    keyword_value.number = 0;
    enumeration.value.push_back(std::move(keyword_value));
    enum_value_descriptor suffixed_value;
    suffixed_value.name = "class_";
    suffixed_value.number = 1;
    enumeration.value.push_back(std::move(suffixed_value));
    enum_file.enum_type.push_back(std::move(enumeration));

    const hpp_generator generator{generator_options{}};
    const auto enum_response = generator.generate(make_request({std::move(enum_file)}, {"enum_collision.proto"}));
    expect(enum_response.file.empty());
    expect(enum_response.error.contains("enum values 'class' and 'class_'"sv));

    auto rpc_file = make_file("rpc_collision.proto");
    rpc_file.message_type.push_back(make_message("Request"));
    service_descriptor service;
    service.name = "KeywordCollisionService";
    for (const std::string_view name : {"class"sv, "class_"sv}) {
      method_descriptor method;
      method.name = name;
      method.input_type = ".generator_test.Request";
      method.output_type = ".generator_test.Request";
      service.method.push_back(std::move(method));
    }
    rpc_file.service.push_back(std::move(service));

    const auto rpc_response = generator.generate(make_request({std::move(rpc_file)}, {"rpc_collision.proto"}));
    expect(rpc_response.file.empty());
    expect(rpc_response.error.contains("RPC methods 'class' and 'class_'"sv));
  };

  "generator_owned_namespace_names_are_diagnosed_from_requests"_test = [] {
    auto service_file = make_file("service_namespace_collision.proto");
    service_file.message_type.push_back(make_message("Request"));
    service_descriptor service;
    service.name = "pb_meta";
    method_descriptor method;
    method.name = "Call";
    method.input_type = ".generator_test.Request";
    method.output_type = ".generator_test.Request";
    service.method.push_back(std::move(method));
    service_file.service.push_back(std::move(service));

    const hpp_generator generator{generator_options{}};
    const auto service_response =
        generator.generate(make_request({std::move(service_file)}, {"service_namespace_collision.proto"}));
    expect(service_response.file.empty());
    expect(service_response.error.contains("service 'pb_meta' collides with the generated C++ namespace API"sv));

    auto enum_file = make_file("enum_namespace_collision.proto");
    enum_descriptor enumeration;
    enumeration.name = "pb_meta";
    enum_value_descriptor value;
    value.name = "VALID";
    value.number = 0;
    enumeration.value.push_back(std::move(value));
    enum_file.enum_type.push_back(std::move(enumeration));

    const auto enum_response =
        generator.generate(make_request({std::move(enum_file)}, {"enum_namespace_collision.proto"}));
    expect(enum_response.file.empty());
    expect(enum_response.error.contains("enum 'generator_test.pb_meta' maps to generated C++ namespace API"sv));
  };

  "missing_requested_files_are_diagnosed_from_a_request"_test = [] {
    const hpp_generator generator{generator_options{}};
    const auto response = generator.generate(make_request({make_file("available.proto")}, {"missing.proto"}));
    expect(response.file.empty());
    expect(response.error.contains("hpp file_to_generate not found: missing.proto"sv));
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
