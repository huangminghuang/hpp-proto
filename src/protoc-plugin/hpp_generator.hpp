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

#include "cpp_lexical_emitter.hpp"

#include <expected>
#include <filesystem>
#include <google/protobuf/compiler/plugin.pb.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hpp_proto::protoc {

using code_generator_request = google::protobuf::compiler::CodeGeneratorRequest<::hpp_proto::default_traits>;
using code_generator_response = google::protobuf::compiler::CodeGeneratorResponse<::hpp_proto::default_traits>;

// Options that affect generated C++ output. An hpp_generator owns an immutable
// copy so separate invocations cannot leak configuration into one another.
struct generator_options {
  std::filesystem::path plugin_name{"protoc-gen-hpp"};
  std::string raw_parameters;
  std::string directory_prefix;
  std::optional<cpp::qualified_name> namespace_prefix;
  std::vector<std::string> proto2_explicit_presences{"."};
  bool preserve_proto_field_names = false;
};

// export_request belongs to the executable adapter: it writes the original wire
// bytes and therefore is deliberately not part of generator_options.
struct plugin_options {
  generator_options generation;
  std::optional<std::filesystem::path> export_request;
};

struct generator_option_error {
  std::string message;
};

[[nodiscard]] std::expected<plugin_options, generator_option_error>
parse_plugin_options(std::string_view parameters,
                     std::filesystem::path plugin_name = std::filesystem::path{"protoc-gen-hpp"});

// Generator core seam. The request is accepted by value because descriptor-pool
// initialization consumes its proto_file storage.
class hpp_generator {
public:
  explicit hpp_generator(generator_options options) : options_(std::move(options)) {}

  [[nodiscard]] code_generator_response generate(code_generator_request request) const;

private:
  generator_options options_;
};

} // namespace hpp_proto::protoc
