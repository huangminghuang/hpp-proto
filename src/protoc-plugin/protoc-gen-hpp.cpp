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

#include "hpp_generator.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <ranges>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {

bool write_response(const hpp_proto::protoc::code_generator_response &response) {
  std::vector<char> data;
  if (auto status = ::hpp_proto::write_binpb(response, data); !status.ok()) {
    (void)fputs("hpp encode error", stderr);
    return false;
  }

#ifdef _WIN32
  _setmode(_fileno(stdout), _O_BINARY);
#endif
  std::ranges::copy(data, std::ostreambuf_iterator<char>(std::cout));
  return true;
}

} // namespace

// NOLINTNEXTLINE(bugprone-exception-escape)
int main(int argc, const char **argv) {
  const std::span<const char *> args{argv, static_cast<std::size_t>(argc)};
  if (std::ranges::find_if(args, [](auto arg) { return std::string_view(arg) == "--version"; }) != args.end()) {
#ifdef HPP_PROTO_VERSION
    std::cout << "hpp-proto version " << HPP_PROTO_VERSION << "\n";
#else
    std::cout << "hpp-proto version unknown\n";
#endif
    return 0;
  }

  std::vector<char> request_data;
  const auto read_file = [&request_data](auto &&stream) {
    std::copy(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>(),
              std::back_inserter(request_data));
  };

#ifdef _WIN32
  _setmode(_fileno(stdin), _O_BINARY);
#endif

  if (args.size() == 2) {
    std::ifstream input(args[1], std::ios_base::binary);
    if (!input) {
      (void)fputs("hpp input file open error", stderr);
      return 1;
    }
    read_file(input);
  } else {
    read_file(std::cin);
  }

  hpp_proto::protoc::code_generator_request request;
  if (auto status = ::hpp_proto::read_binpb(request, request_data); !status.ok()) {
    (void)fputs("hpp decode error", stderr);
    return 1;
  }

  auto parsed_options = hpp_proto::protoc::parse_plugin_options(request.parameter, args[0]);
  if (!parsed_options.has_value()) {
    hpp_proto::protoc::code_generator_response response;
    using enum hpp_proto::protoc::code_generator_response::Feature;
    response.supported_features =
        static_cast<std::uint64_t>(FEATURE_PROTO3_OPTIONAL) | static_cast<std::uint64_t>(FEATURE_SUPPORTS_EDITIONS);
    response.minimum_edition = static_cast<std::int32_t>(google::protobuf::Edition::EDITION_PROTO2);
    response.maximum_edition = static_cast<std::int32_t>(google::protobuf::Edition::EDITION_2024);
    response.error = parsed_options.error().message;
    return write_response(response) ? 0 : 1;
  }

  if (parsed_options->export_request.has_value()) {
    std::ofstream output{*parsed_options->export_request, std::ios::binary};
    if (!output) {
      (void)fputs("hpp export_request open error", stderr);
      return 1;
    }
    std::ranges::copy(request_data, std::ostreambuf_iterator<char>(output));
  }

  const hpp_proto::protoc::hpp_generator generator{std::move(parsed_options->generation)};
  return write_response(generator.generate(std::move(request))) ? 0 : 1;
}
