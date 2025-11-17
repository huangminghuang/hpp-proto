#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <span>
#include <string_view>

#include "test_harness.hpp"

namespace {
bool write_endpoint_file(const std::string &path, std::string_view endpoint) {
  std::ofstream out(path, std::ios::trunc);
  if (!out.is_open()) {
    return false;
  }
  out << endpoint;
  out.flush();
  return static_cast<bool>(out);
}
} // namespace

int main(int argc, char **argv) {
  std::span args(argv, static_cast<size_t>(argc));
  if (args.size() < 2) {
    std::cerr << "Usage: grpc_test_server <port_file> [listen_address]" << '\n';
    return 1;
  }

  const std::string port_file = args[1];
  std::string address = "127.0.0.1:0";
  if (args.size() > 2) {
    address = args[2];
  }

  hpp::proto::grpc::test_utils::EchoService service;
  ::grpc::ServerBuilder builder;
  builder.SetMaxReceiveMessageSize(-1);
  int selected_port = 0;
  builder.AddListeningPort(address, ::grpc::InsecureServerCredentials(), &selected_port);
  builder.RegisterService(&service);
  auto server = builder.BuildAndStart();
  if (server == nullptr || selected_port == 0) {
    std::cerr << "Failed to start grpc test server." << '\n';
    return 1;
  }

  const std::string endpoint = "127.0.0.1:" + std::to_string(selected_port);
  if (!write_endpoint_file(port_file, endpoint)) {
    std::cerr << "Failed to write port file at " << port_file << '\n';
    return 1;
  }

  std::cout << "grpc_test_server listening on " << endpoint << '\n';
  std::cout.flush();
  server->Wait();
  return 0;
}
