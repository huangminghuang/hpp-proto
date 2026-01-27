#include <string>

#include <boost/ut.hpp>
#include <grpc/byte_buffer.h>
#include <grpc/compression.h>
#include <grpc/slice.h>
#include <grpcpp/grpcpp.h>
#include <hpp_proto/grpc/serialization.hpp>

#include "echo_stream.pb.hpp"

namespace {
const boost::ut::suite grpc_serialization_tests = [] {
  using namespace boost::ut;
  "read_binpb_empty_buffer_succeeds"_test = [] {
    ::grpc::ByteBuffer buffer;
    ::hpp::proto::grpc::EchoRequest<> msg;
    auto status = ::hpp::proto::grpc::read_binpb(msg, buffer);
    expect(status.ok());
  };

  "read_binpb_invalid_payload_fails"_test = [] {
    const std::string bad_payload = "not-a-binpb-payload";
    ::grpc::Slice slice(bad_payload.data(), bad_payload.size());
    ::grpc::ByteBuffer buffer(&slice, 1);
    ::hpp::proto::grpc::EchoRequest<> msg;
    auto status = ::hpp::proto::grpc::read_binpb(msg, buffer);
    expect(!status.ok());
  };

#if !HPP_PROTO_NO_UTF8_VALIDATION
  "write_binpb_failure_returns_internal"_test = [] {
    ::grpc::ByteBuffer buffer;
    ::hpp::proto::grpc::EchoRequest<> msg;
    msg.message = std::string{"\xFF"};
    auto status = ::hpp::proto::grpc::write_binpb(msg, buffer);
    expect(status.error_code() == ::grpc::StatusCode::INTERNAL);
  };
#endif
};
} // namespace
