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
    hpp_proto_test::EchoRequest<> msg;
    auto status = ::hpp_proto::grpc::read_binpb(msg, buffer);
    expect(status.ok());
  };

  "read_binpb_invalid_payload_fails"_test = [] {
    const std::string bad_payload = "not-a-binpb-payload";
    ::grpc::Slice slice(bad_payload.data(), bad_payload.size());
    ::grpc::ByteBuffer buffer(&slice, 1);
    hpp_proto_test::EchoRequest<> msg;
    auto status = ::hpp_proto::grpc::read_binpb(msg, buffer);
    expect(!status.ok());
  };

  "write_read_binpb_roundtrip"_test = []<class Mode> {
    hpp_proto_test::EchoRequest<> msg;
    msg.message = "hello grpc";
    ::grpc::ByteBuffer buffer;
    auto write_status = ::hpp_proto::grpc::write_binpb(msg, buffer, Mode{});
    expect(write_status.ok());

    hpp_proto_test::EchoRequest<> decoded;
    auto read_status = ::hpp_proto::grpc::read_binpb(decoded, buffer);
    expect(read_status.ok());
    expect(decoded.message == msg.message);
  } | std::make_tuple(hpp_proto::contiguous_mode, hpp_proto::adaptive_mode, hpp_proto::chunked_mode);

#if !HPP_PROTO_NO_UTF8_VALIDATION
  "write_binpb_failure_returns_internal"_test = [] {
    ::grpc::ByteBuffer buffer;
    hpp_proto_test::EchoRequest<> msg;
    msg.message = std::string{"\xFF"};
    auto status = ::hpp_proto::grpc::write_binpb(msg, buffer);
    expect(status.error_code() == ::grpc::StatusCode::INTERNAL);
  };
#endif
};
} // namespace
