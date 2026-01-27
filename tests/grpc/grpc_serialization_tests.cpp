#include <array>
#include <string>

#include <boost/ut.hpp>
#include <grpc/byte_buffer.h>
#include <grpc/compression.h>
#include <grpc/slice.h>
#include <grpcpp/grpcpp.h>
#include <hpp_proto/grpc/serialization.hpp>

#include "echo_stream.pb.hpp"

namespace grpc::internal {
class GrpcByteBufferPeer {
public:
  static void set_buffer(::grpc::ByteBuffer *buffer, grpc_byte_buffer *raw) { buffer->set_buffer(raw); }
};
} // namespace grpc::internal

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

  "read_binpb_rejects_compressed_byte_buffer"_test = [] {
    constexpr std::array<unsigned char, 6> payload = {
        0x0A, 0x80, 0x80, 0x80, 0x80, 0x10,
    };
    grpc_slice slice = grpc_slice_from_copied_buffer(reinterpret_cast<const char *>(payload.data()), payload.size());
    grpc_byte_buffer *raw = grpc_raw_compressed_byte_buffer_create(&slice, 1, GRPC_COMPRESS_GZIP);
    grpc_slice_unref(slice);

    ::grpc::ByteBuffer buffer;
    ::grpc::internal::GrpcByteBufferPeer::set_buffer(&buffer, raw);

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
