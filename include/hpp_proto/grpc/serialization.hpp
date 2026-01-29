#pragma once
#include <algorithm>
#include <array>
#include <cassert>
#include <memory_resource>
#include <span>
#include <vector>

#include <grpc/byte_buffer.h>
#include <grpc/byte_buffer_reader.h>
#include <grpc/slice.h>
#include <grpcpp/impl/call_op_set.h>
#include <grpcpp/impl/serialization_traits.h>
#include <hpp_proto/binpb.hpp>

namespace hpp::proto::grpc {
class byte_buffer_access;
}

namespace grpc::internal {
template <>
class CallOpRecvMessage<::hpp::proto::grpc::byte_buffer_access> {
public:
  static grpc_byte_buffer *c_buffer(const ::grpc::ByteBuffer &buffer) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    return const_cast<::grpc::ByteBuffer &>(buffer).c_buffer();
  }
};
} // namespace grpc::internal

namespace hpp::proto {

template <typename Message, typename Context>
struct with_pb_context {
  using is_with_pb_context = void;
  // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
  Message &message;
  [[no_unique_address]] Context &context;
  // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

  explicit with_pb_context(Message &m, Context &ctx) : message(m), context(ctx) {}
};

namespace concepts {
template <typename T>
concept with_pb_context = requires { typename std::decay_t<T>::is_with_pb_context; };
} // namespace concepts

namespace grpc {

class byte_buffer_sink {
public:
  using byte_type = std::byte;
  using slice_type = ::grpc::Slice;

  explicit byte_buffer_sink(std::pmr::memory_resource &mr, std::size_t chunk_size)
      : slices_(&mr), chunk_size_(chunk_size) {}
  byte_buffer_sink(const byte_buffer_sink &) = delete;
  byte_buffer_sink(byte_buffer_sink &&) = delete;
  byte_buffer_sink &operator=(const byte_buffer_sink &) = delete;
  byte_buffer_sink &operator=(byte_buffer_sink &&) = delete;
  ~byte_buffer_sink() = default;

  void set_message_size(std::size_t message_size) {
    slices_.clear();
    if (message_size != 0) {
      const auto num_slices = chunk_size_ == std::numeric_limits<std::size_t>::max()
                                  ? std::size_t{1}
                                  : (message_size + chunk_size_ - 1) / chunk_size_;
      slices_.reserve(num_slices);
    }
    remaining_total_ = message_size;
  }

  std::span<std::byte> next_chunk() {
    if (remaining_total_ == 0) {
      return {};
    }
    const auto reserve_size = std::min(chunk_size_, remaining_total_);
    auto &slice = slices_.emplace_back(reserve_size);
    remaining_total_ -= reserve_size;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto bytes = std::span<uint8_t>(const_cast<uint8_t *>(slice.begin()), slice.size());
    return std::as_writable_bytes(bytes);
  }

  void finalize(::grpc::ByteBuffer &buffer) {
    ::grpc::ByteBuffer tmp(slices_.data(), slices_.size());
    buffer.Swap(&tmp);
  }
  [[nodiscard]] std::size_t chunk_size() const { return chunk_size_; }

private:
  std::pmr::vector<::grpc::Slice> slices_;
  std::size_t remaining_total_ = 0;
  std::size_t chunk_size_ = 0;
};

::grpc::Status write_binpb(::hpp::proto::concepts::has_meta auto const &message, ::grpc::ByteBuffer &buffer,
                           ::hpp::proto::concepts::is_pb_context auto &ctx) {
  constexpr bool is_contiguous = ::hpp::proto::pb_serializer::serialization_mode_for_context<decltype(ctx)>() ==
                                 ::hpp::proto::serialization_mode::contiguous;
  constexpr std::size_t kStackBufferSize = is_contiguous ? sizeof(::grpc::Slice) : 4096;
  alignas(std::max_align_t) std::array<std::byte, kStackBufferSize> stack_buffer{};
  std::pmr::monotonic_buffer_resource mr{stack_buffer.data(), stack_buffer.size()};
  byte_buffer_sink sink{mr, is_contiguous ? std::numeric_limits<std::size_t>::max() : 1024ULL * 1024ULL};
  if (::hpp::proto::write_binpb(message, sink, ctx).ok()) [[likely]] {
    sink.finalize(buffer);
    return ::grpc::Status::OK;
  }

  return {::grpc::StatusCode::INTERNAL, "Failed to serialize message"};
}

::grpc::Status write_binpb(::hpp::proto::concepts::has_meta auto const &message, ::grpc::ByteBuffer &buffer,
                           ::hpp::proto::concepts::is_option_type auto &&...option) {
  pb_context context{option...};
  return write_binpb(message, buffer, context);
}

class slices_view {
public:
  using slice_span = std::span<const uint8_t>;

  slices_view(const slices_view &) = delete;
  slices_view &operator=(const slices_view &) = delete;
  slices_view(slices_view &&) = delete;
  slices_view &operator=(slices_view &&) = delete;
  ~slices_view() = default;

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
  explicit slices_view(const ::grpc::ByteBuffer &buffer)
      : resource_(buffer_.data(), buffer_.size()), slices_(&resource_), spans_(&resource_) {
    auto *c_buffer = ::grpc::internal::CallOpRecvMessage<::hpp::proto::grpc::byte_buffer_access>::c_buffer(buffer);
    if (c_buffer == nullptr) {
      return;
    }

    // NOLINTBEGIN(cppcoreguidelines-pro-type-union-access)
    if (c_buffer->type == GRPC_BB_RAW && c_buffer->data.raw.compression == GRPC_COMPRESS_NONE) {
      size_t count = c_buffer->data.raw.slice_buffer.count;
      slices_.reserve(count);
      spans_.reserve(count);
    }
    // NOLINTEND(cppcoreguidelines-pro-type-union-access)

    grpc_byte_buffer_reader reader;
    if (grpc_byte_buffer_reader_init(&reader, c_buffer) != 0) {
      grpc_slice s;
      while (grpc_byte_buffer_reader_next(&reader, &s) != 0) {
        slices_.emplace_back(s, ::grpc::Slice::STEAL_REF);
      }
      grpc_byte_buffer_reader_destroy(&reader);
    } else {
      supported_ = false;
      return;
    }

    if (spans_.capacity() < slices_.size()) {
      spans_.reserve(slices_.size());
    }

    for (const auto &slice : slices_) {
      spans_.emplace_back(slice.begin(), slice.size());
    }
  }

  [[nodiscard]] std::span<slice_span> get() { return {spans_}; }
  [[nodiscard]] bool supported() const { return supported_; }

private:
  static constexpr size_t kStackBufferSize = size_t{16} * 1024;
  // NOLINTNEXTLINE(cppcoreguidelines-use-default-member-init,modernize-use-default-member-init)
  alignas(std::max_align_t) std::array<std::byte, kStackBufferSize> buffer_;
  std::pmr::monotonic_buffer_resource resource_;
  std::pmr::vector<::grpc::Slice> slices_;
  std::pmr::vector<slice_span> spans_;
  bool supported_ = true;
};

::grpc::Status read_binpb(::hpp::proto::concepts::has_meta auto &message, const ::grpc::ByteBuffer &buffer,
                          ::hpp::proto::concepts::is_pb_context auto &context) {

  slices_view buffers{buffer};
  if (!buffers.supported()) {
    return {::grpc::StatusCode::INVALID_ARGUMENT, "Unsupported ByteBuffer compression"};
  }
  if (::hpp::proto::read_binpb(message, buffers.get(), context).ok()) [[likely]] {
    return ::grpc::Status::OK;
  }
  return {::grpc::StatusCode::INTERNAL, "Failed to deserialize message"};
}

::grpc::Status read_binpb(::hpp::proto::concepts::has_meta auto &message, const ::grpc::ByteBuffer &buffer,
                          ::hpp::proto::concepts::is_option_type auto &&...option) {
  pb_context context{option...};
  return read_binpb(message, buffer, context);
}
} // namespace grpc

} // namespace hpp::proto

namespace grpc {
template <class T>
  requires ::hpp::proto::concepts::with_pb_context<T>
class SerializationTraits<T> {
public:
  static Status Serialize(const T &msg_with_context, ByteBuffer *bb, bool *own_buffer) {
    *own_buffer = true;
    return ::hpp::proto::grpc::write_binpb(msg_with_context.message, *bb, msg_with_context.context);
  }

  static Status Deserialize(ByteBuffer *buffer, T *msg_with_context) {
    auto status = ::hpp::proto::grpc::read_binpb(msg_with_context->message, *buffer, msg_with_context->context);
    buffer->Clear();
    return status;
  }
};
} // namespace grpc
