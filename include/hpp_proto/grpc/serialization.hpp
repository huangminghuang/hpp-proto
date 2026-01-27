#pragma once
#include <array>
#include <span>
#include <vector>

#include <grpc/byte_buffer.h>
#include <grpc/byte_buffer_reader.h>
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
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  Message &message;
  [[no_unique_address]] Context context;
  explicit with_pb_context(Message &m, Context &&ctx) : message(m), context(std::move(ctx)) {}
};

namespace concepts {
template <typename T>
concept with_pb_context = requires { typename std::decay_t<T>::is_with_pb_context; };
} // namespace concepts

namespace grpc {

::grpc::Status write_binpb(::hpp::proto::concepts::has_meta auto const &message, ::grpc::ByteBuffer &buffer) {
  class slice_arena {
    ::grpc::ByteBuffer *buffer_;
    ::grpc::Slice slice_;

  public:
    explicit slice_arena(::grpc::ByteBuffer &buffer) : buffer_(&buffer) {}
    slice_arena(const slice_arena &) = delete;
    slice_arena(slice_arena &&) = delete;
    slice_arena &operator=(const slice_arena &) = delete;
    slice_arena &operator=(slice_arena &&) = delete;
    ~slice_arena() {
      ::grpc::ByteBuffer tmp(&slice_, 1);
      buffer_->Swap(&tmp);
    }

    void *allocate(std::size_t size, std::size_t) {
      std::construct_at(&slice_, size);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
      return const_cast<uint8_t *>(slice_.begin());
    }
  } pool{buffer};
  std::span<const std::byte> buf;
  // TODO: consider writing to a chain of bounded slices
  if (::hpp::proto::write_binpb(message, buf, ::hpp::proto::alloc_from{pool}).ok()) [[likely]] {
    return ::grpc::Status::OK;
  }

  return {::grpc::StatusCode::INTERNAL, "Failed to serialize message"};
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
      : resource_(buffer_.data(), buffer_.size()), // 2. Init resource with stack buffer
        slices_(&resource_),                       // 3. Init vectors with resource
        spans_(&resource_) {
    auto *c_buffer = ::grpc::internal::CallOpRecvMessage<::hpp::proto::grpc::byte_buffer_access>::c_buffer(buffer);
    if (c_buffer == nullptr) {
      return;
    }

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
    return ::hpp::proto::grpc::write_binpb(msg_with_context.message, *bb);
  }

  static Status Deserialize(ByteBuffer *buffer, T *msg_with_context) {
    auto status = ::hpp::proto::grpc::read_binpb(msg_with_context->message, *buffer, msg_with_context->context);
    buffer->Clear();
    return status;
  }
};
} // namespace grpc
