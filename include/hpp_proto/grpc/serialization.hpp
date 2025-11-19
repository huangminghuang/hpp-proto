#pragma once
#include <array>
#include <span>
#include <vector>

#include <grpc/byte_buffer.h>
#include <grpc/byte_buffer_reader.h>
#include <grpcpp/impl/call_op_set.h>
#include <grpcpp/impl/serialization_traits.h>
#include <hpp_proto/pb_serializer.hpp>

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

::grpc::Status write_proto(::hpp::proto::concepts::has_meta auto const &message, ::grpc::ByteBuffer &buffer) {
  class slice_arena {
    ::grpc::ByteBuffer *buffer_;
    ::grpc::Slice slice_{};

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
      return const_cast<uint8_t *>(slice_.begin());
    }
  } pool{buffer};
  std::span<const std::byte> buf;
  // TODO: consider writing to a chain of bounded slices
  if (::hpp::proto::write_proto(message, buf, ::hpp::proto::alloc_from{pool}).ok()) [[likely]] {
    return ::grpc::Status::OK;
  }

  return {::grpc::StatusCode::INTERNAL, "Failed to serialize message"};
}

::grpc::Status read_proto(::hpp::proto::concepts::has_meta auto &message, const ::grpc::ByteBuffer &buffer,
                          ::hpp::proto::concepts::is_pb_context auto &context) {

  using slice_span = std::span<const uint8_t>;
  class slices_view {
    std::span<const slice_span> slices_;

  public:
    slices_view(grpc_byte_buffer *c_buffer, std::span<slice_span> storage) {
      grpc_byte_buffer_reader reader;
      grpc_byte_buffer_reader_init(&reader, c_buffer);

      grpc_slice *slice = nullptr;
      std::size_t slice_count = 0;
      while (grpc_byte_buffer_reader_peek(&reader, &slice) != 0) {
        auto *start_ptr = GRPC_SLICE_START_PTR(*slice);
        auto len = GRPC_SLICE_LENGTH(*slice);
        slice_span current{start_ptr, len};
        storage[slice_count++] = current;
      }

      grpc_byte_buffer_reader_destroy(&reader);
      slices_ = std::span<const slice_span>{storage.data(), slice_count};
    }

    [[nodiscard]] std::size_t size() const { return slices_.size(); }
    [[nodiscard]] const slice_span *data() const { return slices_.data(); }
    [[nodiscard]] auto cbegin() const { return std::cbegin(slices_); }
    [[nodiscard]] auto cend() const { return std::cend(slices_); }
    [[nodiscard]] auto begin() const { return slices_.begin(); }
    [[nodiscard]] auto end() const { return slices_.end(); }
  };

  auto *c_buffer = ::grpc::internal::CallOpRecvMessage<::hpp::proto::grpc::byte_buffer_access>::c_buffer(buffer);
  auto deserialize_by_slices = [&](auto &storage) -> ::grpc::Status {
    slices_view buffers{c_buffer, storage};
    if (::hpp::proto::read_proto(message, buffers, context).ok()) [[likely]] {
      return ::grpc::Status::OK;
    }
    return {::grpc::StatusCode::INTERNAL, "Failed to deserialize message"};
  };

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
  std::size_t num_slices = c_buffer->data.raw.slice_buffer.count;
  if (num_slices <= ::hpp::proto::pb_serializer::stack_segment_threshold) [[likely]] {
    std::array<slice_span, ::hpp::proto::pb_serializer::stack_segment_threshold> storage;
    return deserialize_by_slices(storage);
  } else {
    std::vector<slice_span> storage(num_slices);
    return deserialize_by_slices(storage);
  }
}

::grpc::Status read_proto(::hpp::proto::concepts::has_meta auto &message, const ::grpc::ByteBuffer &buffer,
                          ::hpp::proto::concepts::is_option_type auto &&...option) {

  pb_context context{option...};
  return read_proto(message, buffer, context);
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
    return ::hpp::proto::grpc::write_proto(msg_with_context.message, *bb);
  }

  static Status Deserialize(ByteBuffer *buffer, T *msg_with_context) {
    auto status = ::hpp::proto::grpc::read_proto(msg_with_context->message, *buffer, msg_with_context->context);
    buffer->Clear();
    return status;
  }
};
} // namespace grpc
