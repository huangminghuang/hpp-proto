#pragma once
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
  static void convert_slices(std::vector<std::span<const uint8_t>> &dest, const ::grpc::ByteBuffer &buffer) {
    grpc_byte_buffer_reader reader;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto *c_buffer = const_cast<::grpc::ByteBuffer &>(buffer).c_buffer();
    grpc_byte_buffer_reader_init(&reader, c_buffer);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    dest.reserve(c_buffer->data.raw.slice_buffer.count);

    grpc_slice *slice = nullptr;
    while (grpc_byte_buffer_reader_peek(&reader, &slice) != 0) {
      auto *start_ptr = GRPC_SLICE_START_PTR(*slice);
      auto len = GRPC_SLICE_LENGTH(*slice);
      dest.emplace_back(start_ptr, len);
    }
    grpc_byte_buffer_reader_destroy(&reader);
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
namespace detail {
class byte_buffer_adaptor {
  using storage_t = std::vector<std::span<const uint8_t>>;
  storage_t slices_;

public:
  using value_type = storage_t::value_type;
  using pointer = storage_t::pointer;
  using const_pointer = storage_t::const_pointer;
  using reference = storage_t::reference;
  using const_reference = storage_t::const_reference;
  using size_type = storage_t::size_type;
  using difference_type = storage_t::difference_type;
  using iterator = storage_t::iterator;
  using const_iterator = storage_t::const_iterator;

  explicit byte_buffer_adaptor(const ::grpc::ByteBuffer &buffer) {
    ::grpc::internal::CallOpRecvMessage<byte_buffer_access>::convert_slices(slices_, buffer);
  }

  [[nodiscard]] size_type size() const { return slices_.size(); }

  [[nodiscard]] const_pointer data() const { return slices_.data(); }

  [[nodiscard]] const_iterator cbegin() const { return slices_.cbegin(); }
  [[nodiscard]] const_iterator cend() const { return slices_.cend(); }
  [[nodiscard]] const_iterator begin() const { return slices_.begin(); }
  [[nodiscard]] const_iterator end() const { return slices_.end(); }
};

struct single_shot_slice_memory_resource {
  grpc_slice slice_{};
  single_shot_slice_memory_resource() = default;
  ~single_shot_slice_memory_resource() {
    if (slice_.refcount != nullptr) {
      grpc_slice_unref(slice_);
    }
  }
  single_shot_slice_memory_resource(const single_shot_slice_memory_resource &) = delete;
  single_shot_slice_memory_resource(single_shot_slice_memory_resource &&) = delete;
  single_shot_slice_memory_resource &operator=(const single_shot_slice_memory_resource &) = delete;
  single_shot_slice_memory_resource &operator=(single_shot_slice_memory_resource &&) = delete;

  void *allocate(std::size_t size, std::size_t) {
    assert(slice_.refcount == nullptr);
    slice_ = grpc_slice_malloc(size);
    return GRPC_SLICE_START_PTR(slice_);
  }

  [[nodiscard]] ::grpc::ByteBuffer finalize() const {
    ::grpc::Slice slice(slice_, ::grpc::Slice::STEAL_REF);
    return {&slice, 1};
  }
};
} // namespace detail

::grpc::Status write_proto(::hpp::proto::concepts::has_meta auto const &message, ::grpc::ByteBuffer &buffer) {
  detail::single_shot_slice_memory_resource pool;
  std::span<const std::byte> buf;
  if (::hpp::proto::write_proto(message, buf, ::hpp::proto::alloc_from{pool}).ok()) [[likely]] {
    buffer = pool.finalize();
    return ::grpc::Status::OK;
  }

  return {::grpc::StatusCode::INTERNAL, "Failed to serialize message"};
}

::grpc::Status read_proto(::hpp::proto::concepts::has_meta auto &message, const ::grpc::ByteBuffer &buffer,
                          ::hpp::proto::concepts::is_pb_context auto &context) {

  detail::byte_buffer_adaptor buffers(buffer);
  if (::hpp::proto::read_proto(message, buffers, context).ok()) [[likely]] {
    return ::grpc::Status::OK;
  }
  return {::grpc::StatusCode::INTERNAL, "Failed to deserialize message"};
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
  static Status Serialize(const T &msg_with_context, ByteBuffer *bb, bool *) {
    return ::hpp::proto::grpc::write_proto(msg_with_context.message, *bb);
  }

  static Status Deserialize(ByteBuffer *buffer, T *msg_with_context) {
    return ::hpp::proto::grpc::read_proto(msg_with_context->message, *buffer, msg_with_context->context);
  }
};
} // namespace grpc
