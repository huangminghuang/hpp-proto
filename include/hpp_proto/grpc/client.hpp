
#pragma once
#include <grpcpp/generic/generic_stub.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/impl/client_unary_call.h>
#include <grpcpp/support/client_callback.h>
#include <grpcpp/support/stub_options.h>

#include <condition_variable>
#include <hpp_proto/grpc/serialization.hpp>
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>

namespace hpp_proto::grpc {

namespace concepts {
template <typename Message, template <typename> typename MessageTemplate>
concept message_instantiation_of = std::same_as<Message, MessageTemplate<typename Message::hpp_proto_traits_type>>;

template <typename Method, typename Request, typename Response>
concept method_check = message_instantiation_of<Request, Method::template request_t> &&
                       message_instantiation_of<Response, Method::template response_t>;

template <typename Method, typename Request, typename Response>
concept unary_method_check =
    !Method::server_streaming && !Method::client_streaming && concepts::method_check<Method, Request, Response>;

template <typename ServiceMethods, typename Method>
concept service_method_check = std::same_as<Method, std::tuple_element_t<Method::ordinal, ServiceMethods>>;

} // namespace concepts

using RpcType = ::grpc::internal::RpcMethod::RpcType;

template <RpcType rpc_type>
struct ClientCallbackSelector;

template <>
struct ClientCallbackSelector<RpcType::NORMAL_RPC> {
  using reactor = ::grpc::ClientUnaryReactor;
};

template <>
struct ClientCallbackSelector<RpcType::CLIENT_STREAMING> {
  using reactor = ::grpc::ClientWriteReactor<::grpc::ByteBuffer>;
};

template <>
struct ClientCallbackSelector<RpcType::SERVER_STREAMING> {
  using reactor = ::grpc::ClientReadReactor<::grpc::ByteBuffer>;
};

template <>
struct ClientCallbackSelector<RpcType::BIDI_STREAMING> {
  using reactor = ::grpc::ClientBidiReactor<::grpc::ByteBuffer, ::grpc::ByteBuffer>;
};

template <typename Method>
class ClientCallbackReactor;

template <typename ServiceMethods>
class Stub {
  class GrpcMethod : public ::grpc::internal::RpcMethod {
  public:
    GrpcMethod() : ::grpc::internal::RpcMethod(nullptr, RpcType::NORMAL_RPC) {}
    void set(const char *name, const char *suffix_for_stats, RpcType type,
             const std::shared_ptr<::grpc::ChannelInterface> &channel) {
      std::construct_at(static_cast<::grpc::internal::RpcMethod *>(this), name, suffix_for_stats, type, channel);
    }
  };

  std::shared_ptr<::grpc::ChannelInterface> channel_;
  ::grpc::StubOptions options_;
  GrpcMethod grpc_methods_[std::tuple_size_v<ServiceMethods>];

  template <typename Method>
  friend class ClientCallbackReactor;

  template <typename Method>
    requires concepts::service_method_check<ServiceMethods, Method>
  [[nodiscard]] const ::grpc::internal::RpcMethod &grpc_method() const {
    return grpc_methods_[Method::ordinal];
  }

public:
  Stub(const std::shared_ptr<::grpc::ChannelInterface> &channel, const ::grpc::StubOptions &options)
      : channel_(channel), options_(options) {
    std::apply(
        [this](auto &&...method) {
          ((grpc_methods_[method.ordinal].set(method.method_name, this->options_.suffix_for_stats(),
                                              static_cast<RpcType>(method.rpc_type), this->channel_)),
           ...);
        },
        ServiceMethods{});
  }

  Stub(const Stub &) = delete;
  Stub(Stub &&) = delete;
  Stub &operator=(const Stub &) = delete;
  Stub &operator=(Stub &&) = delete;
  ~Stub() = default;

  template <typename Method, typename Request, typename Response>
    requires(concepts::unary_method_check<Method, Request, Response>)::grpc::Status
  call(::grpc::ClientContext &context, const Request &request, Response &response,
       hpp_proto::concepts::is_option_type auto &&...option) {
    pb_context ctx{std::forward<decltype(option)>(option)...};
    hpp_proto::with_pb_context request_with_context{request, ctx};
    hpp_proto::with_pb_context response_with_context{response, ctx};

    return ::grpc::internal::BlockingUnaryCallImpl{this->channel_.get(), grpc_method<Method>(), &context,
                                                   request_with_context, &response_with_context}
        .status();
  }

  template <typename Method, typename Request>
    requires(!Method::client_streaming)
  void async_call(::grpc::ClientContext &context, const Request &request, ClientCallbackReactor<Method> *reactor) {
    reactor->prepare(*this, context, request);
  }

  template <typename Method>
    requires(Method::client_streaming)
  void async_call(::grpc::ClientContext &context, ClientCallbackReactor<Method> *reactor) {
    reactor->prepare(*this, context);
  }

  template <typename Method, typename Request, typename Response, typename CallbackFunction>
    requires(concepts::unary_method_check<Method, Request, Response>)
  void async_call(::grpc::ClientContext &context, const Request &request, Response &response, CallbackFunction &&f,
                  hpp_proto::concepts::is_option_type auto &&...response_option);
};

template <typename Method>
class ClientCallbackReactor : public ClientCallbackSelector<static_cast<RpcType>(Method::rpc_type)>::reactor {
  using base = typename ClientCallbackSelector<static_cast<RpcType>(Method::rpc_type)>::reactor;
  ::grpc::ByteBuffer request_;
  ::grpc::ByteBuffer response_;

public:
  static const auto rpc_type = static_cast<RpcType>(Method::rpc_type);

  ClientCallbackReactor() = default;

  template <typename Stub, typename Traits>
    requires(rpc_type == RpcType::NORMAL_RPC)
  void prepare(const Stub &stub, ::grpc::ClientContext &context, const typename Method::template request_t<Traits> &req,
               hpp_proto::concepts::is_option_type auto &&...option) {
    auto result = ::hpp_proto::grpc::write_binpb(req, request_, std::forward<decltype(option)>(option)...);
    if (result.ok()) {
      ::grpc::internal::ClientCallbackUnaryFactory::Create<::grpc::ByteBuffer, ::grpc::ByteBuffer>(
          stub.channel_.get(), stub.template grpc_method<Method>(), &context, &request_, &response_, this);
    } else {
      this->OnDone(result);
    }
  }

  template <typename Stub>
    requires(rpc_type == RpcType::CLIENT_STREAMING)
  void prepare(const Stub &stub, ::grpc::ClientContext &context) {
    ::grpc::internal::ClientCallbackWriterFactory<::grpc::ByteBuffer>::Create(
        stub.channel_.get(), stub.template grpc_method<Method>(), &context, &response_, this);
  }

  template <typename Stub, typename Traits>
    requires(rpc_type == RpcType::SERVER_STREAMING)
  void prepare(const Stub &stub, ::grpc::ClientContext &context, const typename Method::template request_t<Traits> &req,
               hpp_proto::concepts::is_option_type auto &&...option) {
    auto result = ::hpp_proto::grpc::write_binpb(req, request_, std::forward<decltype(option)>(option)...);
    if (result.ok()) {
      ::grpc::internal::ClientCallbackReaderFactory<::grpc::ByteBuffer>::Create(
          stub.channel_.get(), stub.template grpc_method<Method>(), &context, &request_, this);
    } else {
      this->OnDone(result);
    }
  }

  template <typename Stub>
    requires(rpc_type == RpcType::BIDI_STREAMING)
  void prepare(const Stub &stub, ::grpc::ClientContext &context) {
    ::grpc::internal::ClientCallbackReaderWriterFactory<::grpc::ByteBuffer, ::grpc::ByteBuffer>::Create(
        stub.channel_.get(), stub.template grpc_method<Method>(), &context, this);
  }

  void start_call() { this->StartCall(); }
  void start_read()
    requires Method::server_streaming
  {
    this->StartRead(&response_);
  }

  template <typename Traits>
  ::grpc::Status write(typename Method::template request_t<Traits> &req, ::grpc::WriteOptions options,
                       hpp_proto::concepts::is_option_type auto &&...ser_option)
    requires Method::client_streaming
  {
    auto result = ::hpp_proto::grpc::write_binpb(req, request_, std::forward<decltype(ser_option)>(ser_option)...);
    if (result.ok()) {
      this->StartWrite(&request_, options);
    }
    return result;
  }

  template <typename Traits>
  ::grpc::Status write(typename Method::template request_t<Traits> &req,
                       hpp_proto::concepts::is_option_type auto &&...ser_option)
    requires Method::client_streaming
  {
    return this->write(req, ::grpc::WriteOptions{}, std::forward<decltype(ser_option)>(ser_option)...);
  }

  template <typename Traits>
  ::grpc::Status write_last(typename Method::template request_t<Traits> &req, ::grpc::WriteOptions options,
                            hpp_proto::concepts::is_option_type auto &&...ser_option)
    requires Method::client_streaming
  {
    options.set_last_message();
    return write(req, options, std::forward<decltype(ser_option)>(ser_option)...);
  }

  void write_done()
    requires Method::client_streaming
  {
    this->StartWritesDone();
  }

  void add_hold() { add_multiple_holds(1); }
  void add_multiple_holds(int holds)
    requires(Method::client_streaming || Method::server_streaming)
  {
    this->AddHold(holds);
  }
  void remove_hold()
    requires(Method::client_streaming || Method::server_streaming)
  {
    this->RemoveHold();
  }

  template <typename Traits>
  ::grpc::Status get_response(typename Method::template response_t<Traits> &response,
                              hpp_proto::concepts::is_option_type auto &&...option) {
    return ::hpp_proto::grpc::read_binpb(response, response_, std::forward<decltype(option)>(option)...);
  }

  template <typename Traits>
  ::grpc::Status get_response(typename Method::template response_t<Traits> &response,
                              hpp_proto::concepts::is_pb_context auto &context) {
    return ::hpp_proto::grpc::read_binpb(response, response_, context);
  }

  ::grpc::ByteBuffer &response() { return response_; }
};

template <typename Method, typename CallbackFunction, typename Response, typename Context>
class CallbackUnaryCall : public ClientCallbackReactor<Method> {
  using callback_storage_t = std::remove_cvref_t<CallbackFunction>;
  callback_storage_t f_;
  Response &response_ref_; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
  Context response_context_;

public:
  CallbackUnaryCall(Method, callback_storage_t callback,
                    Response &response, // NOLINT(cppcoreguidelines-rvalue-reference-param-not-moved)
                    hpp_proto::concepts::is_option_type auto &&...response_option)
      : f_(std::move(callback)), response_ref_(response),
        response_context_(std::forward<decltype(response_option)>(response_option)...) {}

  void OnDone(const ::grpc::Status &status) override {
    ::grpc::Status final_status = status;
    if (final_status.ok()) {
      auto read_status = this->get_response(response_ref_, response_context_);
      if (!read_status.ok()) {
        final_status = read_status;
      }
    }
    f_(final_status);
    delete this;
  }
};

template <typename Method, typename CallbackFunction, typename Response, typename... U>
CallbackUnaryCall(Method, CallbackFunction &&, Response &, U &&...)
    -> CallbackUnaryCall<Method, CallbackFunction, Response, hpp_proto::pb_context<std::remove_cvref_t<U>...>>;

template <typename ServiceMethods>
template <typename Method, typename Request, typename Response, typename CallbackFunction>
  requires(concepts::unary_method_check<Method, Request, Response>)
void Stub<ServiceMethods>::async_call(::grpc::ClientContext &context, const Request &request, Response &response,
                                      CallbackFunction &&f,
                                      hpp_proto::concepts::is_option_type auto &&...response_option) {
  using CallbackReactorType =
      CallbackUnaryCall<Method, CallbackFunction, Response,
                        hpp_proto::pb_context<std::remove_cvref_t<decltype(response_option)>...>>;

  auto callback_reactor = std::unique_ptr<CallbackReactorType>{
      new CallbackReactorType{Method{}, std::forward<CallbackFunction>(f), response, response_option...}};
  callback_reactor->prepare(*this, context, request);
  callback_reactor.release()->start_call(); // gRPC callback deletes reactor in OnDone
}
} // namespace hpp_proto::grpc
