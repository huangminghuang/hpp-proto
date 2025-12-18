#pragma once

#include <grpcpp/grpcpp.h>
#include <grpcpp/impl/service_type.h>
#include <grpcpp/support/server_callback.h>

#if GRPC_CPP_VERSION_MINOR > 51
#include <grpcpp/impl/server_callback_handlers.h>
#else
#include <grpcpp/impl/codegen/server_callback_handlers.h>
#endif

#include <hpp_proto/grpc/serialization.hpp>

namespace hpp::proto::grpc {

using RpcType = ::grpc::internal::RpcMethod::RpcType;

template <typename Method>
class RequestToken {
  const ::grpc::ByteBuffer *req_buf_;

public:
  explicit RequestToken(const ::grpc::ByteBuffer *req_buf) : req_buf_(req_buf) {}
  ~RequestToken() = default;

  RequestToken(RequestToken &&) = default;
  RequestToken(const RequestToken &) = default;
  RequestToken &operator=(const RequestToken &) = default;
  RequestToken &operator=(RequestToken &&) = default;

  template <typename Traits>
  ::grpc::Status get(typename Method::template request_t<Traits> &request,
                     hpp::proto::concepts::is_option_type auto &&...option) const {
    return ::hpp::proto::grpc::read_binpb(request, *req_buf_, std::forward<decltype(option)>(option)...);
  }

  [[nodiscard]] const ::grpc::ByteBuffer *get() const { return req_buf_; }
};

class RpcRawCallbackServiceMethod : public ::grpc::internal::RpcServiceMethod {
public:
  RpcRawCallbackServiceMethod(const char *name, RpcType type, ::grpc::internal::MethodHandler *handler)
      : ::grpc::internal::RpcServiceMethod(name, type, handler) {
    SetServerApiType(::grpc::internal::RpcServiceMethod::ApiType::RAW_CALL_BACK);
  }
};

template <typename Method, RpcType Type = static_cast<RpcType>(Method::rpc_type)>
class ServerRPC;

// NOLINTBEGIN(portability-template-virtual-member-function)
template <typename Method>
class ServerRPC<Method, RpcType::NORMAL_RPC> : public ::grpc::ServerUnaryReactor {
  ::grpc::CallbackServerContext *context_;
  ::grpc::ByteBuffer *resp_buf_;

public:
  ServerRPC(::grpc::CallbackServerContext *context, ::grpc::ByteBuffer *resp_buf)
      : context_(context), resp_buf_(resp_buf) {}

  [[nodiscard]] ::grpc::CallbackServerContext &context() const { return *context_; }
  void finish(::grpc::Status s) { this->Finish(std::move(s)); }

  template <typename Traits>
  void finish(const typename Method::template response_t<Traits> &reply, ::grpc::Status s = ::grpc::Status{}) {
    auto result = ::hpp::proto::grpc::write_binpb(reply, *resp_buf_);
    this->Finish(result.ok() ? std::move(result) : std::move(s));
  }

  void finish(const ::grpc::ByteBuffer &response, ::grpc::Status s = ::grpc::Status{}) {
    *resp_buf_ = response;
    this->Finish(std::move(s));
  }
};

template <typename Method>
class ServerRPC<Method, RpcType::CLIENT_STREAMING> : public ::grpc::ServerReadReactor<::grpc::ByteBuffer> {
  ::grpc::CallbackServerContext *context_;
  ::grpc::ByteBuffer request_;
  ::grpc::ByteBuffer *resp_buf_;

protected:
  [[nodiscard]] const ::grpc::ByteBuffer *request_buf() const { return &request_; }

public:
  ServerRPC(::grpc::CallbackServerContext *context, ::grpc::ByteBuffer *resp_buf)
      : context_(context), resp_buf_(resp_buf) {}

  void start_read() { this->StartRead(&request_); }

  [[nodiscard]] ::grpc::CallbackServerContext &context() const { return *context_; }
  void finish(::grpc::Status s) { this->Finish(std::move(s)); }

  template <typename Traits>
  void finish(const typename Method::template response_t<Traits> &reply) {
    auto result = ::hpp::proto::grpc::write_binpb(reply, *resp_buf_);
    this->Finish(std::move(result));
  }

  void finish(const ::grpc::ByteBuffer &response, ::grpc::Status s = ::grpc::Status{}) {
    *resp_buf_ = response;
    this->Finish(std::move(s));
  }
};

template <typename Method>
class ServerRPC<Method, RpcType::SERVER_STREAMING> : public ::grpc::ServerWriteReactor<::grpc::ByteBuffer> {
  ::grpc::CallbackServerContext *context_;
  ::grpc::ByteBuffer response_;

public:
  ServerRPC(::grpc::CallbackServerContext *context, ::grpc::ByteBuffer *) : context_(context) {}

  [[nodiscard]] ::grpc::CallbackServerContext &context() const { return *context_; }
  void finish(::grpc::Status s) { this->Finish(std::move(s)); }

  template <typename Traits>
  void write(const typename Method::template response_t<Traits> &reply,
             ::grpc::WriteOptions options = ::grpc::WriteOptions{}) {
    auto result = ::hpp::proto::grpc::write_binpb(reply, response_);
    if (result.ok()) {
      this->StartWrite(&response_, options);
    } else {
      this->Finish(std::move(result));
    }
  }

  void write(const ::grpc::ByteBuffer &reply, ::grpc::WriteOptions options = ::grpc::WriteOptions{}) {
    response_ = reply;
    this->StartWrite(&response_, options);
  }

  template <typename Traits>
  void finish(const typename Method::template response_t<Traits> &reply,
              ::grpc::WriteOptions options = ::grpc::WriteOptions{}, ::grpc::Status s = ::grpc::Status{}) {
    auto result = ::hpp::proto::grpc::write_binpb(reply, response_);
    if (result.ok()) {
      this->StartWriteAndFinish(&response_, options, std::move(s));
    } else {
      this->Finish(std::move(result));
    }
  }

  void finish(const ::grpc::ByteBuffer &reply, ::grpc::WriteOptions options = ::grpc::WriteOptions{},
              ::grpc::Status s = ::grpc::Status{}) {
    response_ = reply;
    this->StartWriteAndFinish(&response_, options, std::move(s));
  }
};

template <typename Method>
class ServerRPC<Method, RpcType::BIDI_STREAMING>
    : public ::grpc::ServerBidiReactor<::grpc::ByteBuffer, ::grpc::ByteBuffer> {
  ::grpc::CallbackServerContext *context_;
  ::grpc::ByteBuffer request_;
  ::grpc::ByteBuffer response_;

protected:
  [[nodiscard]] const ::grpc::ByteBuffer *request_buf() const { return &request_; }

public:
  ServerRPC(::grpc::CallbackServerContext *context, ::grpc::ByteBuffer *) : context_(context) {}

  void start_read() { this->StartRead(&request_); }

  [[nodiscard]] ::grpc::CallbackServerContext &context() const { return *context_; }
  void finish(::grpc::Status s) { this->Finish(std::move(s)); }

  template <typename Traits>
  void write(const typename Method::template response_t<Traits> &reply,
             ::grpc::WriteOptions options = ::grpc::WriteOptions{}) {
    auto result = ::hpp::proto::grpc::write_binpb(reply, response_);
    if (result.ok()) {
      this->StartWrite(&response_, options);
    } else {
      this->Finish(std::move(result));
    }
  }

  void write(const ::grpc::ByteBuffer &reply, ::grpc::WriteOptions options = ::grpc::WriteOptions{}) {
    response_ = reply;
    this->StartWrite(&response_, options);
  }

  template <typename Traits>
  void finish(const typename Method::template response_t<Traits> &reply,
              ::grpc::WriteOptions options = ::grpc::WriteOptions{}, ::grpc::Status s = ::grpc::Status{}) {
    auto result = ::hpp::proto::grpc::write_binpb(reply, response_);
    if (result.ok()) {
      this->StartWriteAndFinish(&response_, options, std::move(s));
    } else {
      this->Finish(std::move(result));
    }
  }

  void finish(const ::grpc::ByteBuffer &reply, ::grpc::WriteOptions options = ::grpc::WriteOptions{},
              ::grpc::Status s = ::grpc::Status{}) {
    response_ = reply;
    this->StartWriteAndFinish(&response_, options, std::move(s));
  }
};
// NOLINTEND(portability-template-virtual-member-function)

template <typename Method, typename RpcHandler>
class BasicServerReactor : public ServerRPC<Method> {
protected:
  using rpc_t = ServerRPC<Method>;
  RpcHandler handler_;

  void on_write_done(bool ok)
    requires Method::server_streaming
  {
    if (ok) {
      handler_.on_write_ok(*this);
    } else {
      if constexpr (requires { handler_.on_write_error(); }) {
        handler_.on_write_error();
      }
      // Client cancelled it
      this->Finish(::grpc::Status::CANCELLED);
    }
  }

  void on_read_done(bool ok)
    requires Method::client_streaming
  {
    if (ok) {
      handler_.on_read_ok(*this, RequestToken<Method>{this->request_buf()});
    } else {
      // Client cancelled it
      if constexpr (requires { handler_.on_read_error(); }) {
        handler_.on_read_error();
      }
      this->Finish(::grpc::Status::CANCELLED);
      return;
    }
  }

public:
  template <typename Service>
    requires(!Method::client_streaming)
  BasicServerReactor(::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *req_buf,
                     ::grpc::ByteBuffer *resp_buf, Service &service)
      : rpc_t(context, resp_buf), handler_(service, *this, RequestToken<Method>{req_buf}) {}

  template <typename Service>
    requires Method::client_streaming
  BasicServerReactor(::grpc::CallbackServerContext *context, ::grpc::ByteBuffer *resp_buf, Service &service)
      : rpc_t(context, resp_buf), handler_(service, *this) {}

  void OnDone() override {
    if constexpr (requires { handler_.on_done(); }) {
      handler_.on_done();
    }
    delete this;
  }

  void OnSendInitialMetadataDone(bool ok) override {
    if constexpr (requires { handler_.on_send_initial_metadata_done(ok); }) {
      handler_.on_send_initial_metadata_done(ok);
    }
  }

  void OnCancel() override {
    if constexpr (requires { handler_.on_cancel(); }) {
      handler_.on_cancel();
    }
  }
};

template <typename Method, typename RpcHandler, RpcType Type = static_cast<RpcType>(Method::rpc_type)>
class ServerReactor : public BasicServerReactor<Method, RpcHandler> {
public:
  using BasicServerReactor<Method, RpcHandler>::BasicServerReactor;

  static ::grpc::internal::MethodHandler *grpc_method_handler(auto &service) {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory,portability-template-virtual-member-function)
    return new ::grpc::internal::CallbackUnaryHandler<::grpc::ByteBuffer, ::grpc::ByteBuffer>(
        [&service](::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *request,
                   ::grpc::ByteBuffer *response) {
          return new ServerReactor(context, request, response, service); // NOLINT(cppcoreguidelines-owning-memory)
        });
  }
};

template <typename Method, typename RpcHandler>
class ServerReactor<Method, RpcHandler, RpcType::CLIENT_STREAMING> : public BasicServerReactor<Method, RpcHandler> {
public:
  using BasicServerReactor<Method, RpcHandler>::BasicServerReactor;
  void OnReadDone(bool ok) override { this->on_read_done(ok); }

  static ::grpc::internal::MethodHandler *grpc_method_handler(auto &service) {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory, portability-template-virtual-member-function)
    return new ::grpc::internal::CallbackClientStreamingHandler<::grpc::ByteBuffer, ::grpc::ByteBuffer>(
        [&service](::grpc::CallbackServerContext *context, ::grpc::ByteBuffer *response) {
          return new ServerReactor(context, response, service); // NOLINT(cppcoreguidelines-owning-memory)
        });
  }
};

template <typename Method, typename RpcHandler>
class ServerReactor<Method, RpcHandler, RpcType::SERVER_STREAMING> : public BasicServerReactor<Method, RpcHandler> {
public:
  using BasicServerReactor<Method, RpcHandler>::BasicServerReactor;
  void OnWriteDone(bool ok) override { this->on_write_done(ok); }

  static ::grpc::internal::MethodHandler *grpc_method_handler(auto &service) {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory, portability-template-virtual-member-function)
    return new ::grpc::internal::CallbackServerStreamingHandler<::grpc::ByteBuffer, ::grpc::ByteBuffer>(
        [&service](::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *request) {
          return new ServerReactor(context, request, nullptr, service); // NOLINT(cppcoreguidelines-owning-memory)
        });
  }
};

template <typename Method, typename RpcHandler>
class ServerReactor<Method, RpcHandler, RpcType::BIDI_STREAMING> : public BasicServerReactor<Method, RpcHandler> {
public:
  using BasicServerReactor<Method, RpcHandler>::BasicServerReactor;
  void OnReadDone(bool ok) override { this->on_read_done(ok); }
  void OnWriteDone(bool ok) override { this->on_write_done(ok); }

  static ::grpc::internal::MethodHandler *grpc_method_handler(auto &service) {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory, portability-template-virtual-member-function)
    return new ::grpc::internal::CallbackBidiHandler<::grpc::ByteBuffer, ::grpc::ByteBuffer>(
        [&service](::grpc::CallbackServerContext *context) {
          return new ServerReactor(context, nullptr, service); // NOLINT(cppcoreguidelines-owning-memory)
        });
  }
};

template <typename Derived, typename Methods>
class CallbackService : public ::grpc::Service {

  template <typename Method>
  void add_method(Method method) {
    if constexpr (requires { std::declval<Derived>().handle(method); }) {
      using rpc_handler_t = decltype(std::declval<Derived>().handle(method));
      auto *handler = ServerReactor<Method, rpc_handler_t>::grpc_method_handler(static_cast<Derived &>(*this));
      this->AddMethod(new RpcRawCallbackServiceMethod( // NOLINT(cppcoreguidelines-owning-memory)
          method.method_name, static_cast<RpcType>(method.rpc_type), handler));
    }
  }

public:
  CallbackService() {
    std::apply([&](auto &&...args) { ((add_method(args)), ...); }, Methods{});
  }
};
} // namespace hpp::proto::grpc
