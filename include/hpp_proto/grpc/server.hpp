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

class RpcRawCallbackServiceMethod : public ::grpc::internal::RpcServiceMethod {
public:
  RpcRawCallbackServiceMethod(const char *name, RpcType type, ::grpc::internal::MethodHandler *handler)
      : ::grpc::internal::RpcServiceMethod(name, type, handler) {
    SetServerApiType(::grpc::internal::RpcServiceMethod::ApiType::RAW_CALL_BACK);
  }
};

template <typename Method, RpcType Type = static_cast<RpcType>(Method::rpc_type)>
class ServerRPC;

template <typename Method>
class ServerRPC<Method, RpcType::NORMAL_RPC> : public ::grpc::ServerUnaryReactor {
  ::grpc::CallbackServerContext *context_;
  const ::grpc::ByteBuffer *req_buf_;
  ::grpc::ByteBuffer *resp_buf_;

public:
  ServerRPC(::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *req_buf, ::grpc::ByteBuffer *resp_buf)
      : context_(context), req_buf_(req_buf), resp_buf_(resp_buf) {
    std::cerr << "NORMAL_RPC ServerRPC created\n";
  }

  template <typename Traits>
  bool get_request(typename Method::template request_t<Traits> &request,
                   hpp::proto::concepts::is_option_type auto &&...option) {
    if (auto status = ::hpp::proto::grpc::read_proto(request, *req_buf_, std::forward<decltype(option)>(option)...);
        !status.ok()) {
      this->Finish(status);
      return false;
    }
    return true;
  }

  ::grpc::CallbackServerContext &context() const { return *context_; }
  void finish(::grpc::Status s) { this->Finish(s); }

  template <typename Traits>
  void finish(const typename Method::template response_t<Traits> &reply) {
    auto result = ::hpp::proto::grpc::write_proto(reply, *resp_buf_);
    this->Finish(result);
  }
};

template <typename Method>
class ServerRPC<Method, RpcType::CLIENT_STREAMING> : public ::grpc::ServerReadReactor<::grpc::ByteBuffer> {
  ::grpc::CallbackServerContext *context_;
  ::grpc::ByteBuffer request_;
  ::grpc::ByteBuffer *resp_buf_;

#ifndef NDEBUG
protected:
  std::atomic<bool> has_request_;
#endif

public:
  ServerRPC(::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *, ::grpc::ByteBuffer *resp_buf)
      : context_(context), resp_buf_(resp_buf) {}

  void start_read() {
#ifndef NDEBUG
    has_request_ = false; // get_request should only be called inside on_read_ok()
#endif
    this->StartRead(&request_);
  }

  template <typename Traits>
  bool get_request(typename Method::template request_t<Traits> &request,
                   hpp::proto::concepts::is_option_type auto &&...option) {
#ifndef NDEBUG
    assert(has_request_); // get_request should only be called inside on_read_ok()
#endif
    if (auto status = ::hpp::proto::grpc::read_proto(request, request_, std::forward<decltype(option)>(option)...);
        !status.ok()) {
      this->Finish(status);
      return false;
    }
    return true;
  }

  ::grpc::CallbackServerContext &context() const { return *context_; }
  void finish(::grpc::Status s) { this->Finish(s); }

  template <typename Traits>
  void finish(const typename Method::template response_t<Traits> &reply) {
    auto result = ::hpp::proto::grpc::write_proto(reply, *resp_buf_);
    this->finish(result);
  }
};

template <typename Method>
class ServerRPC<Method, RpcType::SERVER_STREAMING> : public ::grpc::ServerWriteReactor<::grpc::ByteBuffer> {
  ::grpc::CallbackServerContext *context_;
  const ::grpc::ByteBuffer *req_buf_;
  ::grpc::ByteBuffer response_;

public:
  ServerRPC(::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *req_buf, ::grpc::ByteBuffer *)
      : context_(context), req_buf_(req_buf) {}

  template <typename Traits>
  bool get_request(typename Method::template request_t<Traits> &request,
                   hpp::proto::concepts::is_option_type auto &&...option) {
    if (auto status = ::hpp::proto::grpc::read_proto(request, *req_buf_, std::forward<decltype(option)>(option)...);
        !status.ok()) {
      this->Finish(status);
      return false;
    }
    return true;
  }

  ::grpc::CallbackServerContext &context() const { return *context_; }
  void finish(::grpc::Status s) { this->Finish(s); }

  template <typename Traits>
  void write(const typename Method::template response_t<Traits> &reply) {
    ::grpc::WriteOptions options = ::grpc::WriteOptions{};
    auto result = ::hpp::proto::grpc::write_proto(reply, response_);
    if (result.ok()) {
      this->StartWrite(&response_);
    } else {
      finish(result);
    }
  }

  template <typename Traits>
  void finish(const typename Method::template response_t<Traits> &reply,
              ::grpc::WriteOptions options = ::grpc::WriteOptions{}, ::grpc::Status s = ::grpc::Status{}) {
    auto result = ::hpp::proto::grpc::write_proto(reply, response_);
    if (result.ok()) {
      this->StartWriteAndFinish(&response_, options, s);
    } else {
      finish(result);
    }
  }
};

template <typename Method>
class ServerRPC<Method, RpcType::BIDI_STREAMING>
    : public ::grpc::ServerBidiReactor<::grpc::ByteBuffer, ::grpc::ByteBuffer> {
  ::grpc::CallbackServerContext *context_;
  ::grpc::ByteBuffer request_;
  ::grpc::ByteBuffer response_;
#ifndef NDEBUG
protected:
  std::atomic<bool> has_request_;
#endif
public:
  ServerRPC(::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *, ::grpc::ByteBuffer *)
      : context_(context) {}

  void start_read() {
#ifndef NDEBUG
    has_request_ = false; // get_request should only be called inside on_read_ok()
#endif
    this->StartRead(&request_);
  }

  template <typename Traits>
  bool get_request(typename Method::template request_t<Traits> &request,
                   hpp::proto::concepts::is_option_type auto &&...option) {
    assert(has_request_); // get_request should only be called inside on_read_ok()
    if (auto status = ::hpp::proto::grpc::read_proto(request, request_, std::forward<decltype(option)>(option)...);
        !status.ok()) {
      this->Finish(status);
      return false;
    }
    return true;
  }

  ::grpc::CallbackServerContext &context() const { return *context_; }
  void finish(::grpc::Status s) { this->Finish(s); }

  template <typename Traits>
  void write(const typename Method::template response_t<Traits> &reply,
             ::grpc::WriteOptions options = ::grpc::WriteOptions{}) {
    auto result = ::hpp::proto::grpc::write_proto(reply, response_);
    if (result.ok()) {
      this->StartWrite(&response_);
    } else {
      finish(result);
    }
  }

  template <typename Traits>
  void finish(const typename Method::template response_t<Traits> &reply,
              ::grpc::WriteOptions options = ::grpc::WriteOptions{}, ::grpc::Status s = ::grpc::Status{}) {
    auto result = ::hpp::proto::grpc::write_proto(reply, response_);
    if (result.ok()) {
      this->StartWriteAndFinish(&response_, options, s);
    } else {
      finish(result);
    }
  }
};

template <typename Method, template <typename> typename RpcHandlerTemplate>
class BasicServerReactor : public ServerRPC<Method> {
protected:
  using rpc_t = ServerRPC<Method>;
  RpcHandlerTemplate<Method> handler_;

  void on_write_done(bool ok)
    requires Method::server_streaming
  {
    if constexpr (requires { handler_.on_write_done(ok, *this); }) {
      handler_.on_write_done(ok, *this);
    } else if constexpr (requires { handler_.on_write_ok(*this); }) {
      if (ok) {
        handler_.on_write_ok(*this);
      } else {
        // Client cancelled it
        this->Finish(::grpc::Status::CANCELLED);
      }
    }
  }

  void on_read_done(bool ok)
    requires Method::client_streaming
  {
#ifndef NDEBUG
    this->has_request_ = ok;
#endif
    if constexpr (requires { handler_.on_read_done(ok, *this); }) {
      handler_.on_read_done(*this, ok);
    } else if (ok) {
      handler_.on_read_ok(*this);
    } else {
      // Client cancelled it
      this->Finish(::grpc::Status::CANCELLED);
      return;
    }
  }

public:
  using handler_t = RpcHandlerTemplate<Method>;
  template <typename Service>
  BasicServerReactor(::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *req_buf,
                     ::grpc::ByteBuffer *resp_buf, Service &service)
      : rpc_t(context, req_buf, resp_buf), handler_(service, *this) {}

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

template <typename Method, template <typename> typename RpcHandlerTemplate,
          RpcType Type = static_cast<RpcType>(Method::rpc_type)>
class ServerReactor : public BasicServerReactor<Method, RpcHandlerTemplate> {
public:
  using BasicServerReactor<Method, RpcHandlerTemplate>::BasicServerReactor;

  static ::grpc::internal::MethodHandler *grpc_method_handler(auto &service) {
    std::cerr << "creating CallbackUnaryHandler\n";
    return new ::grpc::internal::CallbackUnaryHandler<::grpc::ByteBuffer, ::grpc::ByteBuffer>(
        [&service](::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *request,
                   ::grpc::ByteBuffer *response) { return new ServerReactor(context, request, response, service); });
  }
};

template <typename Method, template <typename> typename RpcHandlerTemplate>
class ServerReactor<Method, RpcHandlerTemplate, RpcType::CLIENT_STREAMING>
    : public BasicServerReactor<Method, RpcHandlerTemplate> {
public:
  using BasicServerReactor<Method, RpcHandlerTemplate>::BasicServerReactor;
  void OnReadDone(bool ok) override { this->on_read_done(ok); }

  static ::grpc::internal::MethodHandler *grpc_method_handler(auto &service) {
    return new ::grpc::internal::CallbackClientStreamingHandler<::grpc::ByteBuffer, ::grpc::ByteBuffer>(
        [&service](::grpc::CallbackServerContext *context, ::grpc::ByteBuffer *response) {
          return new ServerReactor(context, nullptr, response, service);
        });
  }
};

template <typename Method, template <typename> typename RpcHandlerTemplate>
class ServerReactor<Method, RpcHandlerTemplate, RpcType::SERVER_STREAMING>
    : public BasicServerReactor<Method, RpcHandlerTemplate> {
public:
  using BasicServerReactor<Method, RpcHandlerTemplate>::BasicServerReactor;
  void OnWriteDone(bool ok) override { this->on_write_done(ok); }

  static ::grpc::internal::MethodHandler *grpc_method_handler(auto &service) {
    std::cerr << "creating CallbackServerStreamingHandler\n";
    return new ::grpc::internal::CallbackServerStreamingHandler<::grpc::ByteBuffer, ::grpc::ByteBuffer>(
        [&service](::grpc::CallbackServerContext *context, const ::grpc::ByteBuffer *request) {
          return new ServerReactor(context, request, nullptr, service);
        });
  }
};

template <typename Method, template <typename> typename RpcHandlerTemplate>
class ServerReactor<Method, RpcHandlerTemplate, RpcType::BIDI_STREAMING>
    : public BasicServerReactor<Method, RpcHandlerTemplate> {
public:
  using BasicServerReactor<Method, RpcHandlerTemplate>::BasicServerReactor;
  void OnReadDone(bool ok) override { this->on_read_done(ok); }
  void OnWriteDone(bool ok) override { this->on_write_done(ok); }

  static ::grpc::internal::MethodHandler *grpc_method_handler(auto &service) {
    return new ::grpc::internal::CallbackBidiHandler<::grpc::ByteBuffer, ::grpc::ByteBuffer>(
        [&service](::grpc::CallbackServerContext *context) {
          return new ServerReactor(context, nullptr, nullptr, service);
        });
  }
};

template <typename Derived, typename Methods>
class CallbackService : public ::grpc::Service {

  template <typename Method>
  void add_method(Method method) {
    std::cerr << "add method\n";
    using handler_t = Derived::template rpc_handler<Method>;
    // check if the rpc_handler instantiation has the right constructor
    if constexpr (std::constructible_from<handler_t, Derived &, ServerRPC<Method> &>) {
      auto *handler =
          ServerReactor<Method, Derived::template rpc_handler>::grpc_method_handler(static_cast<Derived &>(*this));
      this->AddMethod(new RpcRawCallbackServiceMethod(
          method.method_name, static_cast<::grpc::internal::RpcMethod::RpcType>(method.rpc_type), handler));
    }
  }

public:
  CallbackService() {
    std::apply([&](auto &&...args) { ((add_method(args)), ...); }, Methods{});
  }
};
} // namespace hpp::proto::grpc