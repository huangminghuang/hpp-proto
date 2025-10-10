#include <google/protobuf/duration.glz.hpp>
#include <google/protobuf/timestamp.glz.hpp>
#include <hpp_proto/field_mask_codec.hpp>
#include <hpp_proto/json_serializer.hpp>

#include <hpp_proto/dynamic_message.hpp>

namespace glz {

struct generic_message_json_serializer {
  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    bool is_wellknown_type = (value.descriptor().wellknown != hpp::proto::wellknown_types_t::NONE);
    const bool dump_brace = !has_opening_handled(Opts) && !value.descriptor().is_map_entry() && !is_wellknown_type;

    if (dump_brace) {
      glz::dump<'{'>(b, ix);
      if constexpr (Opts.prettify) {
        ctx.indentation_level += Opts.indentation_width;
        glz::dump<'\n'>(b, ix);
        glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
      }
    }

    constexpr auto field_opts = glz::opening_handled_off<Opts>();
    const char *separator = nullptr;

    for (auto field : value.fields()) {
      if (!field.has_value()) {
        continue;
      }

      if (separator != nullptr) {
        // not the first field in a message, output the separator
        glz::dump(separator, b, ix);
        if (Opts.prettify) {
          glz::dump<'\n'>(b, ix);
          glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
        }
      }

      if (!value.descriptor().is_map_entry()) {
        if (!is_wellknown_type) {
          auto json_name = field.descriptor().proto().json_name;
          glz::serialize<glz::JSON>::op<field_opts>(json_name, ctx, b, ix);
          glz::dump<':'>(b, ix);
          if constexpr (Opts.prettify) {
            glz::dump<' '>(b, ix);
          }
        }
        field.visit([&](auto v) { to<JSON, decltype(v)>::template op<field_opts>(v, ctx, b, ix); });
        separator = ",";
      } else {
        if (separator == nullptr) {
          bool need_extra_quote = (field.field_kind() == hpp::proto::KIND_BOOL);
          if (need_extra_quote) {
            glz::dump<'"'>(b, ix);
          }
          field.visit([&](auto v) {
            to<JSON, decltype(v)>::template op<opt_true<field_opts, &opts::quoted_num>>(v, ctx, b, ix);
          });
          if (need_extra_quote) {
            glz::dump<'"'>(b, ix);
          }
        } else {
          field.visit([&](auto v) { to<JSON, decltype(v)>::template op<field_opts>(v, ctx, b, ix); });
        }

        separator = ":";
      }
    }

    if (dump_brace) {
      if constexpr (Opts.prettify) {
        ctx.indentation_level -= Opts.indentation_width;
        glz::dump<'\n'>(b, ix);
        glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
      }
      glz::dump<'}'>(b, ix);
    }
  }
};

struct any_message_json_serializer {
  template <auto Opts>
  static void any_value_to_json(const hpp::proto::message_descriptor_t &descriptor, std::span<const std::byte> value,
                                is_context auto &ctx, auto &b, auto &ix) noexcept;

  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    auto *type_url_desc = value.field_descriptor_by_number(1);
    auto *value_desc = value.field_descriptor_by_number(2);
    if (type_url_desc == nullptr || value_desc == nullptr) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Any message descriptor";
      return;
    }
    auto type_url_field = value.const_field(*type_url_desc).to<hpp::proto::string_field_cref>();
    auto value_field = value.const_field(*value_desc).to<hpp::proto::bytes_field_cref>();
    if (!type_url_field.has_value() || !value_field.has_value()) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Any message descriptor";
      return;
    }
    std::string_view type_url = type_url_field.value().value();
    const auto &pool = value.descriptor().parent_file()->descriptor_pool();

    auto slash_pos = type_url.find('/');
    if (slash_pos >= type_url.size() - 1) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "invalid type_url in google.protobuf.Any message";
      return;
    }

    auto *value_descriptor = pool.get_message_descriptor(type_url.substr(slash_pos + 1));
    if (!value_descriptor) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "unresolvable type_url in google.protobuf.Any message";
      return;
    }

    glz::dump<"\"@type\":">(b, ix);
    if constexpr (Opts.prettify) {
      glz::dump<' '>(b, ix);
    }

    glz::serialize<glz::JSON>::op<Opts>(type_url, ctx, b, ix);
    glz::dump<','>(b, ix);
    if (Opts.prettify) {
      glz::dump<'\n'>(b, ix);
      glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
    }

    const bool is_wellknown = value_descriptor->wellknown != hpp::proto::wellknown_types_t::NONE;
    if (is_wellknown) {
      glz::dump<R"("value":)">(b, ix);
      if constexpr (Opts.prettify) {
        glz::dump<' '>(b, ix);
      }

      any_value_to_json<Opts>(*value_descriptor, value_field->value(), ctx, b, ix);

      if constexpr (Opts.prettify) {
        ctx.indentation_level -= Opts.indentation_width;
        glz::dump<'\n'>(b, ix);
        glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
      }
      glz::dump<'}'>(b, ix);
    } else {
      any_value_to_json<glz::opening_handled<Opts>()>(*value_descriptor, value_field->value(), ctx, b, ix);
    }
  }
};
struct timestamp_message_json_serializer {

  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    auto *seconds_desc = value.field_descriptor_by_number(1);
    auto *nanos_desc = value.field_descriptor_by_number(2);
    if (seconds_desc == nullptr || nanos_desc == nullptr) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Timestamp message descriptor";
      return;
    }
    auto seconds_field = value.const_field(*seconds_desc).to<hpp::proto::int64_field_cref>();
    auto nanos_field = value.const_field(*nanos_desc).to<hpp::proto::int32_field_cref>();
    if (!seconds_field.has_value() || !nanos_field.has_value()) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Timestamp message descriptor";
      return;
    }
    google::protobuf::Timestamp v{seconds_field->value(), nanos_field->value()};
    to<JSON, google::protobuf::Timestamp<>>::template op<Opts>(v, ctx, b, ix);
  }
};

struct duration_message_json_serializer {
  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    auto *seconds_desc = value.field_descriptor_by_number(1);
    auto *nanos_desc = value.field_descriptor_by_number(2);
    if (seconds_desc == nullptr || nanos_desc == nullptr) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Duration message descriptor";
      return;
    }
    auto seconds_field = value.const_field(*seconds_desc).to<hpp::proto::int64_field_cref>();
    auto nanos_field = value.const_field(*nanos_desc).to<hpp::proto::int32_field_cref>();
    if (!seconds_field.has_value() || !nanos_field.has_value()) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Duration message descriptor";
      return;
    }
    google::protobuf::Duration v{seconds_field->value(), nanos_field->value()};
    to<JSON, google::protobuf::Duration<>>::template op<Opts>(v, ctx, b, ix);
  }
};

struct field_mask_message_json_serializer {
  struct FieldMask {
    using json_code = hpp::proto::field_mask_codec;
    std::span<const std::string_view> paths;
  };

  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    auto *paths_desc = value.field_descriptor_by_number(1);
    if (paths_desc == nullptr) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.FieldMask message descriptor";
      return;
    }
    auto paths_field = value.const_field(*paths_desc).to<hpp::proto::repeated_string_field_cref>();
    if (paths_field.has_value()) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.FieldMask message descriptor";
      return;
    }

    to<JSON, FieldMask>::template op<Opts>(FieldMask{.paths = {paths_field->data(), paths_field->size()}}, ctx, b, ix);
  }
};

template <typename T, hpp::proto::field_kind_t Kind>
struct to<JSON, hpp::proto::scalar_field_cref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::scalar_field_cref<T, Kind> &value, auto &&...args) noexcept {

    if (value.has_value()) {
      using value_type = hpp::proto::scalar_field_cref<T, Kind>::value_type;
      if constexpr (!std::same_as<T, double> && sizeof(T) == 8) {
        to<JSON, value_type>::template op<opt_true<Opts, &opts::quoted_num>>(*value,
                                                                             std::forward<decltype(args)>(args)...);
      } else {
        to<JSON, value_type>::template op<Opts>(*value, std::forward<decltype(args)>(args)...);
      }
    }
  }
};

template <typename T, hpp::proto::field_kind_t Kind>
struct to<JSON, hpp::proto::repeated_scalar_field_cref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::repeated_scalar_field_cref<T, Kind> &value,
                                   auto &&...args) noexcept {
    if (!value.empty()) {
      auto range = std::span{value.data(), value.size()};
      if constexpr (!std::same_as<T, double> && sizeof(T) == 8) {
        to<JSON, decltype(range)>::template op<opt_true<Opts, &opts::quoted_num>>(
            range, std::forward<decltype(args)>(args)...);
      } else {
        to<JSON, decltype(range)>::template op<Opts>(range, std::forward<decltype(args)>(args)...);
      }
    }
  }
};

template <>
struct to<JSON, hpp::proto::enum_value_cref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::enum_value_cref &value, is_context auto &ctx, auto &b,
                                   auto &ix) noexcept {
    const char *name = value.name();
    if (name != nullptr) {
      dump<'"'>(b, ix);
      dump(name, b, ix);
      dump<'"'>(b, ix);
    } else {
      serialize<JSON>::op<Opts>(value.number(), ctx, b, ix);
    }
  }
};

template <>
struct to<JSON, hpp::proto::message_value_cref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::message_value_cref &value, auto &&...args) noexcept {
    using enum hpp::proto::wellknown_types_t;
    switch (value.descriptor().wellknown) {
    case ANY:
      any_message_json_serializer::template to_json<Opts>(value, std::forward<decltype(args)>(args)...);
      break;
    case TIMESTAMP:
      timestamp_message_json_serializer::template to_json<Opts>(value, std::forward<decltype(args)>(args)...);
      break;
    case DURATION:
      duration_message_json_serializer::template to_json<Opts>(value, std::forward<decltype(args)>(args)...);
      break;
    case FIELDMASK:
      field_mask_message_json_serializer::template to_json<Opts>(value, std::forward<decltype(args)>(args)...);
      break;
    default:
      generic_message_json_serializer::template to_json<Opts>(value, std::forward<decltype(args)>(args)...);
    }
  }
};

template <>
struct to<JSON, hpp::proto::message_value_mref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::message_value_mref &value, auto &&...args) noexcept {
    to<JSON, hpp::proto::message_value_cref>::template op<Opts>(value.cref(), std::forward<decltype(args)>(args)...);
  }
};

template <>
struct to<JSON, hpp::proto::repeated_message_field_cref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto const &value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    if (value.descriptor().is_map_entry()) {
      glz::dump<'{'>(b, ix);
    } else {
      glz::dump<'['>(b, ix);
    }
    if constexpr (Opts.prettify) {
      ctx.indentation_level += Opts.indentation_width;
      glz::dump<'\n'>(b, ix);
      glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
    }

    char separator = '\0';

    for (auto entry : value) {
      if (separator) {
        // not the first field in a message, output the separator
        glz::dump<','>(b, ix);
        if (Opts.prettify) {
          glz::dump<'\n'>(b, ix);
          glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
        }
      }

      to<JSON, hpp::proto::message_value_cref>::template op<Opts>(entry, ctx, b, ix);
      separator = ',';
    }

    if constexpr (Opts.prettify) {
      ctx.indentation_level -= Opts.indentation_width;
      glz::dump<'\n'>(b, ix);
      glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
    }
    if (value.descriptor().is_map_entry()) {
      glz::dump<'}'>(b, ix);
    } else {
      glz::dump<']'>(b, ix);
    }
  }
};

template <auto Opts>
void any_message_json_serializer::any_value_to_json(const hpp::proto::message_descriptor_t &descriptor,
                                                    std::span<const std::byte> value, is_context auto &ctx, auto &b,
                                                    auto &ix) noexcept {
  std::pmr::monotonic_buffer_resource memory_resource;
  hpp::proto::message_value_mref message{descriptor, memory_resource};
  auto r = hpp::proto::read_proto(message, value);
  if (!r.ok()) {
    ctx.error = error_code::invalid_get;
    ctx.custom_error_message = "unable to deserialize value in google.protobuf.Any message";
    return;
  }
  to<JSON, hpp::proto::message_value_cref>::template op<Opts>(message, ctx, b, ix);
}

} // namespace glz