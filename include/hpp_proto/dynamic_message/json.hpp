#pragma once
#include <google/protobuf/duration.glz.hpp>
#include <google/protobuf/field_mask.glz.hpp>
#include <google/protobuf/struct.msg.hpp>
#include <google/protobuf/timestamp.glz.hpp>
#include <hpp_proto/binpb/utf8.hpp>
#include <hpp_proto/dynamic_message/binpb.hpp>
#include <hpp_proto/dynamic_message/factory.hpp>
#include <hpp_proto/dynamic_message/field_visit.hpp>
#include <hpp_proto/json.hpp>
#include <iterator>

namespace glz {

namespace util {

template <auto Opts>
void dump_opening_brace(is_context auto &ctx, auto &b, auto &ix) {
  glz::dump<'{'>(b, ix);
  if constexpr (Opts.prettify) {
    ctx.depth += glz::check_indentation_width(Opts);
    glz::dump<'\n'>(b, ix);
    glz::dumpn(glz::check_indentation_char(Opts), ctx.depth, b, ix);
  }
}

template <auto Opts>
void dump_closing_brace(is_context auto &ctx, auto &b, auto &ix) {
  if constexpr (Opts.prettify) {
    ctx.depth -= glz::check_indentation_width(Opts);
    glz::dump<'\n'>(b, ix);
    glz::dumpn(glz::check_indentation_char(Opts), ctx.depth, b, ix);
  }
  glz::dump<'}'>(b, ix);
}

template <auto Opts>
void dump_field_separator(bool is_map_entry, is_context auto &ctx, auto &b, auto &ix, char separator) {
  glz::dump(separator, b, ix);
  if constexpr (Opts.prettify) {
    if (!is_map_entry) {
      glz::dump<'\n'>(b, ix);
      glz::dumpn(glz::check_indentation_char(Opts), ctx.depth, b, ix);
    } else {
      glz::dump<' '>(b, ix);
    }
  }
}

} // namespace util

namespace concepts {
template <typename T>
concept string_mref =
    (std::same_as<T, ::hpp_proto::string_field_mref> || std::same_as<T, ::hpp_proto::string_value_mref>);

template <typename T>
concept bytes_mref = (std::same_as<T, ::hpp_proto::bytes_field_mref> || std::same_as<T, ::hpp_proto::bytes_value_mref>);

template <typename T>
concept repeated_mref = requires {
  requires T::is_mutable;
  requires T::field_kind >= ::hpp_proto::field_kind_t::KIND_REPEATED_DOUBLE;
};

template <typename T>
concept requires_custom_read = string_mref<T> || bytes_mref<T> || repeated_mref<T>;

template <typename T>
concept map_key_mref = std::same_as<T, ::hpp_proto::string_field_mref> ||
                       (std::same_as<T, ::hpp_proto::scalar_field_mref<typename T::encode_type, T::field_kind>> &&
                        !std::is_floating_point_v<typename T::value_type>);

} // namespace concepts

template <>
struct to<JSON, hpp_proto::field_cref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(hpp_proto::field_cref value, is_context auto &ctx, auto &b, auto &ix) {
    if (value.has_value()) {
      value.visit([&](auto v) {
        using T = std::remove_cvref_t<decltype(v)>;
        to<JSON, T>::template op<Opts>(v, ctx, b, ix);
      });
    }
  }
};

template <>
struct from<JSON, hpp_proto::field_mref> {
  template <auto Options>
  static void op(hpp_proto::field_mref value, is_context auto &ctx, auto &it, auto &end) {
    if (!util::parse_null<Options>(value, ctx, it, end)) {
      value.visit([&](auto v) {
        using T = std::remove_cvref_t<decltype(v)>;
        from<JSON, T>::template op<Options>(v, ctx, it, end);
      });
    }
  }
};

struct generic_message_json_serializer {
  template <auto Opts>
  static void serialize_regular_field(hpp_proto::field_cref field, is_context auto &ctx, auto &b, auto &ix) {
    constexpr auto field_opts = glz::opening_handled_off<Opts>();
    auto json_name = field.descriptor().proto().json_name;
    to<glz::JSON, std::string_view>::template op<field_opts>(json_name, ctx, b, ix);
    glz::dump<':'>(b, ix);
    if constexpr (Opts.prettify) {
      glz::dump<' '>(b, ix);
    }

    field.visit([&](auto v) { to<JSON, decltype(v)>::template op<Opts>(v, ctx, b, ix); });
  }

  template <auto Opts>
  static void serialize_map_entry_field(hpp_proto::field_cref field, bool is_first_field, is_context auto &ctx, auto &b,
                                        auto &ix) {
    constexpr auto field_opts = glz::opening_handled_off<Opts>();
    if (is_first_field) {
      bool need_extra_quote = (field.field_kind() == hpp_proto::KIND_BOOL);
      if (need_extra_quote) {
        glz::dump<'"'>(b, ix);
      }
      field.visit([&](auto v) {
        to<JSON, decltype(v)>::template op<opt_true<field_opts, quoted_num_opt_tag{}>>(v, ctx, b, ix);
      });
      if (need_extra_quote) {
        glz::dump<'"'>(b, ix);
      }
    } else {
      field.visit([&](auto v) { to<JSON, decltype(v)>::template op<field_opts>(v, ctx, b, ix); });
    }
  }

  template <auto Opts>
  static void to_json(hpp_proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
    bool is_wellknown_type = (value.descriptor().wellknown != hpp_proto::wellknown_types_t::NONE);
    bool is_map_entry = value.descriptor().is_map_entry();
    const bool dump_brace = !check_opening_handled(Opts) && !is_map_entry && !is_wellknown_type;
    const auto should_skip_any_field = [](hpp_proto::field_cref field) -> bool {
      using namespace ::hpp_proto;
      const auto msg_field = field.to<message_field_cref>();
      if (!msg_field.has_value()) {
        return false;
      }
      const auto msg = msg_field->value();
      if (msg.descriptor().wellknown != ::hpp_proto::wellknown_types_t::ANY) {
        return false;
      }
      const auto type_url_field = msg.fields()[0].to<string_field_cref>();
      const auto value_field = msg.fields()[1].to<bytes_field_cref>();
      if (!type_url_field.has_value() || !value_field.has_value()) {
        return false;
      }
      return !type_url_field->value().empty() && value_field->value().empty();
    };

    if (dump_brace) {
      util::dump_opening_brace<Opts>(ctx, b, ix);
    }

    const char *separator = nullptr;

    for (auto field : value.fields()) {
      if (!field.has_value()) {
        continue;
      }
      if (should_skip_any_field(field)) {
        continue;
      }

      if (separator != nullptr) {
        util::dump_field_separator<Opts>(is_map_entry, ctx, b, ix, *separator);
      }

      if (!value.descriptor().is_map_entry()) {
        serialize_regular_field<Opts>(field, ctx, b, ix);
        separator = ",";
      } else {
        serialize_map_entry_field<Opts>(field, separator == nullptr, ctx, b, ix);
        separator = ":";
      }

      if (bool(ctx.error)) {
        return;
      }
    }

    if (dump_brace) {
      util::dump_closing_brace<Opts>(ctx, b, ix);
    }
  }

  template <auto Options>
  static void from_json(hpp_proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    // adapted from the snippet of
    // template <class T>
    //    requires((readable_map_t<T> || glaze_object_t<T> || reflectable<T>) && not custom_read<T>)
    //  struct from<JSON, T> {
    //  {
    //    template <auto Options, string_literal tag = "">
    //    static void op(auto&& value, is_context auto&& ctx, auto&& it, auto&& end);
    //  };
    std::string_view key;
    util::scan_object_fields<Options, true>(
        ctx, it, end, key, [](auto &, auto &) {},
        [&](auto &it_ref, auto &end_ref) {
          static constexpr auto Opts = opening_handled_off<ws_handled<Options>()>();
          const auto *desc = value.field_descriptor_by_json_name(key);
          if (desc == nullptr) {
            if constexpr (Opts.error_on_unknown_keys) {
              ctx.error = error_code::unknown_key;
              return true;
            }
            skip_value<JSON>::template op<Opts>(ctx, it_ref, end_ref);
          } else {
            from<JSON, ::hpp_proto::field_mref>::template op<Opts>(value.field(*desc), ctx, it_ref, end_ref);
          }
          return bool(ctx.error);
        },
        [](auto &, auto &) {});
  }
};

struct any_message_json_serializer {
  template <auto Opts>
  /**
   * @brief Handle the @type field when reading google.protobuf.Any from JSON.
   *
   * @tparam Opts Glaze parsing options controlling whitespace and termination behavior.
   * @param key Current JSON field name.
   * @param ctx Parsing context for error reporting.
   * @param it Current input iterator.
   * @param end Input end iterator.
   * @param type_url Storage for the parsed @type value.
   * @param is_type_key_first Tracks whether @type was encountered before other fields.
   * @return true if parsing should stop due to error or termination, false to continue.
   */
  static bool handle_any_type_key(std::string_view key, glz::is_context auto &ctx, auto &it, auto &end, auto &type_url,
                                  bool &is_type_key_first) {

    if (key == "@type") {
      if (!type_url.empty()) {
        ctx.error = error_code::syntax_error;
        ctx.custom_error_message = "duplicate @type field in google.protobuf.Any";
      } else {
        parse<JSON>::template op<ws_handled<Opts>()>(type_url, ctx, it, end);
        if (bool(ctx.error)) [[unlikely]] {
          return true;
        } else if (type_url.empty()) {
          ctx.error = error_code::syntax_error;
          ctx.custom_error_message = "empty @type field in google.protobuf.Any";
        }
      }
    } else {
      is_type_key_first = false;
      skip_value<JSON>::template op<ws_handled<Opts>()>(ctx, it, end);
    }
    return bool(ctx.error);
  }

  static std::expected<std::string_view, const char *> to_message_name(std::string_view type_url) {
    auto slash_pos = type_url.find('/');
    if (slash_pos >= type_url.size() - 1) {
      return std::unexpected("invalid formatted google.protobuf.Any type_url field value");
    }
    return type_url.substr(slash_pos + 1);
  }

  template <auto Opts>
  static void to_json_impl(auto &&build_message, const auto &any_type_url, const auto &any_value, is_context auto &ctx,
                           auto &b, auto &ix);

  template <auto Opts>
  static void from_json_impl(auto &&build_message, auto &&any_type_url, auto &&any_value, is_context auto &ctx,
                             auto &it, auto &end);

  static auto msg_builder(std::pmr::monotonic_buffer_resource &mr, const hpp_proto::message_value_cref &value) {
    return [&](std::string_view message_name) -> std::expected<::hpp_proto::message_value_mref, const char *> {
      const auto &pool = value.descriptor().parent_file()->get_descriptor_pool();
      const auto *const descriptor = pool.get_message_descriptor(message_name);
      if (descriptor) {
        return ::hpp_proto::message_value_mref{*descriptor, mr};
      } else {
        return std::unexpected("unknown message type from google.protobuf.Any type_url field");
      }
    };
  }

  template <auto Opts>
  static void to_json(::hpp_proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
    assert(value.descriptor().full_name() == "google.protobuf.Any");
    if (value.fields().size() == 2U) [[likely]] {
      const auto type_url_field = value.fields()[0].to<::hpp_proto::string_field_cref>();
      const auto value_field = value.fields()[1].to<::hpp_proto::bytes_field_cref>();
      if (type_url_field.has_value() && value_field.has_value()) [[likely]] {
        std::string_view any_type_url = type_url_field->value();
        ::hpp_proto::bytes_view any_value = value_field->value();
        std::pmr::monotonic_buffer_resource mr;
        to_json_impl<Opts>(msg_builder(mr, value), any_type_url, any_value, ctx, b, ix);
        return;
      }
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.Any descriptor";
  }

  template <auto Options>
  /**
   * @brief Scan a JSON object for the "@type" field and adjust the input iterator for follow-up parsing.
   *
   * The function walks the object, returning the "@type" string when found and reporting errors for duplicates
   * (or empty values). The caller's iterator is advanced to the start of the first key after leading whitespace;
   * if "@type" is the first key, it is further advanced to the start of the next field when present (comma and
   * whitespace consumed), otherwise to the position after the "@type" value and trailing whitespace.
   *
   * @tparam Options Glaze parsing options controlling whitespace and termination behavior.
   * @param any_type_url Storage for parsed any type_url.
   * @param ctx Parsing context for error reporting.
   * @param input_it Iterator to the start of the object; updated for subsequent parsing.
   * @param end Input end iterator.
   * @return The parsed "@type" value on success, or an error message on failure.
   */
  static std::expected<std::string_view, const char *> get_type_url(auto &any_type_url, is_context auto &ctx,
                                                                    auto &input_it, auto &end) {
    auto it = input_it;
    bool is_type_key_first = true;
    bool is_first_iteration = true;
    std::string_view key;
    util::scan_object_fields<opening_handled_off<Options>(), false>(
        ctx, it, end, key,
        [&](auto &it_ref, auto &) {
          if (is_first_iteration || is_type_key_first) {
            input_it = it_ref;
            is_first_iteration = false;
          }
        },
        [&](auto &it_ref, auto &end_ref) {
          return handle_any_type_key<opening_handled_off<ws_handled_off<Options>()>()>(key, ctx, it_ref, end_ref,
                                                                                       any_type_url, is_type_key_first);
        },
        [&](auto &it_ref, auto &) {
          if (is_type_key_first) {
            input_it = it_ref;
          }
        });

    if (bool(ctx.error)) [[unlikely]] {
      return std::unexpected("");
    }
    if (any_type_url.empty()) {
      return std::unexpected("@type key not found in google.protobuf.Any message");
    }
    return std::string_view{any_type_url};
  }

  template <auto Opts>
  static void from_json(::hpp_proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    assert(value.descriptor().full_name() == "google.protobuf.Any");
    std::string_view any_type_url;
    ::hpp_proto::bytes_view any_value;

    using namespace ::hpp_proto;
    pb_context pb_ctx{alloc_from{value.memory_resource()}};
    using ::hpp_proto::detail::as_modifiable;

    from_json_impl<Opts>(msg_builder(value.memory_resource(), value), as_modifiable(pb_ctx, any_type_url),
                         as_modifiable(pb_ctx, any_value), ctx, it, end);
    if (!bool(ctx.error)) {
      if (value.fields().size() == 2U && value.fields()[0].adopt(any_type_url).has_value() &&
          value.fields()[1].adopt(any_value).has_value()) [[likely]] {
        return;
      } else {
        ctx.error = error_code::syntax_error;
        ctx.custom_error_message = "invalid google.protobuf.Any descriptor";
      }
    }
  }

  static auto msg_builder(std::pmr::monotonic_buffer_resource &mr, ::hpp_proto::concepts::is_json_context auto &ctx) {
    return [&](auto message_name) -> std::expected<::hpp_proto::message_value_mref, const char *> {
      auto &msg_factory = ctx.get_dynamic_message_factory();
      auto opt_msg = msg_factory.get_message(message_name, mr);
      if (opt_msg.has_value()) {
        return *opt_msg;
      } else {
        return std::unexpected("unknown message type from type_url");
      }
    };
  }

  template <auto Opts>
  static bool parse_wellknown_any_value(::hpp_proto::message_value_mref &message, is_context auto &ctx, auto &it,
                                        auto &end);

  template <auto Opts>
  static bool parse_generic_any_value(::hpp_proto::message_value_mref &message, is_context auto &ctx, auto &it,
                                      auto &end);

  template <auto Opts>
  static void to_json(const ::hpp_proto::concepts::is_any auto &any, ::hpp_proto::concepts::is_json_context auto &ctx,
                      auto &b, auto &ix) {
    if (!any.type_url.empty() && !any.value.empty()) {
      std::pmr::monotonic_buffer_resource mr;
      to_json_impl<Opts>(msg_builder(mr, ctx), any.type_url, any.value, ctx, b, ix);
    }
  }

  template <auto Opts>
  static void from_json(::hpp_proto::concepts::is_any auto &any, ::hpp_proto::concepts::is_json_context auto &ctx,
                        auto &it, auto &end) {
    using namespace ::hpp_proto::detail;
    std::pmr::monotonic_buffer_resource mr;
    from_json_impl<Opts>(msg_builder(mr, ctx), as_modifiable(ctx, any.type_url), as_modifiable(ctx, any.value), ctx, it,
                         end);
  }
};
struct timestamp_message_json_serializer {
  template <auto Opts>
  static void to_json(hpp_proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
    assert(value.descriptor().full_name() == "google.protobuf.Timestamp");
    if (value.fields().size() == 2U) [[likely]] {
      auto seconds_value = value.fields()[0].get<std::int64_t>();
      auto nanos_value = value.fields()[1].get<std::int32_t>();
      if (seconds_value.has_value() && nanos_value.has_value()) [[likely]] {
        google::protobuf::Timestamp v{seconds_value.value(), nanos_value.value(), {}};
        to<JSON, google::protobuf::Timestamp<>>::template op<Opts>(v, ctx, b, ix);
        return;
      }
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.Timestamp descriptor";
  }

  template <auto Opts>
  static void from_json(hpp_proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    assert(value.descriptor().full_name() == "google.protobuf.Timestamp");
    google::protobuf::Timestamp<> v;
    from<JSON, google::protobuf::Timestamp<>>::template op<Opts>(v, ctx, it, end);
    if (!bool(ctx.error) && value.fields().size() == 2 && (value.fields()[0].set(v.seconds).has_value()) &&
        (value.fields()[1].set(v.nanos).has_value())) [[likely]] {
      return;
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.Timestamp descriptor";
  }
};

struct duration_message_json_serializer {
  template <auto Opts>
  static void to_json(hpp_proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
    assert(value.descriptor().full_name() == "google.protobuf.Duration");
    if (value.fields().size() == 2) [[likely]] {
      auto seconds_value = value.fields()[0].get<std::int64_t>();
      auto nanos_value = value.fields()[1].get<std::int32_t>();
      if (seconds_value.has_value() && nanos_value.has_value()) [[likely]] {
        google::protobuf::Duration<> v{seconds_value.value(), nanos_value.value(), {}};
        to<JSON, google::protobuf::Duration<>>::template op<Opts>(v, ctx, b, ix);
        return;
      }
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.Duration descriptor";
  }

  template <auto Opts>
  static void from_json(hpp_proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    assert(value.descriptor().full_name() == "google.protobuf.Duration");
    google::protobuf::Duration<> v;
    from<JSON, google::protobuf::Duration<>>::template op<Opts>(v, ctx, it, end);
    if (!bool(ctx.error) && value.fields().size() == 2 && (value.fields()[0].set(v.seconds).has_value()) &&
        (value.fields()[1].set(v.nanos).has_value())) [[likely]] {
      return;
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.Duration descriptor";
  }
};

struct field_mask_message_json_serializer {
  using FieldMask = ::google::protobuf::FieldMask<::hpp_proto::non_owning_traits>;

  template <auto Opts>
  GLZ_ALWAYS_INLINE static void to_json(hpp_proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
    assert(value.descriptor().full_name() == "google.protobuf.FieldMask");
    if (value.fields().size() == 1U) [[likely]] {
      auto paths = value.fields()[0].get<std::span<const std::string_view>>();
      if (paths.has_value()) [[likely]] {
        to<JSON, FieldMask>::template op<Opts>(FieldMask{.paths = paths.value(), .unknown_fields_ = {}}, ctx, b, ix);
        return;
      }
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.FieldMask descriptor";
  }

  template <auto Opts>
  static void from_json(hpp_proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    assert(value.descriptor().full_name() == "google.protobuf.FieldMask");
    std::string_view encoded;
    from<JSON, std::string_view>::template op<Opts>(encoded, ctx, it, end);
    if constexpr (not Opts.null_terminated) {
      if (ctx.error == error_code::end_reached) {
        ctx.error = error_code::none;
      }
    }
    if (static_cast<bool>(ctx.error)) [[unlikely]] {
      return;
    }

    if (encoded.empty()) {
      return;
    }

    auto num_commas = static_cast<std::size_t>(std::ranges::count_if(encoded, [](char c) { return c == ','; }));
    auto comma_separated_view = encoded | std::views::split(',') | std::views::transform([](auto subrange) {
                                  return std::string_view{subrange.data(), subrange.size()};
                                });

    if (value.fields().size() == 1 &&
        value.fields()[0].set(::hpp_proto::sized_input_range{comma_separated_view, num_commas + 1}).has_value())
        [[likely]] {
      return;
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.FieldMask descriptor";
  }
};

struct value_message_json_serializer {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void to_json(hpp_proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
    assert(value.descriptor().full_name() == "google.protobuf.Value");
    if (value.fields().size() > 0) {
      auto oneof_index = value.fields()[0].active_oneof_index();
      if (oneof_index >= 0 && std::cmp_less(oneof_index, value.fields().size())) {
        to<JSON, ::hpp_proto::field_cref>::template op<Opts>(value.fields()[static_cast<std::size_t>(oneof_index)], ctx,
                                                             b, ix);
      }
    }
  }
  template <auto Options>
  static void from_json(hpp_proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    if constexpr (!check_ws_handled(Options)) {
      if (skip_ws<Options>(ctx, it, end)) {
        return;
      }
    }

    constexpr auto Opts = ws_handled<Options>();
    using enum ::google::protobuf::Value<>::kind_oneof_case;
    // parse null
    if (*it == 'n') {
      ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      if constexpr (not Opts.null_terminated) {
        if (it == end) [[unlikely]] {
          ctx.error = error_code::unexpected_end;
          return;
        }
      }
      match<"ull", Opts>(ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return;
      }
      (void)value.fields()[null_value - 1].set(::hpp_proto::enum_number{0}); // NOLINT
    } else if (*it == 'f' || *it == 't') {
      from<JSON, ::hpp_proto::field_mref>::template op<Opts>(value.fields()[bool_value - 1], ctx, it, end);
    } else if (*it == '"') {
      from<JSON, ::hpp_proto::field_mref>::template op<Opts>(value.fields()[string_value - 1], ctx, it, end);
    } else if (*it == '[') {
      from<JSON, ::hpp_proto::field_mref>::template op<Opts>(value.fields()[list_value - 1], ctx, it, end);
    } else if (*it == '{') {
      from<JSON, ::hpp_proto::field_mref>::template op<Opts>(value.fields()[struct_value - 1], ctx, it, end);
    } else {
      from<JSON, ::hpp_proto::field_mref>::template op<Opts>(value.fields()[number_value - 1], ctx, it, end);
    }
  }
};

template <typename T, hpp_proto::field_kind_t Kind>
struct to<JSON, hpp_proto::scalar_field_cref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp_proto::scalar_field_cref<T, Kind> &value, auto &&...args) {
    if (value.has_value()) {
      using value_type = hpp_proto::scalar_field_cref<T, Kind>::value_type;
      constexpr bool need_quote = ::hpp_proto::concepts::integral_64_bits<value_type> || check_quoted_num(Opts);
      to<JSON, value_type>::template op<set_opt<Opts, quoted_num_opt_tag{}>(need_quote)>(
          value.value(), std::forward<decltype(args)>(args)...);
    }
  }
};

template <typename T, hpp_proto::field_kind_t Kind>
struct to<JSON, hpp_proto::repeated_scalar_field_cref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp_proto::repeated_scalar_field_cref<T, Kind> &value, auto &&...args) {
    if (!value.empty()) {
      auto range = std::span{value.data(), value.size()};
      using value_type = hpp_proto::repeated_scalar_field_cref<T, Kind>::value_type;
      constexpr bool need_quote = ::hpp_proto::concepts::integral_64_bits<value_type>;
      to<JSON, decltype(range)>::template op<set_opt<Opts, quoted_num_opt_tag{}>(need_quote)>(
          range, std::forward<decltype(args)>(args)...);
    }
  }
};

template <>
struct to<JSON, hpp_proto::enum_value> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp_proto::enum_value &value, is_context auto &ctx, auto &b, auto &ix) {
    if (value.descriptor().is_null_value) {
      dump<"null">(b, ix);
      return;
    }
    std::string_view name = value.name();
    if (!name.empty()) {
      dump<'"'>(b, ix);
      dump(name, b, ix);
      dump<'"'>(b, ix);
    } else {
      to<JSON, uint32_t>::template op<Opts>(value.number(), ctx, b, ix);
    }
  }
};

template <>
struct to<JSON, hpp_proto::repeated_message_field_cref> {
  template <auto Opts>
  static void op(auto const &value, is_context auto &ctx, auto &b, auto &ix);
};

template <>
struct to<JSON, hpp_proto::message_value_cref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp_proto::message_value_cref &value, is_context auto &ctx, auto &b,
                                   auto &ix) {
    using enum hpp_proto::wellknown_types_t;
    switch (value.descriptor().wellknown) {
    case ANY:
      any_message_json_serializer::template to_json<Opts>(value, ctx, b, ix);
      break;
    case TIMESTAMP:
      timestamp_message_json_serializer::template to_json<Opts>(value, ctx, b, ix);
      break;
    case DURATION:
      duration_message_json_serializer::template to_json<Opts>(value, ctx, b, ix);
      break;
    case FIELDMASK:
      field_mask_message_json_serializer::template to_json<Opts>(value, ctx, b, ix);
      break;
    case VALUE:
      value_message_json_serializer::template to_json<Opts>(value, ctx, b, ix);
      break;
    case STRUCT:
    case LISTVALUE: {
      auto f0 = value.fields()[0].to<::hpp_proto::repeated_message_field_cref>();
      // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
      to<JSON, ::hpp_proto::repeated_message_field_cref>::template op<Opts>(*f0, ctx, b, ix);
    } break;
    case WRAPPER: {
      to<JSON, ::hpp_proto::field_cref>::template op<Opts>(value.fields()[0], ctx, b, ix);
    } break;
    default:
      generic_message_json_serializer::template to_json<Opts>(value, ctx, b, ix);
    }
  }
};

template <>
struct to<JSON, hpp_proto::message_value_mref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp_proto::message_value_mref &value, auto &&...args) {
    to<JSON, hpp_proto::message_value_cref>::template op<Opts>(value.cref(), std::forward<decltype(args)>(args)...);
  }
};

template <auto Opts>
void to<JSON, hpp_proto::repeated_message_field_cref>::op(auto const &value, is_context auto &ctx, auto &b, auto &ix) {
  if (value.descriptor().is_map_entry()) {
    glz::dump<'{'>(b, ix);
  } else {
    glz::dump<'['>(b, ix);
  }
  if constexpr (Opts.prettify) {
    ctx.depth += glz::check_indentation_width(Opts);
    glz::dump<'\n'>(b, ix);
    glz::dumpn(glz::check_indentation_char(Opts), ctx.depth, b, ix);
  }

  char separator = '\0';

  for (auto entry : value) {
    auto pre_separator_ix = ix;
    if (separator) {
      // not the first field in a message, output the separator
      glz::dump<','>(b, ix);
      if (Opts.prettify) {
        glz::dump<'\n'>(b, ix);
        glz::dumpn(glz::check_indentation_char(Opts), ctx.depth, b, ix);
      }
    }
    auto pre_element_ix = ix;
    to<JSON, hpp_proto::message_value_cref>::template op<Opts>(entry, ctx, b, ix);
    if (ix == pre_element_ix) [[unlikely]] {
      // in this case, we have an element with unknown fields only, just skip it.
      ix = pre_separator_ix;
    } else {
      separator = ',';
    }
  }

  if constexpr (Opts.prettify) {
    ctx.depth -= glz::check_indentation_width(Opts);
    glz::dump<'\n'>(b, ix);
    glz::dumpn(glz::check_indentation_char(Opts), ctx.depth, b, ix);
  }
  if (value.descriptor().is_map_entry()) {
    glz::dump<'}'>(b, ix);
  } else {
    glz::dump<']'>(b, ix);
  }
}

template <typename T, hpp_proto::field_kind_t Kind>
struct from<JSON, hpp_proto::scalar_field_mref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp_proto::scalar_field_mref<T, Kind> &value, auto &ctx, auto &it, auto &end) {
    using value_type = hpp_proto::scalar_field_cref<T, Kind>::value_type;
    value_type v = {};
    if constexpr (std::is_integral_v<value_type>) {
      auto &descriptor = value.descriptor();
      if (descriptor.proto().number == 1 && descriptor.parent_message()->is_map_entry()) {
        util::parse_integral_map_key<Opts>(v, ctx, it, end);
        value.set(v);
        return;
      }
    }
    if constexpr (::hpp_proto::concepts::integral_64_bits<value_type> || check_quoted_num(Opts)) {
      from<JSON, value_type>::template op<opt_true<ws_handled<Opts>(), quoted_num_opt_tag{}>>(v, ctx, it, end);
    } else {
      from<JSON, value_type>::template op<Opts>(v, ctx, it, end);
    }
    value.set(v);
  }
};

template <concepts::requires_custom_read T>
struct meta<T> {
  static constexpr auto custom_read = true;
};
template <concepts::string_mref T>
struct from<JSON, T> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &ctx, auto &it, auto &end) {
    std::string_view v;
    hpp_proto::pb_context pb_ctx{hpp_proto::alloc_from(value.memory_resource())};
    decltype(auto) m = hpp_proto::detail::as_modifiable(pb_ctx, v);
    from<JSON, decltype(m)>::template op<Opts>(m, ctx, it, end);
    if constexpr (not Opts.null_terminated) {
      if (ctx.error == error_code::end_reached) {
        ctx.error = error_code::none;
      }
    }
    if (!bool(ctx.error)) [[likely]] {
      value.adopt(v);
    }
  }
};

template <concepts::bytes_mref T>
struct from<JSON, T> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &ctx, auto &it, auto &end) {
    std::string_view encoded;
    from<JSON, std::string_view>::template op<Opts>(encoded, ctx, it, end);
    if (static_cast<bool>(ctx.error)) [[unlikely]] {
      return;
    }
    hpp_proto::pb_context pb_ctx{hpp_proto::alloc_from{value.memory_resource()}};
    hpp_proto::bytes_view decoded;
    if (::hpp_proto::base64::decode(encoded, decoded, pb_ctx)) [[likely]] {
      value.adopt(decoded);
    } else {
      ctx.error = error_code::syntax_error;
      return;
    }
  }
};

template <>
struct from<JSON, hpp_proto::enum_value_mref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp_proto::enum_value_mref &value, is_context auto &ctx, auto &it, auto &end) {
    if constexpr (!check_ws_handled(Opts)) {
      if (skip_ws<Opts>(ctx, it, end)) [[unlikely]] {
        return;
      }
    }

    if (*it != '"') [[unlikely]] {
      int32_t v = 0;
      from<JSON, int32_t>::template op<Opts>(v, ctx, it, end);
      if (!bool(ctx.error)) {
        value.set(v);
      }
      return;
    }
    it = std::next(it);
    const auto start = it;
    skip_string_view(ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }
    const sv key{start, size_t(it - start)};
    ++it; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    if constexpr (not Opts.null_terminated) {
      if (it == end) [[unlikely]] {
        ctx.error = error_code::unexpected_end;
        return;
      }
    }

    const auto *pv = value.number_by_name(key);
    if (pv == nullptr) {
      ctx.error = error_code::unexpected_enum;
      return;
    }
    value.set(*pv);
  }
};

template <>
struct from<JSON, hpp_proto::message_value_mref> {
  template <auto Options>
  static void parse_mapped(hpp_proto::field_mref value, is_context auto &ctx, auto &it, auto &end) {
    const auto *msg_descriptor = value.descriptor().message_field_type_descriptor();
    bool is_wellknown_value =
        msg_descriptor != nullptr && msg_descriptor->wellknown == hpp_proto::wellknown_types_t::VALUE;

    if (util::parse_null<Options>(value, ctx, it, end)) {
      if (!is_wellknown_value) {
        ctx.error = error_code::syntax_error;
      }
      return;
    }

    value.visit([&](auto v) { util::from_json<Options>(v, ctx, it, end); });
  }

  template <auto Opts>
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &ctx, auto &it, auto &end) {
    if (value.descriptor().is_map_entry()) {
      value.fields()[0].visit([&](auto key_mref) {
        using key_mref_type = decltype(key_mref);
        if constexpr (concepts::map_key_mref<key_mref_type>) {
          util::parse_key_and_colon<opt_true<Opts, quoted_num_opt_tag{}>>(key_mref, ctx, it, end);
          if (bool(ctx.error)) [[unlikely]] {
            return;
          }
          parse_mapped<ws_handled<Opts>()>(value.fields()[1], ctx, it, end);
        } else {
          ctx.error = error_code::syntax_error;
        }
      });
    } else {
      using enum hpp_proto::wellknown_types_t;
      switch (value.descriptor().wellknown) {
      case ANY:
        any_message_json_serializer::template from_json<Opts>(value, ctx, it, end);
        break;
      case TIMESTAMP:
        timestamp_message_json_serializer::template from_json<Opts>(value, ctx, it, end);
        break;
      case DURATION:
        duration_message_json_serializer::template from_json<Opts>(value, ctx, it, end);
        break;
      case FIELDMASK:
        field_mask_message_json_serializer::template from_json<Opts>(value, ctx, it, end);
        break;
      case VALUE:
        value_message_json_serializer::template from_json<Opts>(value, ctx, it, end);
        break;
      case STRUCT:
      case LISTVALUE:
      case WRAPPER:
        from<JSON, ::hpp_proto::field_mref>::template op<Opts>(value.fields()[0], ctx, it, end);
        break;
      default:
        generic_message_json_serializer::template from_json<Opts>(value, ctx, it, end);
      }
    }
  }
};

template <concepts::repeated_mref T>
struct from<JSON, T> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &ctx, auto &it, auto &end) {
    const bool is_map =
        std::same_as<T, ::hpp_proto::repeated_message_field_mref> ? value.descriptor().is_map_entry() : false;

    util::parse_repeated<Opts>(is_map, value, ctx, it, end);
  }
};

template <auto Opts>
static std::expected<bool, const char *> message_to_json(::hpp_proto::message_value_mref message, const auto &any_value,
                                                         is_context auto &ctx, auto &b, auto &ix) {
  if (hpp_proto::read_binpb(message, any_value).ok()) {
    const auto pre_ix = ix;
    to<JSON, hpp_proto::message_value_cref>::template op<Opts>(message, ctx, b, ix);
    if (bool(ctx.error)) [[unlikely]] {
      return false;
    }
    return ix != pre_ix;
  } else {
    return std::unexpected("unable to deserialize value in google.protobuf.Any message");
  }
};

template <auto Opts>
bool any_message_json_serializer::parse_wellknown_any_value(::hpp_proto::message_value_mref &message,
                                                            is_context auto &ctx, auto &it, auto &end) {
  bool seen_value = false;
  std::string_view key;
  util::scan_object_fields<opening_handled<Opts>(), true>(
      ctx, it, end, key, [](auto &, auto &) {},
      [&](auto &it_ref, auto &end_ref) {
        if (key == "value") {
          if (seen_value) {
            if (!bool(ctx.error)) {
              ctx.error = error_code::syntax_error;
              ctx.custom_error_message = "duplicate value field in google.protobuf.Any message";
            }
            return true;
          }
          seen_value = true;
          // parse the the json into a new dynamic_message
          from<JSON, ::hpp_proto::message_value_mref>::template op<ws_handled<Opts>()>(message, ctx, it_ref, end_ref);
          return bool(ctx.error);
        } else if (key == "@type") {
          // Consume the already-parsed @type field to enforce no extra keys.
          skip_value<JSON>::template op<ws_handled<Opts>()>(ctx, it_ref, end_ref);
          return bool(ctx.error);
        } else {
          if (!bool(ctx.error)) {
            ctx.error = error_code::syntax_error;
            ctx.custom_error_message = "unknown key in google.protobuf.Any message";
          }
          return true;
        }
      },
      [](auto &, auto &) {});
  if (!bool(ctx.error) && !seen_value) [[unlikely]] {
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "value key not found in google.protobuf.Any message";
  }
  return !bool(ctx.error);
}

template <auto Options>
bool any_message_json_serializer::parse_generic_any_value(::hpp_proto::message_value_mref &message,
                                                          is_context auto &ctx, auto &it, auto &end) {
  std::string_view key;
  util::scan_object_fields<Options, true>(
      ctx, it, end, key, [](auto &, auto &) {},
      [&](auto &it_ref, auto &end_ref) {
        static constexpr auto Opts = opening_handled_off<ws_handled<Options>()>();
        if (key == "@type") [[unlikely]] {
          skip_value<JSON>::template op<Opts>(ctx, it_ref, end_ref);
        } else {
          const auto *desc = message.field_descriptor_by_json_name(key);
          if (desc == nullptr) {
            if constexpr (Opts.error_on_unknown_keys) {
              ctx.error = error_code::unknown_key;
              return true;
            }
            skip_value<JSON>::template op<Opts>(ctx, it_ref, end_ref);
          } else {
            from<JSON, ::hpp_proto::field_mref>::template op<Opts>(message.field(*desc), ctx, it_ref, end_ref);
          }
        }
        return bool(ctx.error);
      },
      [](auto &, auto &) {});
  return !bool(ctx.error);
}

template <auto Opts>
void any_message_json_serializer::to_json_impl(auto &&build_message, const auto &any_type_url, const auto &any_value,
                                               is_context auto &ctx, auto &b, auto &ix) {
  util::dump_opening_brace<Opts>(ctx, b, ix);

  dump<"\"@type\":">(b, ix);
  if constexpr (Opts.prettify) {
    glz::dump<' '>(b, ix);
  }

  glz::to<glz::JSON, std::string_view>::template op<Opts>(std::string_view{any_type_url}, ctx, b, ix);

  (void)to_message_name(any_type_url)
      .and_then(build_message)
      .and_then([&](::hpp_proto::message_value_mref message) -> std::expected<void, const char *> {
        if (message.descriptor().wellknown != hpp_proto::wellknown_types_t::NONE) {
          dump<','>(b, ix);
          if (Opts.prettify) {
            dump<'\n'>(b, ix);
            dumpn(glz::check_indentation_char(Opts), ctx.depth, b, ix);
          }
          dump<R"("value":)">(b, ix);
          if constexpr (Opts.prettify) {
            dump<' '>(b, ix);
          }

          auto wrote = message_to_json<Opts>(message, any_value, ctx, b, ix);
          if (!wrote.has_value()) {
            return std::unexpected(wrote.error());
          }
        } else {
          const auto sep_ix = ix;
          dump<','>(b, ix);
          if (Opts.prettify) {
            dump<'\n'>(b, ix);
            dumpn(glz::check_indentation_char(Opts), ctx.depth, b, ix);
          }
          auto wrote = message_to_json<opening_handled<Opts>()>(message, any_value, ctx, b, ix);
          if (!wrote.has_value()) {
            return std::unexpected(wrote.error());
          }
          if (!*wrote) {
            ix = sep_ix;
          }
        }
        util::dump_closing_brace<Opts>(ctx, b, ix);
        return {};
      })
      .transform_error([&](const char *err_msg) {
        ctx.error = error_code::syntax_error;
        ctx.custom_error_message = err_msg;
        return 0;
      });
}

template <auto Opts>
void any_message_json_serializer::from_json_impl(auto &&build_message, auto &&any_type_url, auto &&any_value,
                                                 is_context auto &ctx, auto &it, auto &end) {
  (void)get_type_url<Opts>(any_type_url, ctx, it, end)
      .and_then([&](std::string_view type_url) { return to_message_name(type_url).and_then(build_message); })
      .and_then([&](auto message) -> std::expected<void, const char *> {
        const bool ok = message.descriptor().wellknown != ::hpp_proto::wellknown_types_t::NONE
                            ? parse_wellknown_any_value<Opts>(message, ctx, it, end)
                            : parse_generic_any_value<opening_handled<Opts>()>(message, ctx, it, end);

        if (ok && !hpp_proto::write_binpb(message, any_value).ok()) {
          return std::unexpected("unable to serialize the value for google.protobuf.Any message");
        }
        return {};
      })
      .transform_error([&](const char *error_msg) {
        if (!bool(ctx.error)) {
          ctx.error = error_code::syntax_error;
          if (error_msg && *error_msg) {
            ctx.custom_error_message = error_msg;
          }
        }
        return 0;
      });
}

} // namespace glz

namespace hpp_proto {

template <auto Opts = glz::opts_validate{}>
json_status json_to_binpb(const dynamic_message_factory &factory, std::string_view message_name, auto &&json_view,
                          concepts::contiguous_byte_range auto &buffer) {
  std::pmr::monotonic_buffer_resource mr;
  auto opt_msg = factory.get_message(message_name, mr);
  if (opt_msg.has_value()) {
    auto msg = *opt_msg;
    auto status = read_json<Opts>(msg, std::forward<decltype(json_view)>(json_view));
    if (status.ok()) [[likely]] {
      if (write_binpb(msg, buffer).ok()) [[likely]] {
        return {};
      } else {
        return {.ctx = {.ec = ::glz::error_code::syntax_error, .custom_error_message = "protobuf encoding error"}};
      }
    } else {
      return status;
    }
  } else {
    return {.ctx = {.ec = ::glz::error_code::get_wrong_type, .custom_error_message = "unknown message name"}};
  }
}

template <auto Opts = json_write_opts{}>
status binpb_to_json(const dynamic_message_factory &factory, std::string_view message_name,
                     concepts::contiguous_byte_range auto const &pb_encoded_stream,
                     concepts::resizable_contiguous_byte_container auto &buffer) {
  std::pmr::monotonic_buffer_resource mr;
  auto opt_msg = factory.get_message(message_name, mr);
  if (opt_msg.has_value()) {
    auto msg = *opt_msg;
    if (auto r = read_binpb(msg, pb_encoded_stream); !r.ok()) {
      return r;
    }
    if (::glz::write<Opts>(msg, buffer)) [[unlikely]] {
      return std::errc::io_error;
    }
    return {};
  } else {
    return std::errc::invalid_argument;
  }
}

} // namespace hpp_proto
