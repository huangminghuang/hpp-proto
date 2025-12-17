#pragma once
#include <google/protobuf/duration.glz.hpp>
#include <google/protobuf/field_mask.glz.hpp>
#include <google/protobuf/struct.msg.hpp>
#include <google/protobuf/timestamp.glz.hpp>
#include <hpp_proto/json_serializer.hpp>

#include <hpp_proto/dynamic_message.hpp>

namespace glz {

namespace util {
template <auto Opts>
bool match_ending_or_consume_comma(auto ws_start, size_t ws_size, bool &first, glz::is_context auto &ctx, auto &it,
                                   auto &end) {
  if (util::match_ending<Opts>('}', ctx, it, end)) {
    if constexpr (not Opts.null_terminated) {
      if (it == end) {
        ctx.error = error_code::end_reached;
      }
    }
    return true;
  } else if (first) {
    first = false;
  } else {
    if (match_invalid_end<',', Opts>(ctx, it, end)) {
      return true;
    }
    if constexpr (not Opts.null_terminated) {
      if (it == end) [[unlikely]] {
        ctx.error = error_code::unexpected_end;
        return true;
      }
    }

    if constexpr ((not Opts.minified) && (!Opts.comments)) {
      if (ws_size && ws_size < size_t(end - it)) {
        skip_matching_ws(ws_start, it, ws_size);
      }
    }

    if (skip_ws<Opts>(ctx, it, end)) {
      return true;
    }
  }
  return false;
}

template <auto Opts>
void dump_opening_brace(is_context auto &ctx, auto &b, auto &ix) {
  glz::dump<'{'>(b, ix);
  if constexpr (Opts.prettify) {
    ctx.indentation_level += Opts.indentation_width;
    glz::dump<'\n'>(b, ix);
    glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
  }
}

template <auto Opts>
void dump_closing_brace(is_context auto &ctx, auto &b, auto &ix) {
  if constexpr (Opts.prettify) {
    ctx.indentation_level -= Opts.indentation_width;
    glz::dump<'\n'>(b, ix);
    glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
  }
  glz::dump<'}'>(b, ix);
}

template <auto Opts>
void dump_field_separator(bool is_map_entry, is_context auto &ctx, auto &b, auto &ix, char separator) {
  glz::dump(separator, b, ix);
  if constexpr (Opts.prettify) {
    if (!is_map_entry) {
      glz::dump<'\n'>(b, ix);
      glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
    } else {
      glz::dump<' '>(b, ix);
    }
  }
}

} // namespace util

namespace concepts {
template <typename T>
concept string_mref =
    (std::same_as<T, ::hpp::proto::string_field_mref> || std::same_as<T, ::hpp::proto::string_value_mref>);

template <typename T>
concept bytes_mref =
    (std::same_as<T, ::hpp::proto::bytes_field_mref> || std::same_as<T, ::hpp::proto::bytes_value_mref>);

template <typename T>
concept repeated_mref = requires {
  requires T::is_mutable;
  requires T::field_kind >= ::hpp::proto::field_kind_t::KIND_REPEATED_DOUBLE;
};

template <typename T>
concept requires_custom_read = string_mref<T> || bytes_mref<T> || repeated_mref<T>;

template <typename T>
concept eight_bytes_integer = std::same_as<T, std::int64_t> || std::same_as<T, std::uint64_t> ||
                              (::hpp::proto::concepts::varint<T> && sizeof(T) == 8);

template <typename T>
concept map_key_mref = std::same_as<T, ::hpp::proto::string_field_mref> ||
                       (std::same_as<T, ::hpp::proto::scalar_field_mref<typename T::encode_type, T::field_kind>> &&
                        !std::is_floating_point_v<typename T::value_type>);

} // namespace concepts

template <>
struct to<JSON, hpp::proto::field_cref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(hpp::proto::field_cref value, is_context auto &ctx, auto &b, auto &ix) {
    if (value.has_value()) {
      value.visit([&](auto v) {
        using T = std::remove_cvref_t<decltype(v)>;
        to<JSON, T>::template op<Opts>(v, ctx, b, ix);
      });
    }
  }
};

template <>
struct from<JSON, hpp::proto::field_mref> {
  template <auto Options>
  static void op(hpp::proto::field_mref value, is_context auto &ctx, auto &it, auto &end) {
    if (!util::parse_null<Options>(value, ctx, it, end)) {
      value.visit([&](auto v) {
        using T = std::remove_cvref_t<decltype(v)>;
        constexpr auto Opts = ws_handled_off<Options>();
        from<JSON, T>::template op<Opts>(v, ctx, it, end);
      });
    }
  }
};

struct generic_message_json_serializer {

  template <auto Opts>
  static void serialize_regular_field(hpp::proto::field_cref field, is_context auto &ctx, auto &b, auto &ix) {
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
  static void serialize_map_entry_field(hpp::proto::field_cref field, bool is_first_field, is_context auto &ctx,
                                        auto &b, auto &ix) {
    constexpr auto field_opts = glz::opening_handled_off<Opts>();
    if (is_first_field) {
      bool need_extra_quote = (field.field_kind() == hpp::proto::KIND_BOOL);
      if (need_extra_quote) {
        glz::dump<'"'>(b, ix);
      }
      field.visit(
          [&](auto v) { to<JSON, decltype(v)>::template op<opt_true<field_opts, &opts::quoted_num>>(v, ctx, b, ix); });
      if (need_extra_quote) {
        glz::dump<'"'>(b, ix);
      }
    } else {
      field.visit([&](auto v) { to<JSON, decltype(v)>::template op<field_opts>(v, ctx, b, ix); });
    }
  }

  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
    bool is_wellknown_type = (value.descriptor().wellknown != hpp::proto::wellknown_types_t::NONE);
    bool is_map_entry = value.descriptor().is_map_entry();
    const bool dump_brace = !check_opening_handled(Opts) && !is_map_entry && !is_wellknown_type;

    if (dump_brace) {
      util::dump_opening_brace<Opts>(ctx, b, ix);
    }

    const char *separator = nullptr;

    for (auto field : value.fields()) {
      if (!field.has_value()) {
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
    }

    if (dump_brace) {
      util::dump_closing_brace<Opts>(ctx, b, ix);
    }
  }

  template <auto Options>
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    // adapted from the snippet of
    // template <class T>
    //    requires((readable_map_t<T> || glaze_object_t<T> || reflectable<T>) && not custom_read<T>)
    //  struct from<JSON, T> {
    //  {
    //    template <auto Options, string_literal tag = "">
    //    static void op(auto&& value, is_context auto&& ctx, auto&& it, auto&& end);
    //  };
    static constexpr auto Opts = opening_handled_off<ws_handled_off<Options>()>();

    util::parse_opening<Options>('{', ctx, it, end);
    const auto ws_start = it;
    if (skip_ws<Opts>(ctx, it, end)) {
      return;
    }
    const auto ws_size = size_t(it - ws_start);
    bool first = true;
    while (true) {
      if (util::match_ending_or_consume_comma<Opts>(ws_start, ws_size, first, ctx, it, end)) {
        return;
      }

      auto key = util::parse_key_and_colon<Opts>(ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return;
      }

      const auto *desc = value.field_descriptor_by_json_name(key);
      if (desc == nullptr) {
        skip_value<JSON>::template op<Opts>(ctx, it, end);
      } else {
        from<JSON, ::hpp::proto::field_mref>::template op<Opts>(value.field(*desc), ctx, it, end);
      }

      if (bool(ctx.error)) [[unlikely]] {
        return;
      }

      if (skip_ws<Opts>(ctx, it, end)) {
        return;
      }
    }
  }
};

struct any_message_json_serializer {

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

  static auto msg_builder(std::pmr::monotonic_buffer_resource &mr, const hpp::proto::message_value_cref &value) {
    return [&](std::string_view message_name) -> std::expected<::hpp::proto::message_value_mref, const char *> {
      const auto &pool = value.descriptor().parent_file()->get_descriptor_pool();
      const auto *const descriptor = pool.get_message_descriptor(message_name);
      if (descriptor) {
        return ::hpp::proto::message_value_mref{*descriptor, mr};
      } else {
        return std::unexpected("unknown message type from google.protobuf.Any type_url field");
      }
    };
  }

  template <auto Opts>
  static void to_json(::hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
    assert(value.descriptor().full_name() == "google.protobuf.Any");
    if (value.fields().size() == 2U) [[likely]] {
      const auto type_url_field = value.fields()[0].to<::hpp::proto::string_field_cref>();
      const auto value_field = value.fields()[1].to<::hpp::proto::bytes_field_cref>();
      if (type_url_field.has_value() && value_field.has_value()) [[likely]] {
        std::string_view any_type_url = type_url_field->value();
        ::hpp::proto::bytes_view any_value = value_field->value();
        std::pmr::monotonic_buffer_resource mr;
        to_json_impl<Opts>(msg_builder(mr, value), any_type_url, any_value, ctx, b, ix);
        return;
      }
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.Any descriptor";
  }

  template <auto Opts>
  static void from_json(::hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    assert(value.descriptor().full_name() == "google.protobuf.Any");
    std::string_view any_type_url;
    ::hpp::proto::bytes_view any_value;

    using namespace ::hpp::proto;
    pb_context pb_ctx{alloc_from{value.memory_resource()}};
    using ::hpp::proto::detail::as_modifiable;

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

  static auto msg_builder(std::pmr::monotonic_buffer_resource &mr, ::hpp::proto::concepts::is_json_context auto &ctx) {
    return [&](auto message_name) -> std::expected<::hpp::proto::message_value_mref, const char *> {
      auto &msg_factory = ctx.template get<::hpp::proto::dynamic_message_factory>();
      auto opt_msg = msg_factory.get_message(message_name, mr);
      if (opt_msg.has_value()) {
        return *opt_msg;
      } else {
        return std::unexpected("unknown message type from type_url");
      }
    };
  }

  template <auto Opts>
  static void to_json(const ::hpp::proto::concepts::is_any auto &any, ::hpp::proto::concepts::is_json_context auto &ctx,
                      auto &b, auto &ix) {
    std::pmr::monotonic_buffer_resource mr;
    to_json_impl<Opts>(msg_builder(mr, ctx), any.type_url, any.value, ctx, b, ix);
  }

  template <auto Opts>
  static void from_json(::hpp::proto::concepts::is_any auto &any, ::hpp::proto::concepts::is_json_context auto &ctx,
                        auto &it, auto &end) {
    using namespace ::hpp::proto::detail;
    std::pmr::monotonic_buffer_resource mr;
    from_json_impl<Opts>(msg_builder(mr, ctx), as_modifiable(ctx, any.type_url), as_modifiable(ctx, any.value), ctx, it,
                         end);
  }
};
struct timestamp_message_json_serializer {

  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
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
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    assert(value.descriptor().full_name() == "google.protobuf.Timestamp");
    google::protobuf::Timestamp<> v;
    from<JSON, google::protobuf::Timestamp<>>::template op<Opts>(v, ctx, it, end);
    if (!bool(ctx.error) && value.fields().size() == 2 &&
        (v.seconds == 0 || value.fields()[0].set(v.seconds).has_value()) &&
        (v.nanos == 0 || value.fields()[1].set(v.nanos).has_value())) [[likely]] {
      return;
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.Timestamp descriptor";
  }
};

struct duration_message_json_serializer {
  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
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
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    assert(value.descriptor().full_name() == "google.protobuf.Duration");
    google::protobuf::Duration<> v;
    from<JSON, google::protobuf::Duration<>>::template op<Opts>(v, ctx, it, end);
    if (!bool(ctx.error) && value.fields().size() == 2 &&
        (v.seconds == 0 || value.fields()[0].set(v.seconds).has_value()) &&
        (v.nanos == 0 || value.fields()[1].set(v.nanos).has_value())) [[likely]] {
      return;
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.Duration descriptor";
  }
};

struct field_mask_message_json_serializer {
  using FieldMask = ::google::protobuf::FieldMask<::hpp::proto::non_owning_traits>;

  template <auto Opts>
  GLZ_ALWAYS_INLINE static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
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
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    assert(value.descriptor().full_name() == "google.protobuf.FieldMask");
    std::string_view encoded;
    from<JSON, std::string_view>::template op<opt_true<Opts, &opts::null_terminated>>(encoded, ctx, it, end);
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
        value.fields()[0].set(::hpp::proto::sized_input_range{comma_separated_view, num_commas + 1}).has_value())
        [[likely]] {
      return;
    }
    ctx.error = error_code::syntax_error;
    ctx.custom_error_message = "invalid google.protobuf.FieldMask descriptor";
  }
};

struct value_message_json_serializer {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) {
    assert(value.descriptor().full_name() == "google.protobuf.Value");
    if (value.fields().size() > 0) {
      auto oneof_index = value.fields()[0].active_oneof_index();
      if (oneof_index >= 0 && std::cmp_less(oneof_index, value.fields().size())) {
        to<JSON, ::hpp::proto::field_cref>::template op<Opts>(value.fields()[static_cast<std::size_t>(oneof_index)],
                                                              ctx, b, ix);
      }
    }
  }
  template <auto Options>
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
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
      (void)value.fields()[null_value - 1].set(::hpp::proto::enum_number{0}); // NOLINT
    } else if (*it == 'f' || *it == 't') {
      from<JSON, ::hpp::proto::field_mref>::template op<Opts>(value.fields()[bool_value - 1], ctx, it, end);
    } else if (*it == '"') {
      from<JSON, ::hpp::proto::field_mref>::template op<opt_true<Opts, &opts::null_terminated>>(
          value.fields()[string_value - 1], ctx, it, end);
    } else if (*it == '[') {
      from<JSON, ::hpp::proto::field_mref>::template op<Opts>(value.fields()[list_value - 1], ctx, it, end);
    } else if (*it == '{') {
      from<JSON, ::hpp::proto::field_mref>::template op<Opts>(value.fields()[struct_value - 1], ctx, it, end);
    } else {
      from<JSON, ::hpp::proto::field_mref>::template op<Opts>(value.fields()[number_value - 1], ctx, it, end);
    }
  }
};

template <typename T, hpp::proto::field_kind_t Kind>
struct to<JSON, hpp::proto::scalar_field_cref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::scalar_field_cref<T, Kind> &value, auto &&...args) {

    if (value.has_value()) {
      using value_type = hpp::proto::scalar_field_cref<T, Kind>::value_type;
      constexpr bool need_quote = (concepts::eight_bytes_integer<T> || (Opts.quoted_num));
      to<JSON, value_type>::template op<set_opt<Opts, &opts::quoted_num>(need_quote)>(
          value.value(), std::forward<decltype(args)>(args)...);
    }
  }
};

template <typename T, hpp::proto::field_kind_t Kind>
struct to<JSON, hpp::proto::repeated_scalar_field_cref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::repeated_scalar_field_cref<T, Kind> &value, auto &&...args) {
    if (!value.empty()) {
      auto range = std::span{value.data(), value.size()};
      constexpr bool need_quote = concepts::eight_bytes_integer<T>;
      to<JSON, decltype(range)>::template op<set_opt<Opts, &opts::quoted_num>(need_quote)>(
          range, std::forward<decltype(args)>(args)...);
    }
  }
};

template <>
struct to<JSON, hpp::proto::enum_value> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::enum_value &value, is_context auto &ctx, auto &b, auto &ix) {
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
struct to<JSON, hpp::proto::repeated_message_field_cref> {
  template <auto Opts>
  static void op(auto const &value, is_context auto &ctx, auto &b, auto &ix);
};

template <>
struct to<JSON, hpp::proto::message_value_cref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::message_value_cref &value, is_context auto &ctx, auto &b,
                                   auto &ix) {
    using enum hpp::proto::wellknown_types_t;
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
      auto f0 = value.fields()[0].to<::hpp::proto::repeated_message_field_cref>();
      // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
      to<JSON, ::hpp::proto::repeated_message_field_cref>::template op<Opts>(*f0, ctx, b, ix);
    } break;
    case WRAPPER: {
      to<JSON, ::hpp::proto::field_cref>::template op<Opts>(value.fields()[0], ctx, b, ix);
    } break;
    default:
      generic_message_json_serializer::template to_json<Opts>(value, ctx, b, ix);
    }
  }
};

template <>
struct to<JSON, hpp::proto::message_value_mref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::message_value_mref &value, auto &&...args) {
    to<JSON, hpp::proto::message_value_cref>::template op<Opts>(value.cref(), std::forward<decltype(args)>(args)...);
  }
};

template <auto Opts>
void to<JSON, hpp::proto::repeated_message_field_cref>::op(auto const &value, is_context auto &ctx, auto &b, auto &ix) {
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
    auto pre_separator_ix = ix;
    if (separator) {
      // not the first field in a message, output the separator
      glz::dump<','>(b, ix);
      if (Opts.prettify) {
        glz::dump<'\n'>(b, ix);
        glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
      }
    }
    auto pre_element_ix = ix;
    to<JSON, hpp::proto::message_value_cref>::template op<Opts>(entry, ctx, b, ix);
    if (ix == pre_element_ix) [[unlikely]] {
      // in this case, we have an element with unknown fields only, just skip it.
      ix = pre_separator_ix;
    } else {
      separator = ',';
    }
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

template <typename T, hpp::proto::field_kind_t Kind>
struct from<JSON, hpp::proto::scalar_field_mref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::scalar_field_mref<T, Kind> &value, auto &&...args) {
    using value_type = hpp::proto::scalar_field_cref<T, Kind>::value_type;
    constexpr bool need_quote = concepts::eight_bytes_integer<T> || (Opts.quoted_num);
    value_type v = {};
    from<JSON, value_type>::template op<set_opt<Opts, &opts::quoted_num>(need_quote)>(
        v, std::forward<decltype(args)>(args)...);
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
  GLZ_ALWAYS_INLINE static void op(auto &value, is_context auto &ctx, auto &it, auto &end) {
    std::string_view v;
    from<JSON, std::string_view>::template op<Opts>(v, ctx, it, end);
    if (!bool(ctx.error)) [[likely]] {
      value.set(v);
    }
  }
};

template <concepts::bytes_mref T>
struct from<JSON, T> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &value, is_context auto &ctx, auto &it, auto &end) {
    std::string_view encoded;
    from<JSON, std::string_view>::template op<Opts>(encoded, ctx, it, end);
    if (static_cast<bool>(ctx.error)) [[unlikely]] {
      return;
    }
    std::pmr::vector<std::byte> decoded{&value.memory_resource()};
    if (::hpp::proto::base64::decode(encoded, decoded)) [[likely]] {
      value.adopt(decoded);
    } else {
      ctx.error = error_code::syntax_error;
      return;
    }
  }
};

template <>
struct from<JSON, hpp::proto::enum_value_mref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::enum_value_mref &value, is_context auto &ctx, auto &it,
                                   auto &end) {

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
    skip_string_view<Opts>(ctx, it, end);
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
struct from<JSON, hpp::proto::message_value_mref> {
  template <auto Opts>
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &ctx, auto &it, auto &end) {
    if (value.descriptor().is_map_entry()) {
      value.fields()[0].visit([&](auto key_mref) {
        using key_mref_type = decltype(key_mref);
        if constexpr (concepts::map_key_mref<key_mref_type>) {
          auto key_str = util::parse_key_and_colon<Opts>(ctx, it, end);
          if (bool(ctx.error)) [[unlikely]] {
            return;
          }

          if constexpr (std::same_as<key_mref_type, ::hpp::proto::string_field_mref>) {
            key_mref.set(key_str);
          } else {
            using key_value_type = typename key_mref_type::value_type;
            key_value_type v;
            from<JSON, key_value_type>::template op<Opts>(v, ctx, std::to_address(key_str.begin()),
                                                          std::to_address(key_str.end()));
            if (bool(ctx.error)) [[unlikely]] {
              return;
            }
            key_mref.set(v);
          }
          from<JSON, ::hpp::proto::field_mref>::template op<Opts>(value.fields()[1], ctx, it, end);
        } else {
          ctx.error = error_code::syntax_error;
        }
      });
    } else {
      using enum hpp::proto::wellknown_types_t;
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
        from<JSON, ::hpp::proto::field_mref>::template op<Opts>(value.fields()[0], ctx, it, end);
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
        std::same_as<T, ::hpp::proto::repeated_message_field_mref> ? value.descriptor().is_map_entry() : false;

    util::parse_repeated<Opts>(is_map, value, ctx, it, end, [](auto &&element, auto &ctx, auto &it, auto &end) {
      constexpr bool need_quote = concepts::eight_bytes_integer<typename T::value_type>;
      constexpr auto ElementOpts = set_opt<Opts, &opts::quoted_num>(need_quote);
      from<JSON, std::remove_reference_t<typename T::reference>>::template op<ElementOpts>(
          std::forward<decltype(element)>(element), ctx, it, end);
    });
  }
};

template <auto Opts>
static std::expected<void, const char *> message_to_json(::hpp::proto::message_value_mref message,
                                                         const auto &any_value, is_context auto &ctx, auto &b,
                                                         auto &ix) {
  if (hpp::proto::read_proto(message, any_value).ok()) {
    to<JSON, hpp::proto::message_value_cref>::template op<Opts>(message, ctx, b, ix);
    if (bool(ctx.error)) [[unlikely]] {
      return {};
    }
    util::dump_closing_brace<Opts>(ctx, b, ix);
    return {};
  } else {
    return std::unexpected("unable to deserialize value in google.protobuf.Any message");
  }
};

template <auto Opts>
void any_message_json_serializer::to_json_impl(auto &&build_message, const auto &any_type_url, const auto &any_value,
                                               is_context auto &ctx, auto &b, auto &ix) {

  util::dump_opening_brace<Opts>(ctx, b, ix);

  dump<"\"@type\":">(b, ix);
  if constexpr (Opts.prettify) {
    glz::dump<' '>(b, ix);
  }

  glz::to<glz::JSON, std::string_view>::template op<Opts>(std::string_view{any_type_url}, ctx, b, ix);
  dump<','>(b, ix);
  if (Opts.prettify) {
    dump<'\n'>(b, ix);
    dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
  }

  (void)to_message_name(any_type_url)
      .and_then(build_message)
      .and_then([&](::hpp::proto::message_value_mref message) -> std::expected<void, const char *> {
        if (message.descriptor().wellknown != hpp::proto::wellknown_types_t::NONE) {
          dump<R"("value":)">(b, ix);
          if constexpr (Opts.prettify) {
            dump<' '>(b, ix);
          }

          return message_to_json<Opts>(message, any_value, ctx, b, ix);
        } else {
          return message_to_json<opening_handled<Opts>()>(message, any_value, ctx, b, ix);
        }
      })
      .transform_error([&](const char *err_msg) {
        ctx.error = error_code::syntax_error;
        ctx.custom_error_message = err_msg;
        return 0;
      });
}

template <auto Opts>
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
void any_message_json_serializer::from_json_impl(auto &&build_message, auto &&any_type_url, auto &&any_value,
                                                 is_context auto &ctx, auto &it, auto &end) {
  if (!util::parse_opening<Opts>('{', ctx, it, end)) [[unlikely]] {
    return;
  }
  if (skip_ws<Opts>(ctx, it, end)) {
    return;
  }
  auto key = util::parse_key_and_colon<Opts>(ctx, it, end);
  if (bool(ctx.error)) [[unlikely]] {
    return;
  }

  if (key == "@type") {
    std::string_view type_url;
    from<JSON, std::string_view>::template op<Opts>(type_url, ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }
    any_type_url = type_url;

    if (match_invalid_end<',', Opts>(ctx, it, end)) {
      return;
    }
    if constexpr (not Opts.null_terminated) {
      if (it == end) [[unlikely]] {
        ctx.error = error_code::unexpected_end;
        return;
      }
    }

    (void)to_message_name(type_url)
        .and_then(build_message)
        .and_then([&](auto message) -> std::expected<void, const char *> {
          if (message.descriptor().wellknown != ::hpp::proto::wellknown_types_t::NONE) {
            auto key = util::parse_key_and_colon<Opts>(ctx, it, end);
            if (bool(ctx.error)) [[unlikely]] {
              return {};
            }
            if (key != "value") {
              return std::unexpected("value key not found in google.protobuf.Any message");
            }
            // parse the the json into a new dynamic_message
            from<JSON, ::hpp::proto::message_value_mref>::template op<Opts>(message, ctx, it, end);
          } else {
            // parse the the json into a new dynamic_message with opening handled
            from<JSON, ::hpp::proto::message_value_mref>::template op<opening_handled<Opts>()>(message, ctx, it, end);
          }

          if (!hpp::proto::write_proto(message, any_value).ok()) {
            return std::unexpected("unable to serialize the value for google.protobuf.Any message");
          }
          return {};
        })
        .transform_error([&](const char *error_msg) {
          ctx.error = error_code::syntax_error;
          ctx.custom_error_message = error_msg;
          return 0;
        });
  }
}

} // namespace glz

namespace hpp::proto {

json_status json_to_pb(const dynamic_message_factory &factory, std::string_view message_name, const char *json_view,
                       concepts::contiguous_byte_range auto &buffer) {
  std::pmr::monotonic_buffer_resource mr;
  auto opt_msg = factory.get_message(message_name, mr);
  if (opt_msg.has_value()) {
    auto msg = *opt_msg;
    auto err = ::glz::read<::glz::opts{}>(msg, json_view);
    if (!err) {
      if (write_proto(msg, buffer).ok()) [[likely]] {
        return {};
      } else {
        return {.ctx = {.ec = ::glz::error_code::syntax_error, .custom_error_message = "protobuf encoding error"}};
      }
    } else {
      return {.ctx = err};
    }
  } else {
    return {.ctx = {.ec = ::glz::error_code::get_wrong_type,
                    .custom_error_message = "unknown message name",
                    .location = {},
                    .includer_error = {}}};
  }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
json_status json_to_pb(const dynamic_message_factory &factory, std::string_view message_name,
                       std::string_view json_view, concepts::contiguous_byte_range auto &buffer) {
  std::pmr::monotonic_buffer_resource mr;

  auto opt_msg = factory.get_message(message_name, mr);
  if (opt_msg.has_value()) {
    auto msg = *opt_msg;
    auto err = ::glz::read<glz::opts{.null_terminated = false}>(msg, json_view);
    if (!err) {
      if (write_proto(msg, buffer).ok()) [[likely]] {
        return {};
      } else {
        return {.ctx = {.ec = ::glz::error_code::syntax_error, .custom_error_message = "protobuf encoding error"}};
      }
    } else {
      return {.ctx = err};
    }
  } else {
    return {.ctx = {.ec = ::glz::error_code::get_wrong_type,
                    .custom_error_message = "unknown message name",
                    .location = {},
                    .includer_error = {}}};
  }
}

status pb_to_json(const dynamic_message_factory &factory, std::string_view message_name,
                  concepts::contiguous_byte_range auto const &pb_encoded_stream,
                  concepts::resizable_contiguous_byte_container auto &buffer, concepts::glz_opts_t auto opts) {
  std::pmr::monotonic_buffer_resource mr;
  auto opt_msg = factory.get_message(message_name, mr);
  if (opt_msg.has_value()) {
    auto msg = *opt_msg;
    if (auto r = read_proto(msg, pb_encoded_stream); !r.ok()) {
      return r;
    }
    if (::glz::write<decltype(opts)::glz_opts_value>(msg, buffer)) [[unlikely]] {
      return std::errc::io_error;
    }
    return {};
  } else {
    return std::errc::invalid_argument;
  }
}

status pb_to_json(const dynamic_message_factory &factory, std::string_view message_name,
                  concepts::contiguous_byte_range auto const &pb_encoded_stream,
                  concepts::resizable_contiguous_byte_container auto &buffer) {
  return pb_to_json(factory, message_name, pb_encoded_stream, buffer, glz_opts_t<glz::opts{}>{});
}

} // namespace hpp::proto
