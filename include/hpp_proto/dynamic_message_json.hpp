#include <google/protobuf/duration.glz.hpp>
#include <google/protobuf/field_mask.glz.hpp>
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
void dump_opening_brace(is_context auto &ctx, auto &b, auto &ix) noexcept {
  glz::dump<'{'>(b, ix);
  if constexpr (Opts.prettify) {
    ctx.indentation_level += Opts.indentation_width;
    glz::dump<'\n'>(b, ix);
    glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
  }
}

template <auto Opts>
void dump_closing_brace(is_context auto &ctx, auto &b, auto &ix) noexcept {
  if constexpr (Opts.prettify) {
    ctx.indentation_level -= Opts.indentation_width;
    glz::dump<'\n'>(b, ix);
    glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
  }
  glz::dump<'}'>(b, ix);
}

template <auto Opts>
void dump_field_separator(bool is_map_entry, is_context auto &ctx, auto &b, auto &ix, char separator) noexcept {
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
struct from<JSON, hpp::proto::field_mref> {
  template <auto Options>
  GLZ_ALWAYS_INLINE static void op(hpp::proto::field_mref value, is_context auto &ctx, auto &it, auto &end) {
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
  static void serialize_regular_field(hpp::proto::field_cref field, bool is_wellknown_type, is_context auto &ctx,
                                      auto &b, auto &ix) noexcept {
    constexpr auto field_opts = glz::opening_handled_off<Opts>();
    if (!is_wellknown_type) {
      auto json_name = field.descriptor().proto().json_name;
      to<glz::JSON, std::string_view>::template op<field_opts>(json_name, ctx, b, ix);
      glz::dump<':'>(b, ix);
      if constexpr (Opts.prettify) {
        glz::dump<' '>(b, ix);
      }
    }
    field.visit([&](auto v) { to<JSON, decltype(v)>::template op<field_opts>(v, ctx, b, ix); });
  }

  template <auto Opts>
  static void serialize_map_entry_field(hpp::proto::field_cref field, bool is_first_field, is_context auto &ctx,
                                        auto &b, auto &ix) noexcept {
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
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
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
        serialize_regular_field<Opts>(field, is_wellknown_type, ctx, b, ix);
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

  template <auto Opts>
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) noexcept {
    // adapted from the snippet of
    // template <class T>
    //    requires((readable_map_t<T> || glaze_object_t<T> || reflectable<T>) && not custom_read<T>)
    //  struct from<JSON, T> {
    //  {
    //    template <auto Options, string_literal tag = "">
    //    static void op(auto&& value, is_context auto&& ctx, auto&& it, auto&& end);
    //  };
    util::parse_opening<Opts>('{', ctx, it, end);
    const auto ws_start = it;
    if (skip_ws<Opts>(ctx, it, end)) {
      return;
    }
    const size_t ws_size = size_t(it - ws_start);
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
        from<JSON, ::hpp::proto::field_mref>::template op<Opts>(value.mutable_field(*desc), ctx, it, end);
      }

      if (bool(ctx.error)) [[unlikely]]
        return;

      if (skip_ws<Opts>(ctx, it, end)) {
        return;
      }
    }
  }
};

struct any_message_json_serializer {
  static const ::hpp::proto::dynamic_message_factory::message_descriptor_t *
  message_descriptor_from_type_url(is_context auto &ctx, hpp::proto::message_value_cref value,
                                   std::string_view type_url) {
    const auto &pool = value.descriptor().parent_file()->get_descriptor_pool();

    auto slash_pos = type_url.find('/');
    if (slash_pos >= type_url.size() - 1) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "invalid type_url in google.protobuf.Any message";
      return nullptr;
    }

    const auto *const descriptor = pool.get_message_descriptor(type_url.substr(slash_pos + 1));
    if (!descriptor) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "unresolvable type_url in google.protobuf.Any message";
      return nullptr;
    }
    return descriptor;
  }

  template <auto Opts>
  static void any_value_to_json(const hpp::proto::message_descriptor_t &descriptor, std::span<const std::byte> value,
                                is_context auto &ctx, auto &b, auto &ix) noexcept;

  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    auto type_url_field = value.field_by_number<hpp::proto::string_field_cref>(1);
    auto value_field = value.field_by_number<hpp::proto::bytes_field_cref>(2);
    if (!type_url_field.has_value() || !value_field.has_value()) {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Any message descriptor";
      return;
    }
    std::string_view type_url = type_url_field.value().value();
    const auto *const value_descriptor = message_descriptor_from_type_url(ctx, value, type_url);
    if (value_descriptor == nullptr) {
      return;
    }

    glz::dump<"\"@type\":">(b, ix);
    if constexpr (Opts.prettify) {
      glz::dump<' '>(b, ix);
    }

    glz::to<glz::JSON, std::string_view>::template op<Opts>(type_url, ctx, b, ix);
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

  template <auto Opts>
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end);
};
struct timestamp_message_json_serializer {

  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    auto seconds_field = value.field_by_number<::hpp::proto::int64_field_cref>(1);
    auto nanos_field = value.field_by_number<::hpp::proto::int32_field_cref>(2);
    if (seconds_field.has_value() && nanos_field.has_value()) [[likely]] {
      google::protobuf::Timestamp v{seconds_field->value(), nanos_field->value(), {}};
      to<JSON, google::protobuf::Timestamp<>>::template op<Opts>(v, ctx, b, ix);
    } else {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Timestamp message descriptor";
    }
  }

  template <auto Opts>
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    auto seconds_field = value.field_by_number<::hpp::proto::int64_field_mref>(1);
    auto nanos_field = value.field_by_number<::hpp::proto::int32_field_mref>(2);
    if (seconds_field.has_value() && nanos_field.has_value()) [[likely]] {
      google::protobuf::Timestamp v;
      from<JSON, google::protobuf::Timestamp<>>::template op<Opts>(v, ctx, it, end);
      seconds_field->set(v.seconds);
      nanos_field->set(v.nanos);
    } else {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Timestamp message descriptor";
    }
  }
};

struct duration_message_json_serializer {
  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    auto seconds_field = value.field_by_number<::hpp::proto::int64_field_cref>(1);
    auto nanos_field = value.field_by_number<::hpp::proto::int32_field_cref>(2);
    if (seconds_field.has_value() && nanos_field.has_value()) [[likely]] {
      google::protobuf::Duration v{seconds_field->value(), nanos_field->value(), {}};
      to<JSON, google::protobuf::Duration<>>::template op<Opts>(v, ctx, b, ix);
    } else {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Duration message descriptor";
    }
  }

  template <auto Opts>
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    auto seconds_field = value.field_by_number<::hpp::proto::int64_field_mref>(1);
    auto nanos_field = value.field_by_number<::hpp::proto::int32_field_mref>(2);
    if (seconds_field.has_value() && nanos_field.has_value()) [[likely]] {
      google::protobuf::Duration v;
      from<JSON, google::protobuf::Duration<>>::template op<Opts>(v, ctx, it, end);
      seconds_field->set(v.seconds);
      nanos_field->set(v.nanos);
    } else {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.Duration message descriptor";
    }
  }
};

struct field_mask_message_json_serializer {
  using FieldMask = ::google::protobuf::FieldMask<::hpp::proto::non_owning_traits>;

  template <auto Opts>
  static void to_json(hpp::proto::message_value_cref value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    auto paths_field = value.field_by_number<hpp::proto::repeated_string_field_cref>(1);
    if (paths_field.has_value()) [[likely]] {
      to<JSON, FieldMask>::template op<Opts>(FieldMask{.paths = {paths_field->data(), paths_field->size()}}, ctx, b,
                                             ix);
    } else {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.FieldMask message descriptor";
    }
  }

  template <auto Opts>
  static void from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it, auto &end) {
    auto paths_field = value.field_by_number<hpp::proto::repeated_string_field_mref>(1);
    if (paths_field.has_value()) [[likely]] {
      std::string_view encoded;
      from<JSON, std::string_view>::template op<Opts>(encoded, ctx, it, end);
      if (static_cast<bool>(ctx.error)) [[unlikely]] {
        return;
      }

      if (encoded.empty()) {
        return;
      }

      auto is_comma = [](auto c) { return c == ','; };
      auto num_commas = std::count_if(encoded.begin(), encoded.end(), is_comma);

      paths_field->resize(static_cast<std::size_t>(num_commas + 1));
      auto cur = encoded.begin();
      for (const auto &p : *paths_field) {
        auto comma_pos = std::find_if(cur, encoded.end(), is_comma);
        p.assign(std::string_view{cur, comma_pos});
        if (comma_pos != encoded.end()) {
          cur = std::next(comma_pos);
        }
      }

    } else {
      ctx.error = error_code::invalid_get;
      ctx.custom_error_message = "non-conforming google.protobuf.FieldMask message descriptor";
    }
  }
};

template <typename T, hpp::proto::field_kind_t Kind>
struct to<JSON, hpp::proto::scalar_field_cref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::scalar_field_cref<T, Kind> &value, auto &&...args) noexcept {

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
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::repeated_scalar_field_cref<T, Kind> &value,
                                   auto &&...args) noexcept {
    if (!value.empty()) {
      auto range = std::span{value.data(), value.size()};
      constexpr bool need_quote = concepts::eight_bytes_integer<T>;
      to<JSON, decltype(range)>::template op<set_opt<Opts, &opts::quoted_num>(need_quote)>(
          range, std::forward<decltype(args)>(args)...);
    }
  }
};

template <>
struct to<JSON, hpp::proto::enum_value_cref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::enum_value_cref &value, is_context auto &ctx, auto &b,
                                   auto &ix) noexcept {
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
  static void op(auto const &value, is_context auto &ctx, auto &b, auto &ix) noexcept;
};

template <>
struct to<JSON, hpp::proto::message_value_cref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::message_value_cref &value, is_context auto &ctx, auto &b,
                                   auto &ix) noexcept {
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
    case STRUCT:
    case LISTVALUE: {
      auto f0 = value.fields()[0].to<::hpp::proto::repeated_message_field_cref>();
      to<JSON, ::hpp::proto::repeated_message_field_cref>::template op<Opts>(*f0, ctx, b, ix);
    } break;
    default:
      generic_message_json_serializer::template to_json<Opts>(value, ctx, b, ix);
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

template <auto Opts>
void to<JSON, hpp::proto::repeated_message_field_cref>::op(auto const &value, is_context auto &ctx, auto &b,
                                                           auto &ix) noexcept {
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

template <typename T, hpp::proto::field_kind_t Kind>
struct from<JSON, hpp::proto::scalar_field_mref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::scalar_field_mref<T, Kind> &value, auto &&...args) noexcept {
    using value_type = hpp::proto::scalar_field_cref<T, Kind>::value_type;
    constexpr bool need_quote = concepts::eight_bytes_integer<T> || (Opts.quoted_num);
    value_type v;
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
  GLZ_ALWAYS_INLINE static void op(auto &value, is_context auto &ctx, auto &it, auto &end) noexcept {
    std::string_view v;
    from<JSON, std::string_view>::template op<Opts>(v, ctx, it, end);
    if (!bool(ctx.error)) [[likely]] {
      value.assign(v);
    }
  }
};

template <concepts::bytes_mref T>
struct from<JSON, T> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto &value, is_context auto &ctx, auto &it, auto &end) noexcept {
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
                                   auto &end) noexcept {

    if (value.descriptor().is_null_value) {
      from<JSON, std::nullptr_t>::template op<Opts>(nullptr, ctx, it, end);
      return;
    }
    if constexpr (!check_ws_handled(Opts)) {
      if (skip_ws<Opts>(ctx, it, end)) [[unlikely]] {
        return;
      }
    }

    if (*it != '"') [[unlikely]] {
      uint32_t v;
      from<JSON, uint32_t>::template op<Opts>(v, ctx, it, end);
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
    ++it;

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
            key_mref.assign(key_str);
          } else {
            using key_value_type = typename key_mref_type::value_type;
            key_value_type v;
            from<JSON, key_value_type>::template op<Opts>(v, ctx, key_str.begin(), key_str.end());
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
      case STRUCT:
      case LISTVALUE:
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
  GLZ_ALWAYS_INLINE static void op(auto &&value, is_context auto &ctx, auto &it, auto &end) noexcept {
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
void any_message_json_serializer::from_json(hpp::proto::message_value_mref value, is_context auto &ctx, auto &it,
                                            auto &end) {
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
    // constexpr auto Opts = glz::opening_handled_off<glz::ws_handled_off<Opts>()>();
    using namespace glz;
    std::string_view type_url;
    from<JSON, std::string_view>::template op<Opts>(type_url, ctx, it, end);
    if (bool(ctx.error)) [[unlikely]] {
      return;
    }

    const auto *const desc = message_descriptor_from_type_url(ctx, value, type_url);
    if (desc == nullptr) [[unlikely]] {
      ctx.error = error_code::key_not_found;
      ctx.custom_error_message = "invalid type_url in google.protobuf.Any message";
      return;
    }

    ::hpp::proto::message_value_mref obj(*desc, value.memory_resource());

    if (desc->wellknown != ::hpp::proto::wellknown_types_t::NONE) {
      auto key = util::parse_key_and_colon<Opts>(ctx, it, end);
      if (bool(ctx.error)) [[unlikely]] {
        return;
      }
      if (key != "value") {
        ctx.error = error_code::key_not_found;
        ctx.custom_error_message = "value key not found in google.protobuf.Any message";
        return;
      }
      // parse the the json into a new dynamic_message
      from<JSON, ::hpp::proto::message_value_mref>::template op<Opts>(obj, ctx, it, end);
    } else {
      // parse the the json into a new dynamic_message with opening handled
      from<JSON, ::hpp::proto::message_value_mref>::template op<opening_handled_off<Opts>()>(obj, ctx, it, end);
    }

    if (bool(ctx.error)) [[unlikely]] {
      return;
    }

    // write the type_url
    value.fields()[0].to<::hpp::proto::string_field_mref>()->assign(type_url);

    // encode the dynamic_message into protobuf
    std::span<const std::byte> v;
    if (::hpp::proto::write_proto(obj, v, ::hpp::proto::alloc_from(value.memory_resource())).ok()) {

      // write the encoded value into the field
      value.fields()[1].to<::hpp::proto::bytes_field_mref>()->adopt(v);
    } else {
      ctx.error = error_code::invalid_body;
      ctx.custom_error_message = "google.protobuf.Any value encode error";
    }

  } else [[unlikely]] {
    ctx.error = error_code::key_not_found;
    ctx.custom_error_message = "@type key not found in google.protobuf.Any message";
  }
}

} // namespace glz
