#include <hpp_proto/json_serializer.hpp>
#include <hpp_proto/reflection.hpp>

namespace glz {

template <typename T, hpp::proto::field_kind_t Kind>
struct to<JSON, hpp::proto::scalar_field_cref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::scalar_field_cref<T, Kind> &value, auto &&...args) noexcept {

    if (value.has_value()) {
      if constexpr (std::is_integral_v<T> && sizeof(T) > 4) {
        to<JSON, T>::template op<opt_true<Opts, &opts::quoted_num>>(*value, std::forward<decltype(args)>(args)...);
      } else {
        to<JSON, T>::template op<Opts>(*value, std::forward<decltype(args)>(args)...);
      }
    }
  }
};

template <typename T, hpp::proto::field_kind_t Kind>
struct to<JSON, hpp::proto::repeated_scalar_field_cref<T, Kind>> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(const hpp::proto::repeated_scalar_field_cref<T, Kind> &value, auto &&...args) noexcept {
    if (!value.empty()) {
      auto range = std::span{value.data(), value.size()};
      if constexpr (std::is_integral_v<T> && sizeof(T) > 4) {
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
  GLZ_ALWAYS_INLINE static void op(auto const &value, is_context auto &ctx, auto &b, auto &ix) noexcept {
    const bool dump_brace = !has_opening_handled(Opts) && !value.descriptor().is_map_entry();

    if (dump_brace) {
      glz::dump<'{'>(b, ix);
      if constexpr (Opts.prettify) {
        ctx.indentation_level += Opts.indentation_width;
        glz::dump<'\n'>(b, ix);
        glz::dumpn<Opts.indentation_char>(ctx.indentation_level, b, ix);
      }
    }

    constexpr auto opts = glz::opening_handled_off<Opts>();
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
      if (!field.descriptor().is_map_entry()) {
        auto json_name = field.descriptor().proto().json_name;
        glz::serialize<glz::JSON>::op<opts>(json_name, ctx, b, ix);
        glz::dump<':'>(b, ix);
        if constexpr (Opts.prettify) {
          glz::dump<' '>(b, ix);
        }
        separator = ",";
      } else {
        separator = ":";
      }

      field.visit([&](auto v) { to<JSON, decltype(v)>::template op<opts>(v, ctx, b, ix); });
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

template <>
struct to<JSON, hpp::proto::message_value_mref> {
  template <auto Opts>
  GLZ_ALWAYS_INLINE static void op(auto const &value, auto &&...args) noexcept {
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

} // namespace glz