#pragma once
#include <cstdint>
#include <hpp_proto/memory_resource_utils.hpp>
#include <numeric>
namespace hpp::proto {

struct field_mask_codec {
  constexpr static std::size_t max_encode_size(auto const &value) noexcept {
    return value.paths.size() + std::transform_reduce(value.paths.begin(), value.paths.end(), 0ULL, std::plus{},
                                                      [](auto &p) { return p.size(); });
  }
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  static int64_t encode(auto const &value, auto &&b) noexcept {
    if (value.paths.empty()) {
      return 0;
    }
    auto* buf = std::data(std::forward<decltype(b)>(b));
    char *cur = buf;
    for (auto &p : value.paths) {
      cur = std::copy(std::begin(p), std::end(p), cur);
      *cur++ = ',';
    }
    --cur;
    return cur - buf;
  }

  static bool decode(auto const &json, auto &value) {
    if (json.empty()) {
      return true;
    }
    auto is_comma = [](auto c) { return c == ','; };
    auto num_commas = std::count_if(json.begin(), json.end(), is_comma);
    value.paths.resize(num_commas + 1);
    auto cur = json.begin();
    for (auto &p : value.paths) {
      auto comma_pos = std::find_if(cur, json.end(), is_comma);
      auto &path = hpp::proto::as_modifiable(value, p);
      path.assign(cur, comma_pos);
#if defined(_MSC_VER)
      if (comma_pos != json.end())
#endif
        cur = comma_pos + 1;
    }
    return true;
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
};
} // namespace hpp::proto