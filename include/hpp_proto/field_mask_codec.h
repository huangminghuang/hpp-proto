#pragma once
#include <cstdint>
#include <numeric>

namespace hpp::proto {

struct field_mask_codec {
  constexpr static std::size_t max_encode_size(auto &&value) noexcept {
    return value.paths.size() + std::transform_reduce(value.paths.begin(), value.paths.end(), 0, std::plus{},
                                                      [](auto &p) { return p.size(); });
  }

  static int64_t encode(auto &&value, auto &&b) noexcept {
    if (value.paths.empty())
      return 0;
    char *cur = std::data(b);
    for (auto &p : value.paths) {
      cur = std::copy(std::begin(p), std::end(p), cur);
      *cur++ = ',';
    }
    --cur;
    return cur - std::data(b);
  }

  static bool decode(auto &&json, auto &&value) {
    if (json.empty())
      return true;
    auto is_comma = [](auto c) { return c == ','; };
    auto num_commas = std::count_if(json.begin(), json.end(), is_comma);
    value.paths.resize(num_commas + 1);
    auto cur = json.begin();
    for (auto &p : value.paths) {
      auto comma_pos = std::find_if(cur, json.end(), is_comma);
      auto &path = hpp::proto::detail::make_growable(value, p);
      path.resize(comma_pos - cur);
      std::copy(cur, comma_pos, path.begin());
#if defined(_MSC_VER)
      if (comma_pos != json.end())
#endif
        cur = comma_pos + 1;
    }
    return true;
  }
};
} // namespace hpp::proto