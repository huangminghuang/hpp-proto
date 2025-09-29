#pragma once
#include <hpp_proto/field_types.hpp>
#include <memory_resource>
#include <string>
#include <vector>

namespace hpp::proto {

struct default_traits {
  template <typename T>
  using vector = std::vector<T>;
  using string = std::string;

  template <typename Key, typename Mapped>
  struct map {
    using type = hpp::proto::flat_map<Key, Mapped>;
  };
};

struct pmr_traits {
  template <typename T>
  using vector = std::pmr::vector<T>;
  using string = std::pmr::string;
  template <typename Key, typename Mapped>
  struct map {
    using type = hpp::proto::flat_map<Key, Mapped>;
  };
};
}; // namespace hpp::proto