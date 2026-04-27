#include <boost/ut.hpp>
#include <hpp_proto/flat_map.hpp>
#include <stdexcept>
#include <vector>

struct throwing_mapped {
  int value = 0;
  bool throw_on_copy = false;
  bool throw_on_int = false;

  throwing_mapped() = default;
  explicit throwing_mapped(int v, bool should_throw = false) : value(v), throw_on_int(should_throw) {
    if (throw_on_int) {
      throw std::runtime_error("int construction failed");
    }
  }
  throwing_mapped(const throwing_mapped &other) : value(other.value), throw_on_copy(other.throw_on_copy) {
    if (throw_on_copy) {
      throw std::runtime_error("copy construction failed");
    }
  }
  throwing_mapped(throwing_mapped &&) noexcept = default;
  throwing_mapped &operator=(const throwing_mapped &) = default;
  throwing_mapped &operator=(throwing_mapped &&) noexcept = default;

  bool operator==(const throwing_mapped &) const = default;
};

struct throwing_int_vector : std::vector<int> {
  using std::vector<int>::vector;
  using std::vector<int>::operator=;

  inline static bool throw_on_move_assign = false;

  throwing_int_vector() = default;
  throwing_int_vector(std::initializer_list<int> values) : std::vector<int>(values) {}
  throwing_int_vector(std::vector<int> values) : std::vector<int>(std::move(values)) {}
  throwing_int_vector(const throwing_int_vector &) = default;
  throwing_int_vector(throwing_int_vector &&) noexcept = default;

  throwing_int_vector &operator=(const throwing_int_vector &) = default;
  throwing_int_vector &operator=(throwing_int_vector &&other) {
    if (throw_on_move_assign) {
      throw std::runtime_error("move assignment failed");
    }
    std::vector<int>::operator=(std::move(other));
    return *this;
  }
};

const boost::ut::suite flat_map_tests = [] {
  using namespace boost::ut;

  "const_at_throws_for_missing_key"_test = [] {
    const stdext::flat_map<int, int> values{{1, 10}};

    expect(throws<std::out_of_range>([&] { (void)values.at(2); }));
  };

  "emplace_with_existing_key_returns_existing_iterator"_test = [] {
    stdext::flat_map<int, int> values{{1, 10}};

    auto result = values.emplace(1, 20);

    expect(!result.second);
    expect(result.first->first == 1);
    expect(result.first->second == 10);
    expect(values == stdext::flat_map<int, int>{{1, 10}});
  };

  "try_emplace_with_lvalue_key_uses_valid_middle_hint"_test = [] {
    stdext::flat_map<int, int> values{{1, 10}, {3, 30}};
    const int key = 2;

    auto it = values.try_emplace(values.find(3), key, 20);

    expect(it->first == 2);
    expect(it->second == 20);
    expect(values == stdext::flat_map<int, int>{{1, 10}, {2, 20}, {3, 30}});
  };

  "try_emplace_with_rvalue_key_uses_valid_middle_hint"_test = [] {
    stdext::flat_map<int, int> values{{1, 10}, {3, 30}};

    auto it = values.try_emplace(values.find(3), 2, 20);

    expect(it->first == 2);
    expect(it->second == 20);
    expect(values == stdext::flat_map<int, int>{{1, 10}, {2, 20}, {3, 30}});
  };

  "try_emplace_with_existing_key_returns_existing_iterator"_test = [] {
    stdext::flat_map<int, int> values{{1, 10}, {3, 30}};
    const int key = 1;

    auto result = values.try_emplace(key, 20);

    expect(!result.second);
    expect(result.first->first == 1);
    expect(result.first->second == 10);
    expect(values == stdext::flat_map<int, int>{{1, 10}, {3, 30}});
  };

  "try_emplace_with_lvalue_key_returns_exact_hint_match"_test = [] {
    stdext::flat_map<int, int> values{{1, 10}, {3, 30}};
    const int key = 1;

    auto it = values.try_emplace(values.find(1), key, 20);

    expect(it->first == 1);
    expect(it->second == 10);
    expect(values == stdext::flat_map<int, int>{{1, 10}, {3, 30}});
  };

  "try_emplace_with_lvalue_key_returns_previous_hint_match"_test = [] {
    stdext::flat_map<int, int> values{{1, 10}, {3, 30}};
    const int key = 1;

    auto it = values.try_emplace(values.find(3), key, 20);

    expect(it->first == 1);
    expect(it->second == 10);
    expect(values == stdext::flat_map<int, int>{{1, 10}, {3, 30}});
  };

  "try_emplace_with_rvalue_key_returns_exact_hint_match"_test = [] {
    stdext::flat_map<int, int> values{{1, 10}, {3, 30}};

    auto it = values.try_emplace(values.find(1), 1, 20);

    expect(it->first == 1);
    expect(it->second == 10);
    expect(values == stdext::flat_map<int, int>{{1, 10}, {3, 30}});
  };

  "try_emplace_with_rvalue_key_returns_previous_hint_match"_test = [] {
    stdext::flat_map<int, int> values{{1, 10}, {3, 30}};

    auto it = values.try_emplace(values.find(3), 1, 20);

    expect(it->first == 1);
    expect(it->second == 10);
    expect(values == stdext::flat_map<int, int>{{1, 10}, {3, 30}});
  };

  "range_constructor_rolls_back_key_when_mapped_insert_throws"_test = [] {
    using Map = stdext::flat_map<int, throwing_mapped>;
    std::pair<int, throwing_mapped> input[] = {
        {1, throwing_mapped{10}},
        {2, throwing_mapped{20}},
    };
    input[1].second.throw_on_copy = true;

    expect(throws<std::runtime_error>([&] { [[maybe_unused]] Map values{input, input + 2}; }));
  };

  "try_emplace_rolls_back_key_when_mapped_emplace_throws"_test = [] {
    stdext::flat_map<int, throwing_mapped> values{{1, throwing_mapped{10}}, {3, throwing_mapped{30}}};

    expect(throws<std::runtime_error>([&] { (void)values.try_emplace(2, 20, true); }));
    expect(values.size() == 2U);
    expect(values.find(2) == values.end());
    expect(values.find(1)->second.value == 10);
    expect(values.find(3)->second.value == 30);
  };

  "replace_clears_when_mapped_container_assignment_throws"_test = [] {
    using Map = stdext::flat_map<int, int, std::less<int>, std::vector<int>, throwing_int_vector>;
    Map values{{1, 10}, {2, 20}};
    throwing_int_vector::throw_on_move_assign = true;

    expect(throws<std::runtime_error>([&] { values.replace(std::vector<int>{3, 4}, throwing_int_vector{30, 40}); }));

    throwing_int_vector::throw_on_move_assign = false;
    expect(values.empty());
  };

  "insert_or_assign_with_lvalue_key_and_existing_hint_assigns_value"_test = [] {
    stdext::flat_map<int, int> values{{1, 10}, {3, 30}};
    const int key = 1;

    auto it = values.insert_or_assign(values.find(1), key, 20);

    expect(it->first == 1);
    expect(it->second == 20);
    expect(values == stdext::flat_map<int, int>{{1, 20}, {3, 30}});
  };
};

int main() {
  const auto result = boost::ut::cfg<>.run({.report_errors = true});
  return static_cast<int>(result);
}
