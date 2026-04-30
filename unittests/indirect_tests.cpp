#include <boost/ut.hpp>
#include <memory_resource>
#include <stdexcept>
#include <type_traits>

#include "test_allocators.hpp"
#include <hpp_proto/indirect.hpp>
#include <hpp_proto/indirect_view.hpp>

// Test literals and intentionally mutable-looking setup values keep these cases readable.
// NOLINTBEGIN(misc-const-correctness, cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)

struct TestMessage {
  int i = 0;
  bool operator==(const TestMessage &) const = default;
  auto operator<=>(const TestMessage &) const = default;
};

struct ThrowingDefaultMessage {
  ThrowingDefaultMessage() { throw std::runtime_error("default construction failed"); }
  bool operator==(const ThrowingDefaultMessage &) const = default;
};

using indirect_with_throwing_move_ctor_alloc = hpp_proto::indirect<int, throwing_move_ctor_allocator<int>>;
using indirect_with_throwing_move_assign_alloc = hpp_proto::indirect<int, throwing_move_assign_allocator<int>>;
using indirect_with_throwing_swap_alloc = hpp_proto::indirect<int, throwing_swap_allocator<int>>;

static_assert(!std::is_nothrow_move_constructible_v<indirect_with_throwing_move_ctor_alloc>);
static_assert(!std::is_nothrow_move_assignable_v<indirect_with_throwing_move_assign_alloc>);
static_assert(!std::is_nothrow_swappable_v<indirect_with_throwing_swap_alloc>);

const boost::ut::suite indirect_tests = [] {
  using namespace boost::ut;

  "indirect"_test = [] {
    using Indirect = hpp_proto::indirect<TestMessage, std::pmr::polymorphic_allocator<TestMessage>>;
    using Alloc = std::pmr::polymorphic_allocator<TestMessage>;

    auto expect_allocator_eq = [](const Alloc &lhs, const Alloc &rhs) {
      if (lhs.resource() != rhs.resource()) {
        expect(lhs.resource() == rhs.resource());
      }
    };

    "default_ctor"_test = [] {
      Indirect ind;
      expect(ind->i == 0);
    };

    "allocator_ctor"_test = [&] {
      Alloc alloc{};
      Indirect ind(alloc);
      expect_allocator_eq(ind.get_allocator(), alloc);
      expect(ind->i == 0);
    };

    "allocator_arg_ctor"_test = [&] {
      Alloc alloc{};
      Indirect ind(std::allocator_arg, alloc);
      expect_allocator_eq(ind.get_allocator(), alloc);
      expect(ind->i == 0);
    };

    "value_ctor"_test = [] {
      TestMessage msg{42};
      Indirect ind(msg);
      expect(ind->i == 42);
    };

    "allocator_value_ctor"_test = [&] {
      Alloc alloc{};
      TestMessage msg{43};
      Indirect ind(std::allocator_arg, alloc, msg);
      expect(ind->i == 43);
      expect_allocator_eq(ind.get_allocator(), alloc);
    };

    "move_value_ctor"_test = [] {
      Indirect ind(TestMessage{44});
      expect(ind->i == 44);
    };

    "in_place_ctor"_test = [] {
      Indirect ind(std::in_place, 45);
      expect(ind->i == 45);
    };

    "copy_ctor"_test = [] {
      Indirect original(TestMessage{46});
      Indirect copy(original);
      expect(copy->i == 46);
      expect(original->i == 46);
      expect(copy == original);
      copy->i = 47;
      expect(copy->i == 47);
      expect(original->i == 46);
    };

    "allocator_copy_ctor"_test = [&] {
      Alloc alloc{};
      Indirect original(TestMessage{47});
      Indirect copy(std::allocator_arg, alloc, original);
      expect(copy->i == 47);
      expect_allocator_eq(copy.get_allocator(), alloc);
    };

    "move_ctor"_test = [] {
      Indirect original(TestMessage{48});
      Indirect moved(std::move(original));
      expect(moved->i == 48);
      // original is in a valid but unspecified state, pointer is null
      // expect(original.get_allocator() ...);
    };

    "allocator_move_ctor"_test = [&] {
      Alloc alloc{};
      Indirect original(TestMessage{49});
      Indirect moved(std::allocator_arg, alloc, std::move(original));
      expect(moved->i == 49);
      expect_allocator_eq(moved.get_allocator(), alloc);
    };

    "copy_assignment"_test = [] {
      Indirect lhs(TestMessage{10});
      Indirect rhs(TestMessage{20});
      lhs = rhs;
      expect(lhs->i == 20);
      expect(lhs == rhs);
    };

    "move_assignment"_test = [] {
      Indirect lhs(TestMessage{30});
      Indirect rhs(TestMessage{40});
      lhs = std::move(rhs);
      expect(lhs->i == 40);
    };

    "value_assignment"_test = [] {
      Indirect ind;
      ind = TestMessage{50};
      expect(ind->i == 50);
    };

    "accessors"_test = [] {
      Indirect ind(TestMessage{60});
      expect(ind.value().i == 60);
      expect((*ind).i == 60);
      expect(ind->i == 60);

      const Indirect cind(TestMessage{61});
      expect(cind.value().i == 61);
      expect((*cind).i == 61);
      expect(cind->i == 61);

      // Rvalue accessors
      static_assert(std::is_rvalue_reference_v<decltype(std::move(ind).value())>);
      static_assert(std::is_rvalue_reference_v<decltype(*std::move(ind))>);

      expect(std::move(ind).value().i == 60);
    };

    "swap"_test = [] {
      Indirect a(TestMessage{70});
      Indirect b(TestMessage{80});
      a.swap(b);
      expect(a->i == 80);
      expect(b->i == 70);
    };

    "comparison"_test = [] {
      Indirect a(TestMessage{90});
      Indirect b(TestMessage{90});
      Indirect c(TestMessage{91});
      expect(a == b);
      expect(a != c);
      expect(a == TestMessage{90});
      expect((a <=> b) == 0);
      expect((a <=> c) < 0);
    };
  };

  "indirect_view"_test = [] {
    using View = hpp_proto::indirect_view<TestMessage>;

    "default_ctor"_test = [] {
      View v;
      // Default constructed view points to a static default object
      expect(v->i == 0);
    };

    "pointer_ctor"_test = [] {
      TestMessage msg{100};
      View v(&msg);
      expect(v->i == 100);
    };

    "copy_ctor"_test = [] {
      TestMessage msg{101};
      View v1(&msg);
      View v2(v1);
      expect(v2->i == 101);
    };

    "assignment"_test = [] {
      TestMessage msg1{102};
      TestMessage msg2{103};
      View v(&msg1);
      expect(v->i == 102);
      v.reset(&msg2);
      expect(v->i == 103);
    };

    "accessors"_test = [] {
      TestMessage msg{104};
      View v(&msg);
      expect(v.value().i == 104);
      expect((*v).i == 104);
      expect(v->i == 104);
    };

    "comparison"_test = [] {
      TestMessage msg1{105};
      TestMessage msg2{105};
      TestMessage msg3{106};
      View v1(&msg1);
      View v2(&msg2);
      View v3(&msg3);

      expect(v1 == v2);
      expect(v1 != v3);
      expect(v1 == msg1);
      expect((v1 <=> v2) == 0);
      expect((v1 <=> v3) < 0);
    };

    "swap"_test = [] {
      TestMessage msg1{107};
      TestMessage msg2{108};
      View v1(&msg1);
      View v2(&msg2);
      v1.swap(v2);
      expect(v1->i == 108);
      expect(v2->i == 107);
    };

    "null_access_propagates_default_ctor_exception"_test = [] {
      hpp_proto::indirect_view<ThrowingDefaultMessage> v;
      expect(throws<std::runtime_error>([&] { (void)v.value(); }));
      expect(throws<std::runtime_error>([&] { (void)*v; }));
      expect(throws<std::runtime_error>([&] { (void)v.operator->(); }));
    };
  };
};

const boost::ut::suite indirect_exception_safety_tests = [] {
  using namespace boost::ut;

  "failing_value_construction_deallocates_allocation"_test = [] {
    auto state = std::make_shared<counting_alloc_state>();
    using Alloc = counting_allocator<throwing_constructible>;
    using Indirect = hpp_proto::indirect<throwing_constructible, Alloc>;

    expect(throws<std::runtime_error>(
        [&] { [[maybe_unused]] Indirect value(std::allocator_arg, Alloc{state}, std::in_place, -1); }));
    expect(eq(state->alloc_count, std::size_t{1}));
    expect(eq(state->dealloc_count, std::size_t{1}));
  };

  "copy_assignment_with_allocator_propagation_and_mismatch_reconstructs_storage"_test = [] {
    using Alloc = propagating_copy_allocator<int>;
    using Indirect = hpp_proto::indirect<int, Alloc>;

    Indirect lhs(std::allocator_arg, Alloc{1}, 1);
    Indirect rhs(std::allocator_arg, Alloc{2}, 7);

    lhs = rhs;

    expect(eq(*lhs, 7));
    expect(lhs.get_allocator() == rhs.get_allocator());
  };
};

// NOLINTEND(misc-const-correctness, cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)

// boost-ext/ut may allocate while parsing the test command line.
// NOLINTNEXTLINE(bugprone-exception-escape)
int main() {
  const auto result = boost::ut::cfg<>.run({.report_errors = true});
  return static_cast<int>(result);
}
