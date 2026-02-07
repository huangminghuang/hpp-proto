#include <boost/ut.hpp>
#include <memory_resource>
#include <type_traits>

#include <hpp_proto/indirect.hpp>
#include <hpp_proto/indirect_view.hpp>

struct TestMessage {
  int i = 0;
  bool operator==(const TestMessage &) const = default;
  auto operator<=>(const TestMessage &) const = default;
};

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
      v = &msg2;
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
  };
};

int main() {
  const auto result = boost::ut::cfg<>.run({.report_errors = true});
  return static_cast<int>(result);
}
