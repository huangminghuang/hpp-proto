#include <boost/ut.hpp>
#include <memory_resource>
#include <optional>

#include <hpp_proto/field_types.hpp>
#include <hpp_proto/json.hpp>

template <typename Traits = ::hpp::proto::default_traits>
struct TestRecursiveMessage {
  using hpp_proto_traits_type = Traits;
  Traits::template optional_indirect_t<TestRecursiveMessage> a;
  std::int32_t i{};

  [[no_unique_address]] ::hpp::proto::pb_unknown_fields<Traits> unknown_fields_;
  bool operator==(const TestRecursiveMessage &) const = default;
};

template <typename Traits>
struct glz::meta<TestRecursiveMessage<Traits>> {
  using T = TestRecursiveMessage<Traits>;
  static constexpr auto value = object("a", &T::a, "i", &T::i);
};

const boost::ut::suite optional_indirect_tests = [] {
  using namespace boost::ut;

  "optional_indirect"_test = []<class Traits> {
    using Message = TestRecursiveMessage<Traits>;
    using Optional = typename Traits::template optional_indirect_t<Message>;
    using Alloc = typename Optional::allocator_type;

    auto expect_allocator_eq = [](const Alloc &lhs, const Alloc &rhs) {
      if constexpr (requires { lhs.resource(); }) {
        expect(lhs.resource() == rhs.resource());
      } else if constexpr (requires { lhs == rhs; }) {
        expect(lhs == rhs);
      }
    };

    "default_ctor"_test = [] {
      Optional opt;
      expect(!opt.has_value());
      expect(!static_cast<bool>(opt));
    };

    "allocator_ctor"_test = [&] {
      Alloc alloc{};
      Optional opt(alloc);
      expect_allocator_eq(opt.get_allocator(), alloc);
    };

    "allocator_arg_ctor"_test = [&] {
      Alloc alloc{};
      Optional opt(std::allocator_arg, alloc);
      expect_allocator_eq(opt.get_allocator(), alloc);
    };

    "nullopt_ctor"_test = [] {
      Optional opt(std::nullopt);
      expect(!opt.has_value());
    };

    "allocator_nullopt_ctor"_test = [&] {
      Alloc alloc{};
      Optional opt(std::allocator_arg, alloc, std::nullopt);
      expect(!opt.has_value());
      expect_allocator_eq(opt.get_allocator(), alloc);
    };

    "value_ctor"_test = [] {
      Message msg;
      msg.i = 7;
      Optional opt(msg);
      expect(opt.has_value());
      expect(opt->i == 7);
    };

    "allocator_value_ctor"_test = [&] {
      Alloc alloc{};
      Message msg;
      msg.i = 9;
      Optional opt(std::allocator_arg, alloc, msg);
      expect(opt.has_value());
      expect(opt->i == 9);
      expect_allocator_eq(opt.get_allocator(), alloc);
    };

    "copy_ctor"_test = [] {
      Message msg;
      msg.i = 1;
      Optional original(msg);
      Optional copy(original); // NOLINT(performance-unnecessary-copy-initialization)
      expect(copy.has_value());
      expect(copy->i == 1);
    };

    "allocator_copy_ctor"_test = [&] {
      Alloc alloc{};
      Message msg;
      msg.i = 2;
      Optional original(alloc);
      original.emplace(msg);
      Optional copy(std::allocator_arg, alloc, original);
      expect(copy.has_value());
      expect(copy->i == 2);
      expect_allocator_eq(copy.get_allocator(), alloc);
    };

    "move_ctor"_test = [] {
      Optional original;
      original.emplace().i = 3;
      Optional moved(std::move(original));
      expect(moved.has_value());
      expect(moved->i == 3);
    };

    "allocator_move_ctor_same_allocator"_test = [&] {
      Alloc alloc{};
      Optional original(alloc);
      original.emplace().i = 4;
      Optional moved(std::allocator_arg, alloc, std::move(original));
      expect(moved.has_value());
      expect(moved->i == 4);
    };

    "allocator_move_ctor_different_allocator"_test = [&] {
      if constexpr (requires(Alloc a) { a.resource(); }) {
        std::pmr::monotonic_buffer_resource mr1;
        std::pmr::monotonic_buffer_resource mr2;
        Alloc alloc1{&mr1};
        Alloc alloc2{&mr2};
        Optional original(alloc1);
        original.emplace().i = 5;
        Optional moved(std::allocator_arg, alloc2, std::move(original));
        expect(moved.has_value());
        expect(moved->i == 5);
        expect(original.has_value()); // NOLINT different allocators: move leaves original intact
      } else {
        expect(true);
      }
    };

    "in_place_ctor"_test = [] {
      Optional opt(std::in_place);
      expect(opt.has_value());
    };

    "allocator_in_place_ctor"_test = [&] {
      Alloc alloc{};
      Optional opt(std::allocator_arg, alloc, std::in_place);
      expect(opt.has_value());
      expect_allocator_eq(opt.get_allocator(), alloc);
    };

    "copy_assignment"_test = [] {
      Optional lhs;
      Optional rhs;
      rhs.emplace().i = 6;
      lhs = rhs;
      expect(lhs.has_value());
      expect(lhs->i == 6);
    };

    "move_assignment"_test = [] {
      Optional lhs;
      Optional rhs;
      rhs.emplace().i = 7;
      lhs = std::move(rhs);
      expect(lhs.has_value());
      expect(lhs->i == 7);
    };

    "value_access"_test = [] {
      Optional opt;
      expect(throws<std::bad_optional_access>([&] { (void)opt.value(); }));
      opt.emplace().i = 8;
      expect(opt.value().i == 8);
      expect((*opt).i == 8);
      expect(opt->i == 8);
    };

    "emplace_overloads"_test = [] {
      Optional opt;
      opt.emplace();
      opt->i = 9;
      expect(opt->i == 9);

      Message msg;
      msg.i = 10;
      opt.emplace(msg);
      expect(opt->i == 10);
    };

    "swap_and_reset"_test = [] {
      Optional a;
      Optional b;
      a.emplace().i = 11;
      b.emplace().i = 12;
      a.swap(b);
      expect(a->i == 12);
      expect(b->i == 11);
      a.reset();
      expect(!a.has_value());
    };

    "comparison"_test = [] {
      Optional a;
      Optional b;
      expect(a == b);
      a.emplace().i = 13;
      expect(!(a == b));
      Message msg;
      msg.i = 13;
      expect(a == msg);
    };

    "nullopt_comparison"_test = [] {
      Optional opt;
      expect(opt == std::nullopt);
      opt.emplace();
      expect(opt != std::nullopt);
    };

    "value_assignment"_test = [] {
      Optional opt;
      Message msg;
      msg.i = 55;
      opt = msg; // Lvalue assignment
      expect(opt->i == 55);

      msg.i = 66;
      opt = std::move(msg); // Rvalue assignment
      expect(opt->i == 66);
    };

    "rvalue_accessors"_test = [] {
      Optional opt;
      opt.emplace().i = 42;
      // Verify rvalue ref qualification
      static_assert(std::is_rvalue_reference_v<decltype(std::move(opt).value())>);
      static_assert(std::is_rvalue_reference_v<decltype(*std::move(opt))>);

      Message msg = std::move(opt).value();
      expect(msg.i == 42);
    };

    "monadic_and_then"_test = [] {
      Optional opt;
      auto none = opt.and_then([](const Message &) { return Optional{}; });
      expect(!none.has_value());

      opt.emplace().i = 21;
      auto some = opt.and_then([](const Message &m) {
        Optional out;
        out.emplace().i = m.i + 1;
        return out;
      });
      expect(some.has_value());
      expect(some->i == 22);

      // Test rvalue overload
      auto some_rvalue = std::move(opt).and_then([](Message &&m) {
        Optional out;
        out.emplace().i = m.i + 2;
        return out;
      });
      expect(some_rvalue.has_value());
      expect(some_rvalue->i == 23);
    };

    "monadic_transform"_test = [] {
      Optional opt;
      auto none = opt.transform([](const Message &m) { return m.i; });
      expect(!none.has_value());

      opt.emplace().i = 30;
      auto some = opt.transform([](const Message &m) { return m.i + 2; });
      expect(some.has_value());
      expect(some.value() == 32);

      // Test rvalue overload
      auto some_rvalue = std::move(opt).transform([](Message &&m) { return m.i + 3; });
      expect(some_rvalue.has_value());
      expect(some_rvalue.value() == 33);
    };

    "monadic_or_else"_test = [] {
      Optional opt;
      auto none = opt.or_else([] {
        Optional out;
        out.emplace().i = 40;
        return out;
      });
      expect(none.has_value());
      expect(none->i == 40);

      opt.emplace().i = 41;
      auto some = opt.or_else([] {
        Optional out;
        out.emplace().i = 42;
        return out;
      });
      expect(some.has_value());
      expect(some->i == 41);

      // Test rvalue overload
      auto some_rvalue = std::move(opt).or_else([] {
        Optional out;
        out.emplace().i = 43;
        return out;
      });
      expect(some_rvalue.has_value());
      expect(some_rvalue->i == 41);
    };

    "json"_test = [] {
      Message msg;
      msg.a.emplace().i = 10;
      msg.i = 100;

      std::string json;
      expect(hpp::proto::write_json(msg, json).ok());
      std::string expected_json = R"({"a":{"i":10},"i":100})";
      expect(eq(expected_json, json));

      Message msg1;
      expect(hpp::proto::read_json(msg1, expected_json).ok());
      expect(msg == msg1);
    };
  } | std::tuple<hpp::proto::default_traits, hpp::proto::pmr_traits>{};
};

int main() {
  const auto result =
      boost::ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}
