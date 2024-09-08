#include "addressbook_lite.pb.hpp"

template <hpp::proto::compile_time_string str>
constexpr auto operator""_bytes_view() {
  return static_cast<hpp::proto::bytes_view>(hpp::proto::bytes_literal<str>{});
}

using enum tutorial::Person::PhoneType;
constexpr std::array<const tutorial::Person::PhoneNumber, 1> alex_phones{
        tutorial::Person::PhoneNumber{.number = "19890604", .type = PHONE_TYPE_MOBILE}};

int main() {
  constexpr auto alex_pb = hpp::proto::write_proto([] {
    return tutorial::Person{.name = "Alex", .id = 1, .email = "alex@email.com", .phones = alex_phones};
  });

  static_assert(std::ranges::equal(alex_pb,"\x0a\x04\x41\x6c\x65\x78\x10\x01\x1a\x0e\x61\x6c\x65\x78\x40\x65\x6d\x61\x69\x6c\x2e\x63\x6f\x6d\x22\x0c\x0a\x08\x31\x39\x38\x39\x30\x36\x30\x34\x10\x01"_bytes_view));
}