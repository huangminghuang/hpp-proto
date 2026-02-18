#include <iostream>
#include <source_location>
#include <string>
#include <vector>

#include <hpp_proto/dynamic_message/binpb.hpp>
#include <hpp_proto/dynamic_message/json.hpp>

// #include "addressbook_proto3.desc.hpp" // descriptor set for dynamic loading

inline void expect(bool condition, const std::source_location location = std::source_location::current()) {
  if (!condition) {
    std::cerr << "assertion failure at " << location.file_name() << ":" << location.line() << "\n";
    std::exit(1);
  }
}

inline std::string read_file(const char *filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  if (!in.is_open()) {
    return {};
  }
  std::string contents;
  in.seekg(0, std::ios::end);
  auto size = in.tellg();
  if (size <= 0) {
    return {};
  }
  contents.resize(static_cast<std::size_t>(size));
  in.seekg(0, std::ios::beg);
  if (!in.read(contents.data(), static_cast<std::streamsize>(contents.size()))) {
    return {};
  }
  return contents;
}

inline std::expected<void, hpp_proto::dynamic_message_errc>
operator&&(const std::expected<void, hpp_proto::dynamic_message_errc> &lhs,
           const std::expected<void, hpp_proto::dynamic_message_errc> &rhs) {
  return lhs.has_value() ? rhs : lhs;
}

int main() {
  // Build a factory from the compiled descriptor set.

  // Read the serialized FileDescriptorSet generated from
  //   `protoc --include_imports --descriptor_set_out=addressbook_proto3.desc.binpb addressbook_proto3.proto`
  auto filedescriptorset_binpb = read_file("addressbook_proto3.desc.binpb");

  // construct and init a dynamic_message_factory
  hpp_proto::dynamic_message_factory factory;
  expect(factory.init(filedescriptorset_binpb));

  // Allocate a message arena.
  std::pmr::monotonic_buffer_resource mr;
  auto expected_msg = factory.get_message("tutorial.AddressBook", mr);

  using namespace std::string_view_literals;
  using hpp_proto::expected_message_mref;

  // Add a person entry dynamically without throwing exception.
  expect(expected_msg
             .modify_field_by_name(
                 "people",
                 [](hpp_proto::repeated_message_field_mref people) {
                   return expected_message_mref{people.emplace_back()}
                       .set_field_by_name("name", "Alex"sv)
                       .set_field_by_name("id", 1)
                       .set_field_by_name("email", "alex@email.com"sv)
                       .modify_field_by_name("phones",
                                             [](hpp_proto::repeated_message_field_mref phones) {
                                               return expected_message_mref{phones.emplace_back()}
                                                   .set_field_by_name("number", "19890604"sv)
                                                   .set_field_by_name("type", hpp_proto::enum_name{"PHONE_TYPE_MOBILE"})
                                                   .done();
                                             })
                       .modify_field_by_name(
                           "nested_message",
                           [](hpp_proto::message_field_mref mref) {
                             return expected_message_mref{mref.emplace()}.set_field_by_name("bb", 89).done();
                           })
                       .modify_field_by_name(
                           "map_string_nested_message",
                           [](hpp_proto::repeated_message_field_mref mref) {
                             mref.resize(2);
                             return expected_message_mref{mref[0]}
                                        .set_field_by_number(1, "Tiananmen"sv)
                                        .modify_field_by_number(2,
                                                                [](hpp_proto::message_field_mref mref) {
                                                                  return expected_message_mref{mref.emplace()}
                                                                      .set_field_by_name("bb", 89)
                                                                      .done();
                                                                })
                                        .done() &&
                                    expected_message_mref{mref[1]}
                                        .set_field_by_number(1, "Square"sv)
                                        .modify_field_by_number(2,
                                                                [](hpp_proto::message_field_mref mref) {
                                                                  return expected_message_mref{mref.emplace()}
                                                                      .set_field_by_name("bb", 64)
                                                                      .done();
                                                                })
                                        .done();
                           })
                       .set_field_by_name("oneof_string",
                                          "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre"sv)
                       .done();
                 })
             .has_value());

  // Add a person entry dynamically with exception as error channel
  try {
    auto msg = expected_msg.value();
    auto people = msg.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("people").value();
    auto bob = people.emplace_back();
    expect(bob.set_field_by_name("name", "Bob").has_value());
    expect(bob.set_field_by_name("id", 2).has_value());
    expect(bob.set_field_by_name("email", "bob@email.com"sv).has_value());
    auto phones = bob.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("phones").value();
    auto phone = phones.emplace_back();
    expect(phone.set_field_by_name("number", "22222222").has_value());
    expect(phone.set_field_by_name("type", hpp_proto::enum_name{"PHONE_TYPE_HOME"}).has_value());
  } catch (const std::exception &ex) {
    std::cerr << ex.what() << '\n';
    expect(false);
  }

  // Serialize to proto
  std::string binary;
  auto msg = *expected_msg;
  expect(hpp_proto::write_binpb(msg, binary).ok());

  // Deserialize to a new dynamic message
  std::pmr::monotonic_buffer_resource mr2;
  auto address_book2 = factory.get_message("tutorial.AddressBook", mr2).value();
  expect(hpp_proto::read_binpb(address_book2, binary).ok());

  // check fields
  auto people2_expected = address_book2.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("people");
  expect(people2_expected.has_value());
  auto people2 = *people2_expected;
  expect(people2.size() == std::size_t{2});
  auto alex = people2[0];
  expect(alex.field_value_by_name<std::string_view>("name") == "Alex");
  expect(alex.field_value_by_name<std::int32_t>("id") == 1);
  expect(alex.field_value_by_name<std::string_view>("email") == "alex@email.com");

  auto alex_phones_expected = alex.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("phones");
  expect(alex_phones_expected.has_value());
  auto alex_phones = *alex_phones_expected;
  expect(alex_phones.size() == std::size_t{1});
  expect("19890604"sv == alex_phones[0].field_value_by_name<std::string_view>("number"));
  expect("PHONE_TYPE_MOBILE"sv == alex_phones[0].field_value_by_name<hpp_proto::enum_name>("type"));

  auto alex_nested_message_expected = alex.typed_ref_by_name<hpp_proto::message_field_cref>("nested_message");
  expect(alex_nested_message_expected.has_value());
  auto alex_nested_message_field = *alex_nested_message_expected;
  expect(alex_nested_message_field.has_value());
  expect((*alex_nested_message_field).field_value_by_name<std::int32_t>("bb") == 89);

  auto alex_map_string_nested_message_expected =
      alex.typed_ref_by_name<hpp_proto::repeated_message_field_cref>("map_string_nested_message");
  expect(alex_map_string_nested_message_expected.has_value());
  auto alex_map_string_nested_message = *alex_map_string_nested_message_expected;
  expect(alex_map_string_nested_message.size() == 2);
  expect("Tiananmen"sv == alex_map_string_nested_message[0].field_value_by_number<std::string_view>(1));
  auto v0 = alex_map_string_nested_message[0].typed_ref_by_number<hpp_proto::message_field_cref>(2);
  expect(v0.has_value());
  expect(89 == (*v0)->field_value_by_name<int32_t>("bb"sv));
  expect("Square"sv == alex_map_string_nested_message[1].field_value_by_number<std::string_view>(1));
  auto v1 = alex_map_string_nested_message[1].typed_ref_by_number<hpp_proto::message_field_cref>(2);
  expect(64 == (*v1)->field_value_by_name<int32_t>("bb"sv));

  expect(alex.field_value_by_name<std::string_view>("oneof_string") ==
         "https://en.wikipedia.org/wiki/1989_Tiananmen_Square_protests_and_massacre"sv);

  std::string json;
  expect(hpp_proto::write_json(msg, json).ok());
  auto address_book3 = factory.get_message("tutorial.AddressBook", mr2).value();
  expect(hpp_proto::read_json(address_book3, json).ok());
  auto people3_expected = address_book3.typed_ref_by_name<hpp_proto::repeated_message_field_mref>("people");
  auto people3 = *people3_expected;
  expect(people3.size() == std::size_t{2});
  return 0;
}
