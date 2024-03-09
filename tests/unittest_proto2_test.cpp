
#include "gpb_proto_json/gpb_proto_json.h"
#include "unittest_proto2_util.h"
namespace ut = boost::ut;


using TestRequired_meta = decltype(pb_meta(std::declval<protobuf_unittest::TestRequired>()));
static_assert(std::tuple_element_t<0, TestRequired_meta>::is_explicit_presence);

const ut::suite proto_test = [] {
  using namespace boost::ut;
  using namespace boost::ut::literals;

  "protobuf"_test =
      []<class T> {
        T message;
        T message2;
        T message3;

        if constexpr (requires { TestUtil::ExpectClear(message); }) {
          TestUtil::ExpectClear(message);
        }
        TestUtil::SetAll(&message);
        message2 = message;

        std::vector<std::byte> data;
        expect(hpp::proto::write_proto(message2, data).ok());
        expect(hpp::proto::read_proto(message3, data).ok());

        TestUtil::ExpectAllSet(message);
        TestUtil::ExpectAllSet(message2);
        TestUtil::ExpectAllSet(message3);
      } |
      std::tuple<protobuf_unittest::TestAllTypes, protobuf_unittest::TestAllExtensions,
                 protobuf_unittest::TestUnpackedTypes, protobuf_unittest::TestPackedTypes,
                 protobuf_unittest::TestPackedExtensions>{};

  "interoperate_with_google_protobuf_parser"_test =
      []<class T> {
        T original;

        TestUtil::SetAll(&original);

        std::vector<char> data;
        expect(hpp::proto::write_proto(original, data).ok());

        auto original_json = gpb_based::proto_to_json(unittest_proto2_descriptorset(),
                                                      hpp::proto::message_name(original), {data.data(), data.size()});

        auto generated_json = hpp::proto::write_json(original);

        expect(eq(generated_json.value(), original_json));

        T msg;
        expect(hpp::proto::read_json(msg, original_json).ok());

        TestUtil::ExpectAllSet(msg);
      } |
      std::tuple<protobuf_unittest::TestAllTypes, protobuf_unittest::TestUnpackedTypes,
                 protobuf_unittest::TestPackedTypes>{};
};

// TODO: need a test case of TestOneof2

int main() {
  const auto result = ut::cfg<>.run({.report_errors = true}); // explicitly run registered test suites and report errors
  return static_cast<int>(result);
}