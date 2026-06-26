#include <recursive_map_cycle.pb.hpp>

#include <boost/ut.hpp>
#include <hpp_proto/binpb.hpp>
#include <vector>

// That this translation unit compiles at all is the primary assertion: code
// generation for the A<->B cycle plus Container's map<string, A> used to hang in
// order_messages, then (after a partial fix) emit non-compiling output. The
// round-trip confirms the generated types are usable.
const boost::ut::suite recursive_map_cycle = [] {
  using namespace boost::ut;
  using namespace hpp_proto_test;

  "compiles_and_round_trips"_test = [] {
    Container<> c;
    c.n = 7;
    c.by_name["x"]; // default-construct the map value (indirect_t<A>)

    std::vector<std::byte> buf;
    expect(hpp_proto::write_binpb(c, buf).ok());

    Container<> out;
    expect(hpp_proto::read_binpb(out, buf).ok());
    expect(out.n.has_value());
    expect(out.n.value() == 7_i);
    expect(out.by_name.contains("x"));
  };
};

int main() { return static_cast<int>(boost::ut::cfg<>.run({.report_errors = true})); }
