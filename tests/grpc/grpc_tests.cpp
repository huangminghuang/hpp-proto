#include <boost/ut.hpp>

// NOLINTNEXTLINE(bugprone-exception-escape)
int main() {
  const auto result = boost::ut::cfg<>.run({.report_errors = true});
  return static_cast<int>(result);
}
