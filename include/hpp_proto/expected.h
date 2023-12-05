#pragma once

#if __cplusplus >= 202302L
#include <expected>
#else
#include <tl/expected.hpp>
#endif

namespace hpp::proto {
#if defined(__cpp_lib_expected)
using std::expected;
using std::unexpected;
#else
using tl::expected;
using tl::unexpected;
#endif
}