#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int main(int argc, char **argv) { return LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t *>(*argv), argc); }
