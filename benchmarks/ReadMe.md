# Comparison with google protobuf C++ implementation
### System Configuration

| Platform |      Mac           |            Linux                |
|----------|--------------------|---------------------------------|
|    OS    |    MacOS 26.2      |         Ubuntu 24.04.2 LTS      |
|   CPU    |   Apple M1 Pro     |  11th Gen Intel(R) Core(TM) i9-11950H @ 2.60GHz |
| Compiler | Apple clang 17.0.0 |           gcc 13.3.0            |

Google protobuf version 33.2

### Runtime Performance

We measured the runtime performance using the dataset and the benchmarks.proto definition from Google Protocol Buffers version 3.6.0. The benchmarks focus on three core operations: deserialization, setting a message (set_message), and setting a message combined with serialization (set_message and serialize). The performance was evaluated on two implementations: Google Protocol Buffers and hpp-proto, with regular and arena/non-owning modes being tested for each operation.

<table>
  <tr>
    <td>
      <a href="Mac_bench.json"><img src="Mac_bench.png" alt="Mac Benchmark" width="400"></a>
    </td>
    <td>
      <a href="Linux_bench.json"><img src="Linux_bench.png" alt="Linux Benchmark" width="400"></a>
    </td>
  </tr>
</table>

[Raw benchmark outputs: Linux_bench.result](Linux_bench.result) • [Mac_bench.result](Mac_bench.result)

The benchmarks show hpp-proto ahead of Google protobuf for deserialization, set_message, and set_message+serialize. The largest gains come from hpp-proto non-owning paths, which reduce allocations and copies.

[Benchmark code is available here](benchmark.cpp)
#### Detailed Observations (Linux numbers; Mac has the same shape)

Key observations
- hpp-proto is consistently faster than Google protobuf across deserialize, set_message, and set_message+serialize; biggest wins are in non-owning paths.
- Proto3 is slower than proto2 for string-heavy decode, especially on big payloads, consistent with UTF-8 validation overheads.

Deserialize: google vs hpp-proto
- Regular: proto2 google 208 ns vs hpp-proto 202 ns; proto3 google 243 ns vs hpp-proto 203 ns.
- Arena/non-owning: proto2 google 200 ns vs hpp-proto 141 ns; proto3 google 239 ns vs hpp-proto 160 ns.

Deserialize: ownership vs non-owning (hpp-proto)
- Non-owning deserialization is the largest gain: proto2 141 ns vs 202 ns; proto3 160 ns vs 203 ns.

Deserialize: padded input + repeated_packed
- Padded input: non-owning further reduces time (proto2 101 ns vs 188 ns; proto3 144 ns vs 192 ns).
- repeated_packed: hpp-proto regular 2511 ns vs google regular 3852 ns; hpp-proto non-owning 2465 ns vs google arena 3941 ns.

Serialize (set-message pipeline + pure serialize)
- Set-message only: hpp-proto is faster than Google protobuf (regular proto2 54.5 ns vs 106 ns, proto3 33.1 ns vs 108 ns; arena/non-owning proto2 18.5 ns vs 98.6 ns, proto3 10.7 ns vs 104 ns).
- Serialize-only: google proto2 64.5 ns vs hpp-proto 85.1 ns; google proto3 98.8 ns vs hpp-proto 102 ns.
- Set-message+serialize: hpp-proto still leads (regular proto2 136 ns vs 181 ns, proto3 142 ns vs 215 ns; arena/non-owning proto2 98.8 ns vs 186 ns, proto3 119 ns vs 220 ns).
- Google protobuf can be faster in serialize-only because it focuses on emission from already-constructed objects, while hpp-proto’s advantage shows up in the end-to-end pipeline where its message construction paths are cheaper; the message layout choice (bitmask presence vs optional field wrappers) can be the key factor.

### Code Size
We compared the code sizes of three equivalent programs: [hpp_proto_decode_encode](hpp_proto_decode_encode.cpp), [google_decode_encode](google_decode_encode.cpp) and [google_decode_encode_lite](google_decode_encode_lite.cpp). These programs are responsible for decoding and encoding messages defined in [benchmarks.proto](https://github.com/protocolbuffers/protobuf/blob/v3.6.0/benchmarks/benchmarks.proto), using the hpp-proto and Google Protocol Buffers implementations. The google_decode_encode program is statically linked with libprotobuf, while google_decode_encode_lite is linked with libprotobuf-lite.

<table>
  <tr>
    <td>
      <a href="Mac_sizes.json"><img src="Mac_sizes.png" alt="Mac Size Comparison" width="400"></a>
    </td>
    <td>
      <a href="Linux_sizes.json"><img src="Linux_sizes.png" alt="Linux Size Comparison" width="400"></a>
    </td>
  </tr>
</table>

### Running the Benchmarks

To run the benchmarks and update the results on your local machine, configure the project with `HPP_PROTO_BENCHMARKS=ON` and build the `benchmarks` target:

```bash
cmake -B build -DHPP_PROTO_BENCHMARKS=ON
cmake --build build --target benchmarks
```

This will generate and update the `.json` and `.png` files in the `benchmarks` directory.
