# hpp-proto

hpp_proto is a C++20-based tool that simplifies the use of Protocol Buffers in C++. The tool achieves this by generating C++ aggregate types from .proto files and providing a header only library to encode/decode Protobuf data using these types. It's worth noting that the generated aggregate types heavily use the C++ Standard Library containers such as std::vector and std::string, in contrast to the Google implementation, which makes them easier to use and integrate with existing C++ codebases. 

## Features
* All Protocol Buffers message definitions are mapped to simple C++ aggregates based on standard C++ library.
* Each generated C++ aggregate are associated with static C++ reflection data for protobuf encoding and decoding.
* Each generated C++ aggregate also contains [glaze](https://github.com/stephenberry/glaze) compatible meta data for JSON serialization.
* Both Protocol Buffers syntax 2 and 3 (except `service` and the deprecated `group`) are supported.


## Requirements
* cmake 3.14+
* g++ 11+ or clang++ 13+

