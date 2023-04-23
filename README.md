# hpp-proto

This is hpp-proto, a modern C++ 20 implementation of the Google Protocol Buffers data serialization format. It includes 

* a Google protoc plugin which converts Protocol Buffer .proto files to C++ code. 
* a header only library libhpp_proto build on top of [zpp-bits](https://github.com/eyalz800/zpp_bits) which implements protobuf encoding and decoding.


## Features
* All Protocol Buffers message definitions are mapped to simple C++ aggregates based on standard C++ library.
* Each generated C++ aggregate are associated with static C++ reflection data for protobuf encoding and decoding.
* Each generated C++ aggregate also contains [glaze](https://github.com/stephenberry/glaze) compatible meta data for JSON serialization.
* Both Protocol Buffers syntax 2 and 3 (except `service` and the deprecated `group`) are supported.


## Requirements
* cmake 3.14+
* g++ 11+ or clang++ 13+

