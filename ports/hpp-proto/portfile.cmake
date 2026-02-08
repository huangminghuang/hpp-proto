# Overlay-port layout in this repo: ports/hpp-proto/portfile.cmake -> source root is ../..
get_filename_component(SOURCE_PATH "${CURRENT_PORT_DIR}/../.." ABSOLUTE)

include("${CURRENT_HOST_INSTALLED_DIR}/share/vcpkg-cmake/vcpkg_cmake_configure.cmake")
include("${CURRENT_HOST_INSTALLED_DIR}/share/vcpkg-cmake/vcpkg_cmake_install.cmake")
include("${CURRENT_HOST_INSTALLED_DIR}/share/vcpkg-cmake-config/vcpkg_cmake_config_fixup.cmake")

set(hpp_proto_protoc_mode "find")
set(hpp_proto_extra_options)

if("vcpkg-protobuf" IN_LIST FEATURES)
    set(hpp_proto_protoc_mode "find")
    # Use vcpkg host-tools protobuf as protoc provider.
    list(APPEND hpp_proto_extra_options
        "-DCMAKE_PROGRAM_PATH=${CURRENT_HOST_INSTALLED_DIR}/tools/protobuf"
        "-DProtobuf_INCLUDE_DIRS=${CURRENT_HOST_INSTALLED_DIR}/include"
    )
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DHPP_PROTO_TESTS=OFF
        -DHPP_PROTO_BENCHMARKS=OFF
        -DHPP_PROTO_FUZZER_ONLY=OFF
        -DHPP_PROTO_PROTOC_PLUGIN=ON
        -DHPP_PROTO_PROTOC=${hpp_proto_protoc_mode}
        -DCPM_USE_LOCAL_PACKAGES=ON
        ${hpp_proto_extra_options}
)

vcpkg_cmake_install()

vcpkg_copy_tools(
    TOOL_NAMES protoc-gen-hpp
    AUTO_CLEAN
)

vcpkg_cmake_config_fixup(
    PACKAGE_NAME hpp_proto
    CONFIG_PATH lib/cmake/hpp_proto
)

vcpkg_copy_pdbs()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")

file(INSTALL "${SOURCE_PATH}/LICENSE"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
    RENAME copyright)
