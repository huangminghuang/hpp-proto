vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO simdutf/is_utf8
    REF 77103c7462b9498f0bbc238260d1f1408a66a461
    SHA512 9280df82aaf077e661e33352651976b2af7a686ed0ad51c6da959534168b6cb8e5a8f3e22073fe3dda0f4bad5a9990882678615604c2dd794b36692f6fc11f5b
    PATCHES
        fix-install-and-benchmarks.patch
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_TESTING=OFF
        -DIS_UTF8_BUILD_BENCHMARKS=OFF
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(
    PACKAGE_NAME is_utf8
    CONFIG_PATH lib/cmake/is_utf8
)
vcpkg_copy_pdbs()

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
)

vcpkg_install_copyright(FILE_LIST
    "${SOURCE_PATH}/LICENSE-APACHE"
    "${SOURCE_PATH}/LICENSE-BOOST"
    "${SOURCE_PATH}/LICENSE-MIT"
)
