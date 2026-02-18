from conan import ConanFile
from conan.tools.files import copy
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.build import check_min_cppstd
import os
from shutil import which


class HppProtoConan(ConanFile):
    name = "hpp_proto"
    version = "1.0.0"
    license = "Apache-2.0"
    url = "https://github.com/huangminghuang/hpp-proto"
    description = "A modern C++23 implementation of Protocol Buffers."
    topics = ("protobuf", "serialization", "codegen", "header-only")
    settings = ("os", "compiler", "build_type", "arch")
    options = {
        "tests": [True, False],
        "with_protobuf": [True, False],
    }
    default_options = {
        "tests": False,
        "with_protobuf": False,
    }
    exports_sources = (
        "CMakeLists.txt",
        "hpp_proto.cmake",
        "cmake/*",
        "hpp_proto-config.cmake.in",
        "third-parties.cmake",
        "include/*",
        "protoc-plugin/*",
        "tests/*",
        "tutorial/*",
        "LICENSE",
        "README.md",
    )

    def validate(self):
        cppstd = self.settings.get_safe("compiler.cppstd")
        if cppstd is not None:
            check_min_cppstd(self, "23")

    def requirements(self):
        self.requires("glaze/7.0.2")

    def build_requirements(self):
        self.protoc_mode = self.conf.get("user.hpp_proto:protoc", default="find")
        if self.options.with_protobuf:
            self.tool_requires("protobuf/[>=3.21.12]")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.variables["HPP_PROTO_PROTOC_PLUGIN"] = "ON"
        tc.variables["HPP_PROTO_TESTS"] = "ON" if self.options.tests else "OFF"
        tc.variables["HPP_PROTO_PROTOC"] = self.protoc_mode
        self.protoc_executable = None
        if self.options.with_protobuf:
            protobuf_dep = self.dependencies.build.get("protobuf")
            if protobuf_dep is not None:
                self.protoc_executable = os.path.join(protobuf_dep.package_folder, "bin", "protoc")
                if os.path.isfile(self.protoc_executable):
                    tc.variables["PROTOC_PROGRAM"] = self.protoc_executable
                else:
                    self.protoc_executable = None
        tc.variables["CPM_USE_LOCAL_PACKAGES"] = "ON"
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        cmake_config_folder = os.path.join(self.package_folder, "lib", "cmake", "hpp_proto")
        src_cmake_folder = os.path.join(self.source_folder, "cmake")
        
        if self.protoc_executable:
            src = os.path.join(src_cmake_folder, "conan_protoc_target.cmake")
            dest = os.path.join(cmake_config_folder, "conan_protoc_target.cmake")
            with open(src, "r", encoding="utf-8") as handle:
                existing = handle.read()
            with open(dest, "w", encoding="utf-8") as handle:
                handle.write(f"set(PROTOC_PROGRAM \"{self.protoc_executable}\")\n" + existing)
        else: 
            copy(self, "conan_protoc_target.cmake", src=src_cmake_folder, dst=cmake_config_folder)

    def package_info(self):
        self.cpp_info.libs = ["is_utf8"]
        self.cpp_info.set_property("cmake_target_name", "hpp_proto::hpp_proto")
        self.cpp_info.requires = ["glaze::glaze"]

        self.cpp_info.set_property(
            "cmake_build_modules",
            ["lib/cmake/hpp_proto/conan_protoc_target.cmake",
             "lib/cmake/hpp_proto/protobuf_generate_hpp.cmake"],
        )

        self.cpp_info.set_property("cmake_file_name", "hpp_proto")
