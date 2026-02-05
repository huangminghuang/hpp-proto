from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from shutil import which


class HppProtoConan(ConanFile):
    name = "hpp-proto"
    version = "1.0.0"
    license = "Apache-2.0"
    url = "https://github.com/huangminghuang/hpp-proto"
    description = "A modern, high-performance, header-only C++23 implementation of Protocol Buffers."
    topics = ("protobuf", "serialization", "codegen", "header-only")
    settings = ("os", "compiler", "build_type", "arch")
    options = {
        "tests": [True, False],
        "use_system_glaze": [True, False],
    }
    default_options = {
        "tests": False,
        "use_system_glaze": True,
    }
    exports_sources = (
        "CMakeLists.txt",
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

    def configure(self):
        self.settings.compiler.cppstd = "23"

    def requirements(self):
        if self.options.use_system_glaze:
            self.requires("glaze/7.0.2")

    def tool_requirements(self):
        if not which("protoc"):
            self.tool_requires("protobuf/[>=3.21.12]")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.variables["HPP_PROTO_PROTOC_PLUGIN"] = "ON"
        tc.variables["HPP_PROTO_TESTS"] = "ON" if self.options.tests else "OFF"
        tc.variables["HPP_PROTO_PROTOC"] = "find"
        tc.variables["HPP_PROTO_USE_SYSTEM_GLAZE"] = "ON" if self.options.use_system_glaze else "OFF"
        try:
            protobuf = self.dependencies.build.get("protobuf")
        except KeyError:
            protobuf = None
        if protobuf and protobuf.cpp_info.bindirs:
            tc.variables["CMAKE_PROGRAM_PATH"] = ";".join(protobuf.cpp_info.bindirs)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "hpp_proto")
        self.cpp_info.set_property(
            "cmake_build_modules",
            ["lib/cmake/hpp_proto/protobuf_generate_hpp.cmake"],
        )
        lib = self.cpp_info.components["libhpp_proto"]
        lib.set_property("cmake_target_name", "hpp_proto::libhpp_proto")
        lib.includedirs = ["include"]
        if self.options.use_system_glaze:
            lib.requires = ["glaze::glaze"]
        lib.libs = ["is_utf8"]
