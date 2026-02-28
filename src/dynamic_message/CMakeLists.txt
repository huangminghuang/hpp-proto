include(GenerateExportHeader)

add_library( dynamic_message factory.cpp )
generate_export_header(
    dynamic_message
    BASE_NAME HPP_PROTO_DYNAMIC_MESSAGE
    EXPORT_FILE_NAME "${PROJECT_BINARY_DIR}/include/hpp_proto/dynamic_message/export.hpp"
)
file( GLOB_RECURSE HPP_PROTO_DYNAMIC_MESSAGE_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/hpp_proto/dynamic_message/*.hpp" )
target_sources( dynamic_message PUBLIC
    FILE_SET HEADERS
    BASE_DIRS "${PROJECT_SOURCE_DIR}/include"
    FILES ${HPP_PROTO_DYNAMIC_MESSAGE_PUBLIC_HEADERS} )
target_sources( dynamic_message PUBLIC
    FILE_SET HEADERS
    BASE_DIRS "${PROJECT_BINARY_DIR}/include"
    FILES "${PROJECT_BINARY_DIR}/include/hpp_proto/dynamic_message/export.hpp" )
target_compile_features( dynamic_message PUBLIC cxx_std_23 )
target_compile_options( dynamic_message PRIVATE ${HPP_PROTO_COMPILE_OPTIONS} )
target_link_libraries( dynamic_message PUBLIC hpp_proto_core well_known_types )
add_library( hpp_proto::dynamic_message ALIAS dynamic_message )
install( TARGETS dynamic_message EXPORT hpp_proto-targets
    FILE_SET HEADERS DESTINATION include )
