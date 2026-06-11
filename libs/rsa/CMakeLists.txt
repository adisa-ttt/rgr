add_library(rsa SHARED rsa.cpp)

target_include_directories(rsa PRIVATE ${CMAKE_SOURCE_DIR}/include)

set_target_properties(rsa PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)