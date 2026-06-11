add_library(atbash SHARED atbash.cpp)

target_include_directories(atbash PRIVATE ${CMAKE_SOURCE_DIR}/include)

set_target_properties(atbash PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
