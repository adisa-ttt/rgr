add_library(caesar SHARED caesar.cpp)
target_include_directories(caesar PRIVATE ${CMAKE_SOURCE_DIR}/include)
set_target_properties(caesar PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
