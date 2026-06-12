add_library(vigenere SHARED caesar.cpp)
target_include_directories(vigenere PRIVATE ${CMAKE_SOURCE_DIR}/include)
set_target_properties(vigenere PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)