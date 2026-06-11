add_library(scytale SHARED scytale.cpp)
target_include_directories(scytale PRIVATE ${CMAKE_SOURCE_DIR}/include)
set_target_properties(scytale PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

