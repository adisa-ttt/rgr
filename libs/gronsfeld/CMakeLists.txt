add_library(gronsfeld SHARED gronsfeld.cpp)
target_include_directories(gronsfeld PRIVATE ${CMAKE_SOURCE_DIR}/include)
set_target_properties(gronsfeld PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
