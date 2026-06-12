add_executable(crypto_tests
    crypto_tests.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto_operations.cpp
    ${CMAKE_SOURCE_DIR}/src/plugin_loader.cpp
)

target_include_directories(crypto_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

if(NOT WIN32)
    target_link_libraries(crypto_tests PRIVATE dl)
endif()

set_target_properties(crypto_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    BUILD_RPATH "${CMAKE_BINARY_DIR}"
)

add_test(NAME crypto_tests COMMAND crypto_tests)
