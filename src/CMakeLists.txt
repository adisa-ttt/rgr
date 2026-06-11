add_executable(SilentChipher
    main.cpp
    plugin_loader.cpp
    io_manager.cpp
    key_manager.cpp
    crypto_operations.cpp)

target_include_directories(SilentChipher PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(SilentChipher PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(WIN32)
    target_link_libraries(SilentChipher PRIVATE advapi32)
else()
    target_link_libraries(SilentChipher PRIVATE dl)
endif()

if(MSVC)
    target_compile_options(SilentChipher PRIVATE /W4 /WX)
else()
    target_compile_options(SilentChipher PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
# Встраиваем путь к папке сборки, чтобы программа сама находила .so библиотеки
set_target_properties(SilentChipher PROPERTIES
    BUILD_RPATH "${CMAKE_BINARY_DIR}"
)
