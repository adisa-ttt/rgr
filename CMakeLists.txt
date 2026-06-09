cmake_minimum_required(VERSION 3.10)
project(cryptum VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDART 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()
project(SilentCipher VERSION 1.0 LANGUAGES CXX)
set(PROJECT_SOURCES
	caesar.cpp
	
	
)

add_executable (${PROJECT_NAME} ${PROJECT_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE include)

# Линковка библиотек ОС для dlopen/SecureZeroMemory
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE advapi32)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE dl)
endif()
