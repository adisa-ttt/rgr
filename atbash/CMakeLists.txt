cmake_minimum_required(VERSION 3.10)
project(AtbashModule LANGUAGES CXX)

add_library(atbash MODULE atbash.cpp)

set_target_properties(atbash PROPERTIES 
    CXX_STANDARD 17 
    CXX_STANDARD_REQUIRED ON
)
