cmake_minimum_required(VERSION 3.30)
project(lab06_task01 C)

set(CMAKE_C_STANDARD 23)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(lab06_task01 task01.c)

target_link_libraries(lab06_task01 OpenSSL::SSL OpenSSL::Crypto)
