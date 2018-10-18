cmake_minimum_required(VERSION 3.12)
project(TestAES C)

set(CMAKE_C_STANDARD 99)
include_directories(${CMAKE_SOURCE_DIR}/aes/include)
add_executable(TestAES main.c aes/aes_core.c aes/aes_cbc.c aes/aes_cfb.c aes/aes_ecb.c aes/cbc128.c aes/cfb128.c aes/ctr128.c aes/ofb128.c aes/cts128.c aes/gcm128.c aes/ccm128.c aes/xts128.c aes/aes_misc.c)