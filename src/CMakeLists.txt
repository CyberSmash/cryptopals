cmake_minimum_required(VERSION 3.17)
project(cryptopals)

set(CMAKE_CXX_STANDARD 14)

include_directories(../include)
set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
find_package(OpenSSL REQUIRED)
add_executable(level1 level1.cpp base64.c helpers.cpp xor.cpp ascii_analysis.cpp hamming.cpp cryptvec.cpp)
add_executable(level2 level2.cpp base64.c helpers.cpp xor.cpp cryptvec.cpp hamming.cpp)
add_executable(level3 level3.cpp base64.c helpers.cpp xor.cpp ascii_analysis.cpp cryptvec.cpp hamming.cpp)
add_executable(level4 level4.cpp file_ops.cpp helpers.cpp ascii_analysis.cpp xor.cpp base64.c aes.cpp cryptvec.cpp hamming.cpp level13.cpp)
add_executable(level5 level5.cpp file_ops.cpp helpers.cpp ascii_analysis.cpp xor.cpp base64.c cryptvec.cpp hamming.cpp)
add_executable(level6 level6.cpp file_ops.cpp helpers.cpp ascii_analysis.cpp xor.cpp base64.c cryptvec.cpp hamming.cpp)
add_executable(level7 level7.cpp file_ops.cpp helpers.cpp ascii_analysis.cpp xor.cpp base64.c aes.cpp hamming.cpp cryptvec.cpp)
add_executable(level8 level8.cpp aes.cpp cryptvec.cpp helpers.cpp base64.c hamming.cpp file_ops.cpp)
add_executable(level9 level9.cpp aes.cpp cryptvec.cpp hamming.cpp helpers.cpp base64.c)
add_executable(level10 level10.cpp aes.cpp cryptvec.cpp hamming.cpp helpers.cpp base64.c file_ops.cpp)
add_executable(level11 level11.cpp aes.cpp cryptvec.cpp hamming.cpp helpers.cpp base64.c file_ops.cpp oracle.cpp)
add_executable(level12 level12.cpp aes.cpp cryptvec.cpp hamming.cpp helpers.cpp base64.c file_ops.cpp oracle.cpp)
add_executable(level13 level13.cpp aes.cpp cryptvec.cpp hamming.cpp helpers.cpp base64.c file_ops.cpp oracle.cpp)


target_link_libraries(level4 OpenSSL::Crypto)
target_link_libraries(level7 OpenSSL::Crypto)
target_link_libraries(level8 OpenSSL::Crypto)
target_link_libraries(level9 OpenSSL::Crypto)
target_link_libraries(level10 OpenSSL::Crypto)
target_link_libraries(level11 OpenSSL::Crypto)
target_link_libraries(level12 OpenSSL::Crypto)
target_link_libraries(level13 OpenSSL::Crypto)


