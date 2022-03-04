cmake_minimum_required(VERSION 3.17)
project(cryptopals)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(src)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/data/)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/data/level4_data.txt ${CMAKE_CURRENT_BINARY_DIR}/data/level4_data.txt COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/data/level6_data.txt ${CMAKE_CURRENT_BINARY_DIR}/data/level6_data.txt COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/data/level7_data.txt ${CMAKE_CURRENT_BINARY_DIR}/data/level7_data.txt COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/data/level8_data.txt ${CMAKE_CURRENT_BINARY_DIR}/data/level8_data.txt COPYONLY)