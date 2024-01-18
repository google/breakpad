
cmake_minimum_required(VERSION 3.26)
project(dump_syms
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

find_package(DiaSDK)

add_executable(dump_syms
  dump_syms.cc)
target_sources(dump_syms PRIVATE
  ../../../common/windows/dia_util.cc
  ../../../common/windows/guid_string.cc
  ../../../common/windows/omap.cc
  ../../../common/windows/pdb_source_line_writer.cc
  ../../../common/windows/pe_source_line_writer.cc
  ../../../common/windows/pe_util.cc
  ../../../common/windows/string_utils.cc)
target_include_directories(dump_syms PRIVATE
  ../../..
  ${DIASDK_INCLUDE_DIR})
target_link_libraries(dump_syms PRIVATE
  DbgHelp
  ImageHlp
  ${DIASDK_LIBRARIES})

