cmake_minimum_required (VERSION 2.8)

project (forthtoy)

set (forthtoy_VERSION_MAJOR 0)
set (forthtoy_VERSION_MINOR 1)

# find_package(BISON REQUIRED)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
endif()

set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -g3 -O0")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -pedantic -Wall -Wextra -Werror -g3 -O0")

#if (NOT HAVE_STRDUP)
#  add_definitions( -DNEED_STRDUP )
#endif()

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/Build)
set(LIBRARY_OUTPUT_PATH    ${CMAKE_CURRENT_BINARY_DIR}/Build/Libraries)
set(MODULES_OUTPUT_PATH    ${CMAKE_CURRENT_BINARY_DIR}/Build/Modules)
set(CMAKE_INSTALL_PREFIX   ${CMAKE_CURRENT_BINARY_DIR}/Local)

#set(PARSER_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/jsonpc_parser")
#file(MAKE_DIRECTORY ${PARSER_OUTPUT_DIR})
#BISON_TARGET(jsonpc_parser source/jsonpc.y
#  ${PARSER_OUTPUT_DIR}/jsonpc.tab.c)

set(FORTHTOY_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Source)
set_property(GLOBAL PROPERTY FORTHTOY_INCLUDE_DIR ${FORTHTOY_INCLUDE_DIR})
include_directories(
  ${FORTHTOY_INCLUDE_DIR}
  # ${PARSER_OUTPUT_DIR}
  )

set(FORTHTOY_SRCS
  # ${BISON_jsonpc_parser_OUTPUTS}
  # ${BISON_jsonpc_parser_OUTPUT_HEADER}
  #Source/interp.h
  Source/interp.c

  )

add_library( forthtoy ${FORTHTOY_SRCS} )

add_executable( forthtoy_exe source/forth_main.c )
set_target_properties( forthtoy_exe PROPERTIES OUTPUT_NAME forthtoy )
target_link_libraries( forthtoy_exe forthtoy )

#add_subdirectory(deps)
#add_subdirectory(tests)

