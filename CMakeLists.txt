cmake_minimum_required(VERSION 3.12)

project(KNSP VERSION 0.2 LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

option(BUILD_EXAMPLES "Include the server and client example binaries" ON)
option(BUILD_DOCS "Add a target for generating documentation using Doxygen" ON)
option(BUILD_TEST "Add targets to build tests. Supported only if Boost is available" ON)

include(GNUInstallDirs)

find_package(Boost CONFIG)
find_package(Doxygen)
find_package(LibUUID REQUIRED)
find_package(json-c CONFIG REQUIRED)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
set(CMAKE_LINK_WARNING_AS_ERROR ON)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-W -Wall -Wextra -pedantic)
  add_compile_options($<$<CONFIG:Release>:-ffile-prefix-map="${CMAKE_CURRENT_SOURCE_DIR}=.">)
  if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wunsafe-buffer-usage -fsafe-buffer-usage-suggestions)
  endif ()
elseif (MSVC)
  add_compile_options(/W4)
endif ()

file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/ksnp/version.h"
  CONTENT "\
/// @brief Major library version.
///
/// Different major revisions are API or ABI incompatible.
static int const KSNP_VERSION_MAJOR = ${CMAKE_PROJECT_VERSION_MAJOR};
/// @brief Minor library version.
///
/// Incremented for changes that at most only extend the API and ABI.
static int const KSNP_VERSION_MINOR = ${CMAKE_PROJECT_VERSION_MINOR};
/// @brief Human-readable library version string.
static char const KSNP_VERSION[] = \"${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}$<$<CONFIG:Debug>:-dbg>\";
"
)

set(PUBLIC_HEADERS
  include/ksnp/client.h
  include/ksnp/compat.h
  include/ksnp/messages.h
  include/ksnp/serde.h
  include/ksnp/server.h
  include/ksnp/types.h
  "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/ksnp/version.h"
)

add_library(ksnp STATIC
  src/client.cpp
  src/client.hpp
  src/serde.cpp
  src/server.cpp
  src/server.hpp
  src/types.cpp
  src/empty.c
  ${PUBLIC_HEADERS}
)

target_link_libraries(ksnp PUBLIC LibUUID::LibUUID json-c::json-c)
target_include_directories(ksnp PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_include_directories(ksnp PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src)
target_compile_features(ksnp PUBLIC cxx_std_20)
target_compile_features(ksnp PUBLIC c_std_23)

set_target_properties(ksnp PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")

add_library(KSNP::ksnp ALIAS ksnp)

install(TARGETS ksnp
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ksnp
)

if (BUILD_TEST OR BUILD_EXAMPLES)
  add_library(example_common OBJECT examples/common.cpp examples/common.hpp)
  target_link_libraries(example_common PUBLIC ksnp)
  target_include_directories(example_common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/examples ${CMAKE_CURRENT_LIST_DIR}/src)
  target_compile_features(example_common PUBLIC cxx_std_20)
endif (BUILD_TEST OR BUILD_EXAMPLES)

if (BUILD_TEST AND Boost_FOUND)
  add_executable(test_api
    test/test_main.cpp
    test/test_serde.cpp
    test/test_client_server.cpp
  )
  target_link_libraries(test_api PRIVATE Boost::boost KSNP::ksnp example_common)
  target_include_directories(test_api PRIVATE ${CMAKE_CURRENT_LIST_DIR}/test)
  target_compile_features(test_api PRIVATE cxx_std_20)
endif (BUILD_TEST AND Boost_FOUND)

if (BUILD_EXAMPLES)
  add_executable(client examples/client_example.cpp)
  target_link_libraries(client PRIVATE ksnp example_common)
  target_compile_features(client PRIVATE cxx_std_20)

  add_executable(server examples/server_example.cpp)
  target_link_libraries(server PRIVATE ksnp example_common)
  target_compile_features(server PRIVATE cxx_std_20)

  add_executable(stream examples/stream.c)
  target_link_libraries(stream PRIVATE ksnp LibUUID::LibUUID)
  target_compile_features(stream PRIVATE c_std_23)
endif (BUILD_EXAMPLES)

if (BUILD_DOCS AND Doxygen_FOUND)
  set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/api_docs")
  set(DOXYGEN_FILE_PATTERNS *.c *.cpp *.h *.hpp)
  set(DOXYGEN_HTML_COLORSTYLE "TOGGLE")
  set(DOXYGEN_QUIET YES)
  set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${CMAKE_CURRENT_LIST_DIR}/README.md")
  set(DOXYGEN_WARN_IF_UNDOCUMENTED YES)
  set(DOXYGEN_ENABLE_PREPROCESSING YES)
  set(DOXYGEN_MACRO_EXPANSION YES)
  set(DOXYGEN_EXPAND_ONLY_PREDEF YES)
  set(DOXYGEN_PREDEFINED "ENUM_TYPE(x,y)=enum x: y" "ENUM_TYPE_T(x,y)=typedef y x;" "NODISCARD=[[nodiscard]]" "NOEXCEPT=")
  set(DOXYGEN_EXCLUDE_SYMBOLS "ENUM_TYPE" "ENUM_TYPE_T" "NODISCARD" "NOEXCEPT" "unused")

  doxygen_add_docs(api_docs "${CMAKE_CURRENT_LIST_DIR}/README.md" "include/" ALL)

  set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/example_docs")
  set(DOXYGEN_USE_MDFILE_AS_MAINPAGE)
  set(DOXYGEN_WARN_IF_UNDOCUMENTED NO)
  set(DOXYGEN_ENABLE_PREPROCESSING NO)
  set(DOXYGEN_MACRO_EXPANSION NO)
  set(DOXYGEN_PREDEFINED)
  set(DOXYGEN_EXCLUDE_SYMBOLS)

  doxygen_add_docs(example_docs examples/client_example.cpp examples/server_example.cpp examples/common.hpp ALL)
endif(BUILD_DOCS AND Doxygen_FOUND)
