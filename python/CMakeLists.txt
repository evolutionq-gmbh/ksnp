cmake_minimum_required(VERSION 3.18)

# When building locally, try and find nanobind in .venv using the Python
# instance configured there.
if (NOT DEFINED SKBUILD_PROJECT_NAME)
  if (NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/.venv")
    message(SEND_ERROR "A local build requires .venv to be configured")
  endif ()
  set(SKBUILD_PROJECT_NAME ksnp)
  set(SKBUILD_PROJECT_VERSION 0.0.1)
  execute_process(
    COMMAND "${CMAKE_CURRENT_LIST_DIR}/.venv/bin/python" -m nanobind --cmake_dir
    OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
endif ()

project(${SKBUILD_PROJECT_NAME} VERSION ${SKBUILD_PROJECT_VERSION} LANGUAGES C CXX)

find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)
find_package(nanobind CONFIG REQUIRED)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(BUILD_EXAMPLES OFF CACHE BOOL "")
set(BUILD_TEST OFF CACHE BOOL "")
set(BUILD_DOCS OFF CACHE BOOL "")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/.." ksnp_lib)

nanobind_add_module(_core
  NB_DOMAIN pyksnp_domain
  bindings/client.cpp
  bindings/ksnp.cpp
  bindings/serde.cpp
  bindings/server.cpp
  bindings/stream.cpp
)

nanobind_add_stub(
  pyksnp_stub
  MODULE ksnp._core
  RECURSIVE
  MARKER_FILE ksnp/py.typed
  OUTPUT_PATH ksnp
  OUTPUT
    ksnp/_core.pyi
    ksnp/_core/client.pyi
    ksnp/_core/client/event.pyi
    ksnp/_core/serde.pyi
    ksnp/_core/serde/messages.pyi
    ksnp/_core/server.pyi
    ksnp/_core/server/event.pyi
    ksnp/_core/stream.pyi
  PATTERN_FILE "${CMAKE_CURRENT_LIST_DIR}/bindings/type_patterns.txt"
  PYTHON_PATH $<TARGET_FILE_DIR:_core>
  DEPENDS _core
)

target_link_libraries(_core PRIVATE ksnp)
target_compile_features(_core PUBLIC cxx_std_20)
set_target_properties(_core PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/ksnp"
    CXX_STANDARD 20
)

# ksnp/__init__.py allows stubgen to find the ksnp package in the build dir.
file(WRITE ${CMAKE_BINARY_DIR}/ksnp/__init__.py "")

install(TARGETS _core LIBRARY DESTINATION "ksnp")
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/ksnp DESTINATION "." PATTERN "__init__.py" EXCLUDE)
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/src/ksnp DESTINATION ".")
