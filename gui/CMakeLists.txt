cmake_minimum_required(VERSION 3.16)
project(pontus_gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

# The GUI links pontus-core through the pontus-ffi C-ABI shim (D-001). Build the
# Cargo workspace first (`cargo build`); this locates the resulting shared library
# and the hand-written header. Override the target dir for a release build:
#   cmake -DPONTUS_TARGET_DIR=../target/release ..
set(PONTUS_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../target/debug"
    CACHE PATH "Cargo target directory containing libpontus_ffi")
set(PONTUS_FFI_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../crates/pontus-ffi/include")

# Resolve the shared library directly from PONTUS_TARGET_DIR rather than via
# find_library, whose cache is independent of the target dir — configuring debug
# then release would otherwise keep linking the stale debug .so.
set(PONTUS_FFI_LIB "${PONTUS_TARGET_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}pontus_ffi${CMAKE_SHARED_LIBRARY_SUFFIX}")
if(NOT EXISTS "${PONTUS_FFI_LIB}")
    message(FATAL_ERROR
        "libpontus_ffi not found at ${PONTUS_FFI_LIB}.\n"
        "Run `cargo build` (or `--release`) in the workspace root first, "
        "or pass -DPONTUS_TARGET_DIR=<dir>.")
endif()

add_executable(pontus-gui
    src/main.cpp
    src/mainwindow.cpp
    src/scandialog.cpp
    src/diffdialog.cpp
    src/heatmapdialog.cpp
    src/riskdialog.cpp
    src/topologyview.cpp
    src/topologydialog.cpp
    src/pontusclient.cpp
)
target_include_directories(pontus-gui PRIVATE include "${PONTUS_FFI_INCLUDE}")
target_link_libraries(pontus-gui PRIVATE Qt6::Widgets "${PONTUS_FFI_LIB}")

# Find libpontus_ffi.so at runtime without LD_LIBRARY_PATH.
set_target_properties(pontus-gui PROPERTIES
    BUILD_RPATH "${PONTUS_TARGET_DIR}"
    INSTALL_RPATH "${PONTUS_TARGET_DIR}")
