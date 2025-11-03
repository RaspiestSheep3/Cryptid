# CMakeList.txt : CMake project for Cryptid, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("Cryptid")

# Add source to this project's executable.
add_executable (Cryptid "Cryptid.cpp" "Cryptid.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET Cryptid PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
# Path to vcpkg install
set(VCPKG_ROOT "C:/Users/iniga/vcpkg/installed/x64-windows")

# Include path
target_include_directories(Cryptid PRIVATE "${VCPKG_ROOT}/include")

# Library path
target_link_libraries(Cryptid PRIVATE "${VCPKG_ROOT}/lib/libsodium.lib")

