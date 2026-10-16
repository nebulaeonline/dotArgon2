cmake_minimum_required(VERSION 3.20)
project(dotArgon2Native LANGUAGES C)

if(NOT WIN32 AND NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Only Windows, Linux, and macOS are supported")
endif()

set(ARGON2_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../argon2" CACHE PATH "Argon2 reference source tree")
set(DOTARGON2_RID "" CACHE STRING "Target RID (win/linux/osx, x64/arm64)")
if(NOT DOTARGON2_RID MATCHES "^(win|linux|osx)-(x64|arm64)$")
    message(FATAL_ERROR "Set DOTARGON2_RID to one of the six supported RIDs")
endif()
set(target_os "${CMAKE_MATCH_1}")
set(target_arch "${CMAKE_MATCH_2}")
if((WIN32 AND NOT target_os STREQUAL "win") OR
   (APPLE AND NOT target_os STREQUAL "osx") OR
   (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT target_os STREQUAL "linux"))
    message(FATAL_ERROR "RID does not match target OS")
endif()
include(CheckCSourceCompiles)
unset(RID_ARCH_MATCHES CACHE)
if(target_arch STREQUAL "arm64")
    set(arch_condition "defined(__aarch64__) || defined(_M_ARM64)")
    set(implementation ref)
else()
    set(arch_condition "defined(__x86_64__) || defined(_M_X64)")
    set(implementation opt)
endif()
check_c_source_compiles("#if !(${arch_condition})\n#error Wrong target architecture\n#endif\nint main(void) { return 0; }" RID_ARCH_MATCHES)
if(NOT RID_ARCH_MATCHES)
    message(FATAL_ERROR "Compiler architecture does not match RID; use a separate build directory per target")
endif()
find_package(Threads REQUIRED)
add_library(argon2 SHARED
    "${ARGON2_SOURCE_DIR}/src/argon2.c"
    "${ARGON2_SOURCE_DIR}/src/core.c"
    "${ARGON2_SOURCE_DIR}/src/encoding.c"
    "${ARGON2_SOURCE_DIR}/src/thread.c"
    "${ARGON2_SOURCE_DIR}/src/blake2/blake2b.c"
    "${ARGON2_SOURCE_DIR}/src/${implementation}.c")
target_include_directories(argon2 PUBLIC "${ARGON2_SOURCE_DIR}/include" PRIVATE "${ARGON2_SOURCE_DIR}/src")
target_link_libraries(argon2 PRIVATE Threads::Threads)
if(MSVC)
    set_property(TARGET argon2 PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    if(target_arch STREQUAL "x64")
        target_compile_options(argon2 PRIVATE /arch:AVX2)
    endif()
else()
    target_compile_definitions(argon2 PRIVATE A2_VISCTL=1)
    set_target_properties(argon2 PROPERTIES C_VISIBILITY_PRESET hidden)
    if(target_arch STREQUAL "x64")
        target_compile_options(argon2 PRIVATE -mavx2)
    endif()
endif()
if(APPLE)
    set_target_properties(argon2 PROPERTIES INSTALL_NAME_DIR "@rpath")
endif()
set(stage "${CMAKE_BINARY_DIR}/package/runtimes/${DOTARGON2_RID}/native")
add_custom_command(TARGET argon2 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${stage}"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:argon2>" "${stage}/$<TARGET_FILE_NAME:argon2>")
file(SHA256 "${ARGON2_SOURCE_DIR}/src/${implementation}.c" implementation_hash)
file(WRITE "${CMAKE_BINARY_DIR}/native-build.txt"
    "RID: ${DOTARGON2_RID}\nSource: ${ARGON2_SOURCE_DIR}\nImplementation: ${implementation}.c\nImplementation SHA256: ${implementation_hash}\nCompiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}\n")
enable_testing()
add_executable(argon2-smoke smoke.c)
target_link_libraries(argon2-smoke PRIVATE argon2)
add_test(NAME argon2-smoke COMMAND argon2-smoke)
