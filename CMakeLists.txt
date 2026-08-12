cmake_minimum_required(VERSION 3.15)
project(rudeauth LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

# On by default when this repository IS the build, off when it is pulled into
# a host project with add_subdirectory().
#
# Someone who cloned the SDK wants the example — the quickstart tells them to
# run it, and defaulting these to OFF meant the documented commands produced no
# example binary and step four failed for every new user. Someone embedding the
# SDK in their own application wants neither.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(RUDEAUTH_STANDALONE ON)
else()
    set(RUDEAUTH_STANDALONE OFF)
endif()

option(RUDEAUTH_BUILD_TESTS "Build the SDK test binaries" ${RUDEAUTH_STANDALONE})
option(RUDEAUTH_BUILD_EXAMPLE "Build the example program" ${RUDEAUTH_STANDALONE})

if(NOT WIN32)
    message(FATAL_ERROR "The RudeAuth C++ SDK targets Windows. Other platforms need a different transport and fingerprint source.")
endif()

add_library(rudeauth STATIC
    src/crypto.cpp
    src/json.cpp
    src/http.cpp
    src/fingerprint.cpp
    src/client.cpp
    src/vendor/monocypher.c
    src/vendor/monocypher-ed25519.c
)

target_include_directories(rudeauth
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# winhttp: transport. advapi32: registry reads for the fingerprint.
# bcrypt: the system CSPRNG.
target_link_libraries(rudeauth PUBLIC winhttp advapi32 bcrypt)

if(MSVC)
    target_compile_options(rudeauth PRIVATE /W4)
    # The SDK reads the registry and calls WinHTTP directly; it does not use
    # the CRT functions MSVC deprecates.
    target_compile_definitions(rudeauth PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(rudeauth PRIVATE -Wall -Wextra)
endif()

if(RUDEAUTH_BUILD_TESTS)
    add_executable(rudeauth_crypto_test tests/crypto_test.cpp)
    target_link_libraries(rudeauth_crypto_test PRIVATE rudeauth)
    target_include_directories(rudeauth_crypto_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    add_executable(rudeauth_live_test tests/live_test.cpp)
    target_link_libraries(rudeauth_live_test PRIVATE rudeauth)

    enable_testing()
    add_test(NAME crypto
             COMMAND rudeauth_crypto_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors.json)
endif()

if(RUDEAUTH_BUILD_EXAMPLE)
    add_executable(rudeauth_example example/main.cpp)
    target_link_libraries(rudeauth_example PRIVATE rudeauth)
endif()
