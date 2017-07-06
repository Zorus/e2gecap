cmake_minimum_required(VERSION 3.7)
project(e2gecap)

set(CMAKE_CXX_STANDARD 14)
include(ExternalProject)
include(GNUInstallDirs)

# Path settings
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib-static)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Libs
find_package(PkgConfig)
find_package(Threads)
find_package(ECAP REQUIRED)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/e2guardian)

set(LIBS_INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${ECAP_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/e2guardian/src
        )
set(LIBS_LIBRARIES "${CMAKE_THREAD_LIBS_INIT};${ECAP_LIBRARIES};e2guardian-static;")

# Compiler settings
set(GENERAL_WARNING_FLAGS "-Wall -Wno-unused-variable -Wno-unused-function")
set(GENERAL_DEBUG_FLAGS "-g3 -O0 -fvar-tracking-assignments")
set(GENERAL_RELEASE_FLAGS "-mtune=native -O2 -fomit-frame-pointer")
set(GENERAL_COMPILER_FLAGS "-fPIC -pthread -pipe -fstack-protector-strong --param=ssp-buffer-size=4")

set(CMAKE_CXX_FLAGS "-std=c++14 ${CMAKE_CXX_FLAGS} ${GENERAL_WARNING_FLAGS} ${GENERAL_COMPILER_FLAGS} ${ECAP_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${GENERAL_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "${GENERAL_RELEASE_FLAGS}")

# Source file globbing
file(GLOB_RECURSE MLS_SOURCE_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp"
)

# Create module
add_library(e2gecap SHARED ${MLS_SOURCE_FILES})
target_include_directories(e2gecap PUBLIC ${LIBS_INCLUDE_DIRS})
target_link_libraries(e2gecap PUBLIC ${LIBS_LIBRARIES})
set_target_properties(e2gecap PROPERTIES OUTPUT_NAME ecap-test PREFIX "")

add_custom_target(e2gecap-copy
        COMMAND cp ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/ecap-test.so /usr/local/lib/ecap-test.so
        DEPENDS ecap-test
)

add_custom_target(e2gecap-deploy
    COMMAND sudo service squid restart
    DEPENDS ecap-test-copy
)


# Install
install(TARGETS
    e2gecap
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
