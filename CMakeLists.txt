cmake_minimum_required(VERSION 3.12)

set(JANUS_PREFIX "/opt/janus" CACHE STRING "Janus Gateway install prefix")

project(janus-ptt-audioroom-plugin)

SET(CMAKE_INSTALL_PREFIX ${JANUS_PREFIX})

find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
pkg_search_module(LIBJANSSON REQUIRED jansson)
pkg_search_module(LIBOPUS REQUIRED opus)
pkg_search_module(LIBSRTP2 REQUIRED libsrtp2)
add_compile_definitions(HAVE_SRTP_2)

find_path(JANUS_INCLUDE_PATH janus/plugins/plugin.h
    PATHS ${JANUS_PREFIX}/include/)

if(JANUS_INCLUDE_PATH STREQUAL "JANUS_INCLUDE_PATH-NOTFOUND")
   message(FATAL_ERROR "Unable to find Janus includes in ${JANUS_PREFIX}/include/janus/plugins/plugin.h")
endif()

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    src/*.h
    src/*.c
    src/*.cpp
    conf/*.jcfg.sample
    snap/snapcraft.yaml
    snap/hooks/install
    README.md)

add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE
    ${JANUS_INCLUDE_PATH}
    ${JANUS_INCLUDE_PATH}/janus/
    ${JANUS_INCLUDE_PATH}/janus/plugins/
    ${GLIB_INCLUDE_DIRS}
    ${LIBJANSSON_INCLUDE_DIRS}
    ${LIBOPUS_INCLUDE_DIRS}
    ${LIBSRTP2_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME}
    ${LIBOPUS_LDFLAGS})

install(TARGETS ${PROJECT_NAME} DESTINATION lib/janus/plugins)
if(DEFINED ENV{SNAPCRAFT_PROJECT_NAME})
    install(FILES conf/janus.plugin.ptt-audioroom.jcfg.sample DESTINATION etc/janus)
endif()
