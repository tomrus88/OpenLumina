cmake_minimum_required(VERSION 3.7)

project(OpenLumina C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(WIN32)
    #set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-fPIC")
    #set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fPIC")
elseif(APPLE)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-fPIC -arch x86_64")
    set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fPIC -arch x86_64")
elseif(UNIX)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-fPIC")
    set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fPIC")
else()
    message("Unknown platform!")
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

if(UNIX OR APPLE)
    find_package(OpenSSL REQUIRED)
endif()
find_package(IdaSdk REQUIRED)

include_directories(${PROJECT_SOURCE_DIR})

if (WIN32)
    set(PLATFORM_SUFFIX "win32")
elseif(APPLE)
    set(PLATFORM_SUFFIX "osx")
elseif (UNIX)
    set(PLATFORM_SUFFIX "elf")
endif()

set(plthooksrc
    "OpenLumina/plthook/plthook_${PLATFORM_SUFFIX}.c"
    "OpenLumina/plthook/plthook.h"
)

add_library(PltHookLib STATIC ${plthooksrc})
set_target_properties(PltHookLib PROPERTIES LINKER_LANGUAGE C)

set(src
    "OpenLumina/framework.h"
    "OpenLumina/pch.cpp"
    "OpenLumina/pch.h"
    "OpenLumina/plugin_ctx.h"
    "OpenLumina/OpenLumina.cpp"
)

add_ida_plugin(OpenLumina ${PROJECT_SOURCE_DIR}/OpenLumina/OpenLumina.cpp)

set_ida_target_properties(OpenLumina PROPERTIES CXX_STANDARD 20)
if(UNIX OR APPLE)
    if (OPENSSL_FOUND)
        ida_target_include_directories(OpenLumina PUBLIC ${OPENSSL_INCLUDE_DIR})
        message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
    else()
        message(STATUS "OpenSSL Not Found")
    endif()
endif()
ida_target_include_directories(OpenLumina PRIVATE ${IdaSdk_INCLUDE_DIRS})

add_ida_library(OpenLuminaLib ${src})
if (WIN32)
    ida_target_link_libraries(OpenLumina crypt32.lib)
endif()
if (UNIX OR APPLE)
    ida_target_link_libraries(OpenLumina OpenSSL::SSL)
endif()
ida_target_link_libraries(OpenLumina PltHookLib)
ida_target_link_libraries(OpenLumina OpenLuminaLib)
