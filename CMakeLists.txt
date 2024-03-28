cmake_minimum_required(VERSION 3.7)

project(OpenLumina C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(APPLE)
  set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fPIC -arch x86_64")
else()
  set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fPIC")
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package(IdaSdk REQUIRED)

include_directories(${PROJECT_SOURCE_DIR})

if (WIN32)
    set(PLATFORM_SUFFIX "win32")
elseif (UNIX)
    set(PLATFORM_SUFFIX "elf")
elseif(APPLE)
    set(PLATFORM_SUFFIX "osx")
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
ida_target_include_directories(OpenLumina PRIVATE ${IdaSdk_INCLUDE_DIRS})

add_ida_library(OpenLuminaLib ${src})
ida_target_link_libraries(OpenLumina crypt32.lib)
ida_target_link_libraries(OpenLumina PltHookLib)
ida_target_link_libraries(OpenLumina OpenLuminaLib)
