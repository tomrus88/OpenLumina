// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"

#include <cstdio>

#if __LINUX__
#include <dlfcn.h>
#include "openssl/x509.h"
#include <openssl/pem.h>
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>

//#include "detours/detours.h"
#include "plthook/plthook.h"

#include "plugin_ctx.h"

#endif //PCH_H
