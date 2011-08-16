/*
 * Copyright (C) 2005 Csaba Henk.
 * All Rights Reserved.
 * See COPYRIGHT file for additional information.
 */

#include <sys/cdefs.h>

/* Debug related stuff */

#ifndef FUSE_DEBUG_MODULE
#error "FUSE_DEBUG_MODULE is not defined"
#else
#define FUSE_DEBUG_VAR		__CONCAT(FUSE_DEBUG_,FUSE_DEBUG_MODULE)
#endif

#define DEBUG(fmt, ...)         DEBUGX(FUSE_DEBUG_VAR >= 1, fmt, ## __VA_ARGS__)
#define DEBUG2G(fmt, ...)       DEBUGX(FUSE_DEBUG_VAR >= 2, fmt, ## __VA_ARGS__)

#define debug_printf(fmt, ...)  DEBUG(fmt, ## __VA_ARGS__)
#define kdebug_printf(fmt, ...) DEBUG(fmt, ## __VA_ARGS__)

#define fuse_trace_printf(fmt, ...) \
    DEBUGX(FUSE_DEBUG_VAR && FUSE_TRACE, fmt, ## __VA_ARGS__)
#define fuse_trace_printf_func() \
    fuse_trace_printf("%s:%d\n", __FILE__, __LINE__)
#define fuse_trace_printf_vfsop() fuse_trace_printf_func()
#define fuse_trace_printf_vnop()  fuse_trace_printf_func()
