/*
 * Just macros for switching some features on and off, some allover used macros
 * and debugging.
 */

#include "fuse4bsd.h"
#include "fuse_kernel.h"

/* Mapping versions to features */

#define FUSE_KERNELABI_GEQ(maj, min)	\
(FUSE_KERNEL_VERSION > (maj) || (FUSE_KERNEL_VERSION == (maj) && FUSE_KERNEL_MINOR_VERSION >= (min)))

/*
 * Appearance of new FUSE operations is not always in par with version
 * numbering... At least, 7.3 is a sufficient condition for having
 * FUSE_{ACCESS,CREATE}.
 */
#if FUSE_KERNELABI_GEQ(7, 3)
#ifndef FUSE_HAS_ACCESS
#define FUSE_HAS_ACCESS 1
#endif
#ifndef FUSE_HAS_CREATE
#define FUSE_HAS_CREATE 1
#endif
#else /* FUSE_KERNELABI_GEQ(7, 3) */
#ifndef FUSE_HAS_ACCESS
#define FUSE_HAS_ACCESS 0
#endif
#ifndef FUSE_HAS_CREATE
#define FUSE_HAS_CREATE 0
#endif
#endif

#if FUSE_KERNELABI_GEQ(7, 7)
#ifndef FUSE_HAS_GETLK
#define FUSE_HAS_GETLK 1
#endif
#ifndef FUSE_HAS_SETLK
#define FUSE_HAS_SETLK 1
#endif
#ifndef FUSE_HAS_SETLKW
#define FUSE_HAS_SETLKW 1
#endif
#ifndef FUSE_HAS_INTERRUPT
#define FUSE_HAS_INTERRUPT 1
#endif
#else /* FUSE_KERNELABI_GEQ(7, 7) */
#ifndef FUSE_HAS_GETLK
#define FUSE_HAS_GETLK 0
#endif
#ifndef FUSE_HAS_SETLK
#define FUSE_HAS_SETLK 0
#endif
#ifndef FUSE_HAS_SETLKW
#define FUSE_HAS_SETLKW 0
#endif
#ifndef FUSE_HAS_INTERRUPT
#define FUSE_HAS_INTERRUPT 0
#endif
#endif

#if FUSE_KERNELABI_GEQ(7, 8)
#ifndef FUSE_HAS_FLUSH_RELEASE
#define FUSE_HAS_FLUSH_RELEASE 1
/*
 * "DESTROY" came in the middle of the 7.8 era,
 * so this is not completely exact...
 */
#ifndef FUSE_HAS_DESTROY
#define FUSE_HAS_DESTROY 1
#endif
#endif
#else /* FUSE_KERNELABI_GEQ(7, 8) */
#ifndef FUSE_HAS_FLUSH_RELEASE
#define FUSE_HAS_FLUSH_RELEASE 0
#ifndef FUSE_HAS_DESTROY
#define FUSE_HAS_DESTROY 0
#endif
#endif
#endif

/* misc */

extern int fuse_useco;
SYSCTL_DECL(_vfs_fuse);

/* Fuse locking */

#ifndef DO_GIANT_MANUALLY
#define DO_GIANT_MANUALLY 1
#endif
#ifndef USE_FUSE_LOCK
#define USE_FUSE_LOCK 1
#endif

#if USE_FUSE_LOCK
extern struct mtx fuse_mtx;
#define FUSE_LOCK() fuse_lck_mtx_lock(fuse_mtx)
#define FUSE_UNLOCK() fuse_lck_mtx_unlock(fuse_mtx)
#else
#define FUSE_LOCK()
#define FUSE_UNLOCK()
#endif

#define RECTIFY_TDCR(td, cred)			\
do {						\
	if (! (td))				\
		(td) = curthread;		\
	if (! (cred))				\
		(cred) = (td)->td_ucred;	\
} while (0)

/* Debug related stuff */

#ifndef FUSE_DEBUG_DEVICE
#define FUSE_DEBUG_DEVICE               0
#endif

#ifndef FUSE_DEBUG_FILE
#define FUSE_DEBUG_FILE                 0
#endif

#ifndef FUSE_DEBUG_INTERNAL
#define FUSE_DEBUG_INTERNAL             0
#endif

#ifndef FUSE_DEBUG_IO
#define FUSE_DEBUG_IO                   0
#endif

#ifndef FUSE_DEBUG_IPC
#define FUSE_DEBUG_IPC                  0
#endif

#ifndef FUSE_DEBUG_LOCK
#define FUSE_DEBUG_LOCK                 0
#endif

#ifndef FUSE_DEBUG_VFSOPS
#define FUSE_DEBUG_VFSOPS               0
#endif

#ifndef FUSE_DEBUG_VNOPS
#define FUSE_DEBUG_VNOPS                0
#endif

#ifndef FUSE_TRACE
#define FUSE_TRACE                      0
#endif

#define DEBUGX(cond, fmt, ...) do {                     \
    if (((cond))) {                                     \
        printf("%s: " fmt, __func__, ## __VA_ARGS__);   \
    } } while (0)

#define fuse_lck_mtx_lock(mtx) do {                                     \
    DEBUGX(FUSE_DEBUG_LOCK, "0:   lock(%s): %s@%d by %d\n",             \
        __STRING(mtx), __func__, __LINE__, curthread->td_proc->p_pid);  \
    mtx_lock(&(mtx));                                                   \
    DEBUGX(FUSE_DEBUG_LOCK, "1:   lock(%s): %s@%d by %d\n",             \
        __STRING(mtx), __func__, __LINE__, curthread->td_proc->p_pid);  \
    } while (0)

#define fuse_lck_mtx_unlock(mtx) do {                                   \
    DEBUGX(FUSE_DEBUG_LOCK, "0: unlock(%s): %s@%d by %d\n",             \
        __STRING(mtx), __func__, __LINE__, curthread->td_proc->p_pid);  \
    mtx_unlock(&(mtx));                                                 \
    DEBUGX(FUSE_DEBUG_LOCK, "1: unlock(%s): %s@%d by %d\n",             \
        __STRING(mtx), __func__, __LINE__, curthread->td_proc->p_pid);  \
    } while (0)

typedef enum fuse_op_waitfor {
    FUSE_OP_BACKGROUNDED = 0,
    FUSE_OP_FOREGROUNDED = 1,
} fuse_op_waitfor_t;
