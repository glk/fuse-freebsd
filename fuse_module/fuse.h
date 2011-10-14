/*
 * Just macros for switching some features on and off, some allover used macros
 * and debugging.
 */

#include "fuse4bsd.h"
#include "fuse_kernel.h"

/* Mapping versions to features */

#define FUSE_KERNELABI_GEQ(maj, min)	\
(FUSE_KERNEL_VERSION > (maj) || (FUSE_KERNEL_VERSION == (maj) && FUSE_KERNEL_MINOR_VERSION >= (min)))

#ifndef USE_OLD_CLONEHANDLER_API
#if __FreeBSD_version < 600034 || ( __FreeBSD_version >= 700000 && __FreeBSD_version < 700002 )
#define USE_OLD_CLONEHANDLER_API
#endif
#endif

#ifndef NEW_VNODES_ADJUSTED_MANUALLY
#if __FreeBSD_version >= 700034
#define NEW_VNODES_ADJUSTED_MANUALLY 1
#else
#define NEW_VNODES_ADJUSTED_MANUALLY 0
#endif
#endif

#ifndef VOP_OPEN_TAKES_FP
#if __FreeBSD_version >= 700044
#define VOP_OPEN_TAKES_FP 1
#else
#define VOP_OPEN_TAKES_FP 0
#endif
#endif

#ifndef VN_LOCK_TAKES_THREAD
#if __FreeBSD_version >= 800010
#define VN_LOCK_TAKES_THREAD 0
#else
#define VN_LOCK_TAKES_THREAD 1
#endif
#endif

#ifndef VOP_UNLOCK_TAKES_THREAD
#if __FreeBSD_version >= 800011
#define VOP_UNLOCK_TAKES_THREAD 0
#else
#define VOP_UNLOCK_TAKES_THREAD 1
#endif
#endif

#ifndef USE_PRIVILEGE_API
/*
 * __FreeBSD_version bump was omitted for introduction of
 * the privilege API (both when it's been added and when the
 * legacy API has been removed), so here we just use the first
 * value of __FreeBSD_version after adding the priv stuff.
 */
#if __FreeBSD_version >= 700025
#define USE_PRIVILEGE_API 1
#else
#define USE_PRIVILEGE_API 0
#endif
#endif
#if ! USE_PRIVILEGE_API
#define priv_check(td, priv) suser(td)
#define priv_check_cred(cred, priv, flag) suser_cred(cred, SUSER_ALLOWJAIL)
#endif

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

#ifndef FUSELIB_CONFORM_BIOREAD
/* 
 * make BIO behave as it's prescribed in fuselib's fuse.h,
 * ie. in case of buffered reading, short reads instruct
 * the kernel to fill the rest of the buffer with zeroes 
 */
#define FUSELIB_CONFORM_BIOREAD 1
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
#define FUSE_LOCK mtx_lock(&fuse_mtx)
#define FUSE_UNLOCK mtx_unlock(&fuse_mtx)
#else
#define FUSE_LOCK
#define FUSE_UNLOCK
#endif

#define RECTIFY_TDCR(td, cred)			\
do {						\
	if (! (td))				\
		(td) = curthread;		\
	if (! (cred))				\
		(cred) = (td)->td_ucred;	\
} while (0)

/* Debug related stuff */

#ifndef DEBUGTOLOG
#define DEBUGTOLOG 0
#endif
#if DEBUGTOLOG
#define dprintf(args ...)  log(LOG_DEBUG, args)
#else
#define dprintf(args ...)  printf(args)
#endif

#define DEBLABEL "[fuse-debug] "
#ifndef _DEBUG
#define _DEBUG 0
#endif
#if     _DEBUG
#ifndef _DEBUG2G
#define _DEBUG2G 1
#endif
#define DEBUG(args, ...)							\
	printf(DEBLABEL "%s <%s@%d>: " args, __func__, __FILE__, __LINE__, ## __VA_ARGS__)
#else
#define DEBUG(args ...)
#endif

#ifndef _DEBUG2G
#define _DEBUG2G 0
#endif
#if     _DEBUG2G
#ifndef _DEBUG3G
#define _DEBUG3G 1
#endif
#define DEBUG2G(args, ...)							\
	printf(DEBLABEL "%s <%s@%d>: " args, __func__, __FILE__, __LINE__, ## __VA_ARGS__)
#else
#define DEBUG2G(args ...)
#endif

#ifndef _DEBUG3G
#define _DEBUG3G 0
#endif
#if     _DEBUG3G
#define DEBUG3G(args, ...)							\
	printf(DEBLABEL "%s <%s@%d>: " args, __func__, __FILE__, __LINE__, ## __VA_ARGS__)
#else
#define DEBUG3G(args ...)
#endif

#ifndef FMASTER
#define FMASTER 0
#endif
#if     FMASTER
#ifndef _DEBUG_MSG
#define _DEBUG_MSG 1
#endif
#endif

#ifndef _DEBUG_MSG
#define _DEBUG_MSG 0
#endif
#if     _DEBUG_MSG
#define DEBUG_MSG(args, ...)							\
	printf(DEBLABEL "%s <%s@%d>: " args, __func__, __FILE__, __LINE__, ## __VA_ARGS__)
#else
#define DEBUG_MSG(args...)
#endif

#ifndef _DEBUG_UNIQUE
#if _DEBUG || _DEBUG2G || _DEBUG3G || _DEBUG_MSG
#define _DEBUG_UNIQUE 1
#else
#define _DEBUG_UNIQUE 0
#endif
#endif

#if _DEBUG || _DEBUG2G || _DEBUG3G || FMASTER
extern char *fuse_opnames[];
extern int fuse_opnames_entries;

struct fuse_iov;

void uprettyprint(char *buf, size_t len);
void prettyprint(char *buf, size_t len);
void fprettyprint(struct fuse_iov *fiov, size_t dlen);
#endif

#if _DEBUG || _DEBUG2G || _DEBUG3G || defined(INVARIANTS) || FUSELIB_CONFORM_BIOREAD
int isbzero(void *buf, size_t len);
#endif

#if _DEBUG || _DEBUG2G || _DEBUG3G
#include <sys/kdb.h>

#define bp_print(bp) \
printf("b_bcount %d, b_data %p, b_error %#x, b_iocmd %#x, b_ioflags %#x, b_iooffset %lld, b_resid %d, b_blkno %d, b_offset %lld, b_flags %#x, b_bufsize %d, b_lblkno %d, b_vp %p, b_vp_ino %llu, b_dirtyoff %d, b_dirtyend %d, b_npages %d\n", \
(int)(bp)->b_bcount, (bp)->b_data, (bp)->b_error, (bp)->b_iocmd, (bp)->b_ioflags, (long long)(bp)->b_iooffset, (int)(bp)->b_resid, (int)(bp)->b_blkno, (long long)(bp)->b_offset, (bp)->b_flags, (int)(bp)->b_bufsize, (int)(bp)->b_lblkno, (bp)->b_vp, VTOILLU((bp)->b_vp), (int)(bp)->b_dirtyoff, (int)(bp)->b_dirtyend, (int)(bp)->b_npages)
#endif
