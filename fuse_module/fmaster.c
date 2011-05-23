/*
 * THIS FILE SERVES JUST FOR DIAGNOSTIC PURPOSES.
 * It implements devices for emulating vfs events for fuse, for testing and
 * for showing demo code of how vfs event handlers can interact with fuse
 * messaging.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/condvar.h>
#include <sys/queue.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/sysctl.h>

#include "fuse.h"
#include "fuse_ipc.h"

#if ! FUSE_KERNELABI_GEQ(7, 5)
#define fuse_init_out fuse_init_in_out
#endif

#define fuprintf(args...)	\
	uprintf("[kern] " args)

/* We need some data from other components which are normally kept private */

extern int  __fticket_aw_pull_uio(struct fuse_ticket *tick, struct uio *uio);
extern int  __fuse_body_audit(struct fuse_ticket *tick, size_t blen);
extern int  __fticket_wait_answer(struct fuse_ticket *tick);

extern fuse_handler_t __fuse_standard_handler;

MALLOC_DECLARE(M_FUSEMSG);

struct clonedevs {                   
	LIST_HEAD(,cdev)        head;
};
extern struct clonedevs *fuseclones;

/* prettyprint routines */

static void pp_fuse_entry_out(struct fuse_entry_out *stru);
static void pp_fuse_open_out(struct fuse_open_out *stru);
static void pp_fuse_write_out(struct fuse_write_out *stru);
#if 0
static void pp_fuse_getxattr_out(struct fuse_getxattr_out *stru);
#endif
static void pp_fuse_init_out(struct fuse_init_out *stru);
static void pp_fuse_attr_out(struct fuse_attr_out *stru);
static void pp_fuse_statfs_out(struct fuse_statfs_out *stru);
static void pp_buf(struct fuse_iov *fiov);
static void fuse_response_prettyprint(enum fuse_opcode opcode, struct fuse_iov *fresp);

fuse_handler_t prettyprint_handler;

d_open_t      fmaster_open;
d_close_t     fmaster_close;
// d_read_t      fmaster_read;
d_write_t     fmaster0_write, fmaster1_write, fmaster2_write, fmaster3_write, fmaster4_write;

struct cdevsw fmaster_cdevsw[] = {

	{
		.d_open = fmaster_open,
		.d_close = fmaster_close,
		.d_name = "fmaster0",
	//	.d_read = fmaster_read,
		.d_write = fmaster0_write,
		.d_version = D_VERSION
#if ! DO_GIANT_MANUALLY
		.d_flags = D_NEEDGIANT,
#endif
	},
	{
		.d_open = fmaster_open,
		.d_close = fmaster_close,
		.d_name = "fmaster1",
	//	.d_read = fmaster_read,
		.d_write = fmaster1_write,
		.d_version = D_VERSION
#if ! DO_GIANT_MANUALLY
		.d_flags = D_NEEDGIANT,
#endif
	},
	{
		.d_open = fmaster_open,
		.d_close = fmaster_close,
		.d_name = "fmaster2",
	//	.d_read = fmaster_read,
		.d_write = fmaster2_write,
		.d_version = D_VERSION
#if ! DO_GIANT_MANUALLY
		.d_flags = D_NEEDGIANT,
#endif
	},
	{
		.d_open = fmaster_open,
		.d_close = fmaster_close,
		.d_name = "fmaster3",
	//	.d_read = fmaster_read,
		.d_write = fmaster3_write,
		.d_version = D_VERSION
#if ! DO_GIANT_MANUALLY
		.d_flags = D_NEEDGIANT,
#endif
	},
	{
		.d_open = fmaster_open,
		.d_close = fmaster_close,
		.d_name = "fmaster4",
	//	.d_read = fmaster_read,
		.d_write = fmaster3_write,
		.d_version = D_VERSION
#if ! DO_GIANT_MANUALLY
		.d_flags = D_NEEDGIANT,
#endif
	}
};

/*******************************
 *
 * >>> Fuse master device dev ops
 *
 ******************************/

int
fmaster_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
#if DO_GIANT_MANUALLY 
	mtx_lock(&Giant);
#endif
	if (fuse_useco < 0) {
		/* Module unload is going on */
#if DO_GIANT_MANUALLY 
		mtx_unlock(&Giant);
#endif
		DEBUG2G("caught in the middle of unload\n");
		return (ENOENT);
	}
	fuse_useco++;
#if DO_GIANT_MANUALLY
 	mtx_unlock(&Giant);
#endif

	DEBUG2G("Opened device \"fmaster\" (that of minor %d) successfully on thread %d.\n",
	        minor(dev), td->td_tid);

	return(0);
}

int
fmaster_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	fuse_useco--;

	DEBUG2G("Closed device \"fmaster\" (that of minor %d) successfully on thread %d.\n",
	        minor(dev), td->td_tid);

	return(0);
}

#if DO_GIANT_MANUALLY && ! USE_FUSE_LOCK
#define FMASTER_LOCK mtx_lock(&Giant)
#define FMASTER_UNLOCK mtx_unlock(&Giant)
#else
#define FMASTER_LOCK FUSE_LOCK
#define FMASTER_UNLOCK FUSE_UNLOCK
#endif


#define FMASTER_COMMON_INBLAHBLAH					\
	int err = 0;							\
	struct fuse_ticket *tick;					\
	size_t len;							\
	struct fuse_in_header *ihead;					\
	struct cdev *fusedev;						\
	struct fuse_data *data;						\
									\
	FMASTER_LOCK;							\
	if (! (fusedev = LIST_FIRST(&fuseclones->head))) {		\
		FMASTER_UNLOCK;						\
		return (ENXIO);						\
	}								\
									\
	if (! (data = fusedev_get_data(fusedev))) {			\
		FMASTER_UNLOCK;						\
		uprintf("first fuse device is not in use\n");		\
		err = ENXIO;						\
		goto out;						\
	}								\
	data->mntco++;							\
	dev_ref(fusedev);						\
	FMASTER_UNLOCK;							\
									\
	len = uio->uio_iov->iov_len;					\
									\
	if (len > 2 * data->max_write || len < sizeof(*ihead)) {	\
		uprintf("Bogus input for fmaster!");			\
		err = EINVAL;						\
		goto out;						\
	}								\
									\
	tick = fuse_ticket_fetch(data);					\
	fiov_adjust(&tick->tk_ms_fiov, len);				\
									\
	err = uiomove(tick->tk_ms_fiov.base, len, uio);			\
									\
	if (err != 0) {							\
		uprintf("Write failed: bad address!\n");		\
		fuse_ticket_drop(tick);					\
		goto out;						\
	}								\
									\
	ihead = (struct fuse_in_header *)tick->tk_ms_fiov.base;		\
	ihead->unique = tick->tk_unique;

#define FMASTER_COMMON_OUTBLAHBLAH					\
out:									\
	if (data) {							\
		data->mntco--;						\
		FMASTER_LOCK;						\
		if (data->mntco == 0 &&					\
		    ! (data->dataflag & FSESS_OPENED)) {		\
			fusedev->si_drv1 = NULL;			\
			fdata_destroy(data);				\
		}							\
		FMASTER_UNLOCK;						\
		dev_rel(fusedev);					\
	}								\
	return (err);

/*
 * example how a syscall handler routine can send a request when answer is ignorable
 */

int
fmaster0_write(struct cdev *dev, struct uio *uio, int ioflag)
{

	FMASTER_COMMON_INBLAHBLAH		/* style(9) don't say you shouldn't do this ;P */
						/* Hey, I mean it's demo code... */

	fuse_insert_callback(tick, NULL);
	fuse_insert_message(tick);

	FMASTER_COMMON_OUTBLAHBLAH
}

/* example how a syscall handler routine can send a "background" request
   (that is, the syscall handler itself is ended, but the installed
   callback handler will be invoked upon response)

   (Note: I don't yet know how useful this mechanism is, but at least currently this
   is used for sending init upon open -- obviously, fuse_dev_open() can't wait
   for device I/O ... see fuse_dev_open() and fuse_init_handler() in fuse.c)
 */ 

int
fmaster1_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	FMASTER_COMMON_INBLAHBLAH

	fuse_insert_callback(tick, prettyprint_handler);
	fuse_insert_message(tick);
	
	FMASTER_COMMON_OUTBLAHBLAH
}

/* example how a syscall handler routine can send a request and handle response by itself
 */

int
fmaster2_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	FMASTER_COMMON_INBLAHBLAH

	fuse_insert_callback(tick, __fuse_standard_handler);
	fuse_insert_message(tick);

	/* so now we go to sleep till answer arrives */
	if ((err = __fticket_wait_answer(tick))) {
		fuprintf("For Heaven's sake, we've been interrupted!\n");
		fuse_ticket_drop(tick);
		goto out;
	}
	if ((err = tick->tk_aw_errno))
		fuprintf("some IO or data format error occurred when answer was written to us");
	else
		fuse_response_prettyprint(fticket_opcode(tick), fticket_resp(tick));
	fuse_ticket_drop(tick);

	FMASTER_COMMON_OUTBLAHBLAH
}


/* example how a syscall handler routine can send a request when no answer is expected */

int
fmaster3_write(struct cdev *dev, struct uio *uio, int ioflag)
{

	FMASTER_COMMON_INBLAHBLAH

	fticket_disown(tick); /* so ticket will be dropped after read passes it up */
	fuse_insert_message(tick);

	FMASTER_COMMON_OUTBLAHBLAH
}

/* a not too effective application of the new API.
 * that kind of preparement stage is not suitable here,
 * and fuse_response_prettyprint() wants a fuse_iov so it
 * can't use fdi.answ.
 * Functionally by-and-large equiv. with fmaster2_write(), though
 * it's less verbose, and might set different errno value.
 */

int
fmaster4_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct fuse_dispatcher fdi;

	FMASTER_COMMON_INBLAHBLAH

	fdi.tick = tick;
	if ((err = fdisp_wait_answ(&fdi)))
		return (err);

	fuse_response_prettyprint(fticket_opcode(tick), fticket_resp(tick));
	fuse_ticket_drop(tick);

	FMASTER_COMMON_OUTBLAHBLAH
}

/******************************
 *
 * >>> Prettyprintintig stuff
 *
 ******************************/

static void
pp_fuse_entry_out(struct fuse_entry_out *stru)
{
	fuprintf("fuse_entry_out -- nodeid: %llu, generation: %llu, entry_valid: %llu, attr_valid: %llu, entry_valid_nsec: %i, attr_valid_nsec: %i, struct attr...\n",
	(unsigned long long)stru->nodeid, (unsigned long long)stru->generation, (unsigned long long)stru->entry_valid, (unsigned long long)stru->attr_valid, stru->entry_valid_nsec, stru->attr_valid_nsec);

	fuprintf("\tattr -- ino: %llu, size: %llu, blocks: %llu, atime: %llu, mtime: %llu, ctime: %llu, atimensec: %i, mtimensec: %i, ctimensec: %i, mode: %i, nlink: %i, uid: %i, gid: %i, rdev: %i\n",
	(unsigned long long)stru->attr.ino, (unsigned long long)stru->attr.size, (unsigned long long)stru->attr.blocks, (unsigned long long)stru->attr.atime, (unsigned long long)stru->attr.mtime, (unsigned long long)stru->attr.ctime, stru->attr.atimensec, stru->attr.mtimensec, stru->attr.ctimensec, stru->attr.mode, stru->attr.nlink, stru->attr.uid, stru->attr.gid, stru->attr.rdev);
}

static void
pp_fuse_open_out(struct fuse_open_out *stru)
{
	fuprintf("fuse_open_out -- fh: %llu, open_flags: %i, padding: %i\n", (unsigned long long)stru->fh, stru->open_flags, stru->padding);
}

static void
pp_fuse_write_out(struct fuse_write_out *stru)
{
	fuprintf("fuse_write_out -- size: %i, padding: %i\n", stru->size, stru->padding);
}

#if 0
static void
pp_fuse_getxattr_out(struct fuse_getxattr_out *stru)
{
	fuprintf("fuse_getxattr_out -- size: %i, padding: %i\n", stru->size, stru->padding);
}
#endif

static void
pp_fuse_init_out(struct fuse_init_out *stru)
{
	fuprintf("major: %i, minor: %i", stru->major, stru->minor);
#if FUSE_KERNELABI_GEQ(7, 5)
	fuprintf(
#if ! FUSE_KERNELABI_GEQ(7, 6)
                 "name_max: %i, symlink_max: %i, xattr_size_max: %i, "
#endif
                 "max_write: %i",
#if ! FUSE_KERNELABI_GEQ(7, 6)
	         stru->name_max, stru->symlink_max, stru->xattr_size_max,
#endif
                 stru->max_write);
#endif
	fuprintf("\n");
}

static void
pp_fuse_attr_out(struct fuse_attr_out *stru)
{
	fuprintf("fuse_entry_out -- attr_valid: %llu, attr_valid_nsec: %i, dummy: %i, struct attr...\n",
	(unsigned long long)stru->attr_valid, stru->attr_valid_nsec, stru->dummy);

	fuprintf("\tattr -- ino: %llu, size: %llu, blocks: %llu, atime: %llu, mtime: %llu, ctime: %llu, atimensec: %i, mtimensec: %i, ctimensec: %i, mode: %i, nlink: %i, uid: %i, gid: %i, rdev: %i\n",
	(unsigned long long)stru->attr.ino, (unsigned long long)stru->attr.size, (unsigned long long)stru->attr.blocks, (unsigned long long)stru->attr.atime, (unsigned long long)stru->attr.mtime, (unsigned long long)stru->attr.ctime, stru->attr.atimensec, stru->attr.mtimensec, stru->attr.ctimensec, stru->attr.mode, stru->attr.nlink, stru->attr.uid, stru->attr.gid, stru->attr.rdev);
}

static void
pp_fuse_statfs_out(struct fuse_statfs_out *stru)
{
	fuprintf("fuse_statfs_out -- blocks: %llu, bfree: %llu, bavail: %llu, files: %llu, ffree: %llu, bsize: %i, namelen: %i\n",
	(unsigned long long)stru->st.blocks, (unsigned long long)stru->st.bfree, (unsigned long long)stru->st.bavail, (unsigned long long)stru->st.files, (unsigned long long)stru->st.ffree, stru->st.bsize, stru->st.namelen);
}

static void
pp_buf(struct fuse_iov *fiov)
{
	fuprintf("buffer -- ");
	fprettyprint(fiov, 80);
}

static void
fuse_response_prettyprint(enum fuse_opcode opcode, struct fuse_iov *fresp)
{
	fuprintf("daemon sent reply to op %s (#%d)\n", fuse_opnames[opcode], opcode);

	switch (opcode) {
	case FUSE_LOOKUP:
		pp_fuse_entry_out((struct fuse_entry_out*)fresp->base);
		break;
	case FUSE_FORGET:
		KASSERT(0, ("a handler has been intalled for FUSE_FORGET"));
		break;
	case FUSE_GETATTR: 
		pp_fuse_attr_out((struct fuse_attr_out*)fresp->base);
		break;
	case FUSE_SETATTR:
		pp_fuse_attr_out((struct fuse_attr_out*)fresp->base);
		break;
	case FUSE_READLINK:
		break;
	case FUSE_SYMLINK:
		pp_fuse_entry_out((struct fuse_entry_out*)fresp->base);
		break;
	case FUSE_MKNOD:
		pp_fuse_entry_out((struct fuse_entry_out*)fresp->base);
		break;
	case FUSE_MKDIR:
		pp_fuse_entry_out((struct fuse_entry_out*)fresp->base);
		break;
	case FUSE_UNLINK:
		//pp_buf(fresp);
		break;
	case FUSE_RMDIR:
		//pp_buf(fresp);
		break;
	case FUSE_RENAME:
		//pp_buf(fresp);
		break;
	case FUSE_LINK:
		pp_fuse_entry_out((struct fuse_entry_out*)fresp->base);
		break;
	case FUSE_OPEN:
		pp_fuse_open_out((struct fuse_open_out*)fresp->base);
		break;
	case FUSE_READ:
		pp_buf(fresp);
		break;
	case FUSE_WRITE:
		pp_fuse_write_out((struct fuse_write_out*)fresp->base);
		break;
	case FUSE_STATFS:
		pp_fuse_statfs_out((struct fuse_statfs_out*)fresp->base);
		break;
	case FUSE_FLUSH:
		//pp_buf(fresp);
		break;
	case FUSE_RELEASE:
		//pp_buf(fresp);
		break;
	case FUSE_FSYNC:
		//pp_buf(fresp);
		break;
	case FUSE_SETXATTR:
		KASSERT(0, ("FUSE_SETXATTR implementor has forgotten to define a response body format check"));
		break;
	case FUSE_GETXATTR:
		KASSERT(0, ("FUSE_GETXATTR implementor has forgotten to define a response body format check"));
		break;
	case FUSE_LISTXATTR:
		KASSERT(0, ("FUSE_LISTXATTR implementor has forgotten to define a response body format check"));
		break;
	case FUSE_REMOVEXATTR:
		KASSERT(0, ("FUSE_REMOVEXATTR implementor has forgotten to define a response body format check"));
		break;
	case FUSE_INIT:
		pp_fuse_init_out((struct fuse_init_out*)fresp->base);
		break;
	case FUSE_OPENDIR:
		pp_fuse_open_out((struct fuse_open_out*)fresp->base);
		break;
	case FUSE_READDIR:
		pp_buf(fresp);
		break;
	case FUSE_RELEASEDIR:
		//pp_buf(fresp);
		break;
	case FUSE_FSYNCDIR:
		//pp_buf(fresp);
		break;
#if FUSE_HAS_ACCESS
	case FUSE_ACCESS:
		break;
#endif
#if FUSE_HAS_CREATE
	case FUSE_CREATE:
		pp_fuse_entry_out((struct fuse_entry_out*)fresp->base);
		pp_fuse_open_out((struct fuse_open_out*)(
		  (struct fuse_entry_out*)fresp->base + 1
		));
		break;
#endif
#if FUSE_HAS_GETLK
	case FUSE_GETLK:
		panic("FUSE_GETLK implementor has forgotten to define a response body format check");
		break;
#endif
#if FUSE_HAS_SETLK
	case FUSE_SETLK:
		panic("FUSE_SETLK implementor has forgotten to define a response body format check");
		break;
#endif
#if FUSE_HAS_SETLKW
	case FUSE_SETLKW:
		panic("FUSE_SETLKW implementor has forgotten to define a response body format check");
		break;
#endif
#if FUSE_HAS_INTERRUPT
	case FUSE_INTERRUPT:
		panic("FUSE_INTERRUPT implementor has forgotten to define a response body format check");
		break;
#endif
	default:
		KASSERT(0, ("fuse opcodes out of sync"));
	}

}

int
prettyprint_handler(struct fuse_ticket *tick,  struct uio *uio)
{
	enum fuse_opcode opcode;
	int err = 0;
	
	opcode = fticket_opcode(tick);

	if (opcode == FUSE_FORGET || opcode == FUSE_SETXATTR || opcode == FUSE_GETXATTR || opcode == FUSE_LISTXATTR || opcode == FUSE_REMOVEXATTR ||
#if FUSE_HAS_GETLK
	   opcode == FUSE_GETLK ||
#endif
#if FUSE_HAS_SETLK
	   opcode == FUSE_SETLK ||
#endif
#if FUSE_HAS_SETLKW
	   opcode == FUSE_SETLKW ||
#endif
	   0) {
		fuprintf("Hey, you've inserted a %s (#%d) request, don't do it in real life, it breaks an assertion!\n", fuse_opnames[opcode], opcode);
		goto out;
	}

	if ((err = __fuse_body_audit(tick, uio->uio_resid))) {
		fuprintf("body audit refused body\n");
		goto out;
	}


	if ((err = __fticket_aw_pull_uio(tick, uio)))	{
		fuprintf("uio pulling failed\n");
		goto out;
	}

	fuse_response_prettyprint(opcode, fticket_resp(tick));

out:

	DEBUG("dropping ticket in prettyprint_handler\n");
	fuse_ticket_drop(tick);
	return (err);
}
