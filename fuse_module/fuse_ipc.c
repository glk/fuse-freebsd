/*
 * Messaging related routines.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>

#include "fuse.h"
#include "fuse_node.h"
#include "fuse_ipc.h"

static struct fuse_ticket *fticket_alloc(struct fuse_data *data);
static void                fticket_refresh(struct fuse_ticket *tick);
static void                fticket_destroy(struct fuse_ticket *tick);
static int                 fticket_wait_answer(struct fuse_ticket *tick);
static __inline int        fticket_aw_pull_uio(struct fuse_ticket *tick,
				                     struct uio *uio);
static __inline void       fuse_push_freeticks(struct fuse_ticket *tick);
static __inline
struct fuse_ticket        *fuse_pop_freeticks(struct fuse_data *data);
static __inline void       fuse_push_allticks(struct fuse_ticket *tick);
static __inline void       fuse_remove_allticks(struct fuse_ticket *tick);
static struct fuse_ticket *fuse_pop_allticks(struct fuse_data *data);

static int                 fuse_body_audit(struct fuse_ticket *tick, size_t blen);
static __inline void       fuse_setup_ihead(struct fuse_in_header *ihead,
                                             struct fuse_ticket *tick, uint64_t nid,
                                             enum fuse_opcode op, size_t blen,
                                             pid_t pid, struct ucred *cred);

static fuse_handler_t      fuse_standard_handler;

SYSCTL_NODE(_vfs, OID_AUTO, fuse, CTLFLAG_RW, 0, "FUSE tunables");
SYSCTL_STRING(_vfs_fuse, OID_AUTO, fuse4bsd_version, CTLFLAG_RD,
              FUSE4BSD_VERSION, 0, "fuse4bsd version");
static int maxfreetickets = 1024;
SYSCTL_INT(_vfs_fuse, OID_AUTO, maxfreetickets, CTLFLAG_RW,
            &maxfreetickets, 0, "limit for number of free tickets kept");
static long fuse_iov_permanent_bufsize = 1 << 19;
SYSCTL_LONG(_vfs_fuse, OID_AUTO, iov_permanent_bufsize, CTLFLAG_RW,
            &fuse_iov_permanent_bufsize, 0,
            "limit for permanently stored buffer size for fuse_iovs");
static int fuse_iov_credit = 16;
SYSCTL_INT(_vfs_fuse, OID_AUTO, iov_credit, CTLFLAG_RW,
            &fuse_iov_credit, 0,
            "how many times is an oversized fuse_iov tolerated");
static unsigned maxtickets = 0;
SYSCTL_UINT(_vfs_fuse, OID_AUTO, maxtickets, CTLFLAG_RW,
            &maxtickets, 0, "limit how many tickets are tolerated");

MALLOC_DEFINE(M_FUSEMSG, "fuse_messaging",
              "buffer for fuse messaging related things");

/***************************************
 *
 * >>> Interface ("methods") of messaging related objects
 *
 ***************************************/

/* fuse_iov methods ==> */

void
fiov_init(struct fuse_iov *fiov, size_t size)
{
	fiov->len = 0;
	fiov->base = malloc(FU_AT_LEAST(size), M_FUSEMSG, M_WAITOK | M_ZERO);
	fiov->allocated_size = FU_AT_LEAST(size);
	fiov->credit = fuse_iov_credit;
}

void
fiov_teardown(struct fuse_iov *fiov)
{
	free(fiov->base, M_FUSEMSG);
}

void
fiov_adjust(struct fuse_iov *fiov, size_t size)
{
	if (fiov->allocated_size < size ||
	    (fuse_iov_permanent_bufsize >= 0 &&
	     fiov->allocated_size - size > fuse_iov_permanent_bufsize &&
             --fiov->credit < 0)) {
		fiov->base = realloc(fiov->base, FU_AT_LEAST(size), M_FUSEMSG,
		                     M_WAITOK | M_ZERO);
		fiov->allocated_size = FU_AT_LEAST(size);
		fiov->credit = fuse_iov_credit;
	}

	fiov->len = size;
}

void
fiov_refresh(struct fuse_iov *fiov)
{
	bzero(fiov->base, fiov->len);	
	fiov_adjust(fiov, 0);
}

/* <== fuse_iov methods */

/* fuse_ticket methods ==> */

/*
 * Tickets are carriers of communication with a fuse daemon.
 * Tickets have a unique id, which should be kept unique
 * among synchronously used tickets. The everyday routine:
 * + Syscall handler gets one by fuse_ticket_fetch()
 *     (then, behind the scenes, either a fresh one is allocated
 *     or a cached old one is put into use again)
 * + Sets up data to be passed to the daemon
 *    (there is a message node attached to the ticket)
 * + If she knows that answer will come, sets up the callback node
 *   attached to the ticket, and enqueues it to the callback nodes' list
 * + enqueues the message and kicks fusedev_read()
 * + if daemon gives a proper answer, it will contain the unique id, by which
 *   fusedev_write() can pick the pre-prepared callback node and run it.
 *   There is the standard callback handler which just awakes the syscall
 *   handler who then waits for the response, deal with it by herself.
 *   Another option is to write a full-fledged callback handler which does all
 *   data processing within fusedev_write()'s thread (although we never do
 *   this). Or, if the answer is uninteresting, a NULL handler can be used.
 * + After answer has been consumed, the handler or anyone to whom the control
 *   has been passed supposed to call ticket_drop()
 *     (then, behind the scenes, either the ticket is destroyed, or put into
 *     cache)
 */


static struct fuse_ticket *
fticket_alloc(struct fuse_data *data)
{
	struct fuse_ticket *tick;

	tick = malloc(sizeof(*tick), M_FUSEMSG, M_WAITOK | M_ZERO);

	tick->tk_data = data;

	fiov_init(&tick->tk_ms_fiov, sizeof(struct fuse_in_header));
	tick->tk_ms_type = FT_M_FIOV;

	mtx_init(&tick->tk_aw_mtx, "fuse answer delivery mutex", NULL, MTX_DEF);
	fiov_init(&tick->tk_aw_fiov, 0);
	fiov_init(&tick->tk_aw_handler_parm, 0);
	tick->tk_aw_type = FT_A_FIOV;

	return (tick);
}

static __inline void
fticket_refresh(struct fuse_ticket *tick)
{
	fiov_refresh(&tick->tk_ms_fiov);
	tick->tk_ms_bufdata = NULL;
	tick->tk_ms_bufsize = 0;
	tick->tk_ms_type = FT_M_FIOV;

	bzero(&tick->tk_aw_ohead, sizeof(struct fuse_out_header));
	fiov_refresh(&tick->tk_aw_fiov);
	fiov_adjust(&tick->tk_aw_handler_parm, 0);
	tick->tk_aw_errno = 0;
	tick->tk_aw_bufdata = NULL;
	tick->tk_aw_bufsize = 0;
	tick->tk_aw_type = FT_A_FIOV;

	tick->tk_flag = 0;
	tick->tk_age++;
}

static void
fticket_destroy(struct fuse_ticket *tick)
{
	fiov_teardown(&tick->tk_ms_fiov);

	mtx_destroy(&tick->tk_aw_mtx);
	fiov_teardown(&tick->tk_aw_fiov);
	fiov_teardown(&tick->tk_aw_handler_parm);

	free(tick, M_FUSEMSG);
}

static int
fticket_wait_answer(struct fuse_ticket *tick)
{
	int err = 0;

	mtx_lock(&tick->tk_aw_mtx);
	if (fticket_answered(tick))
		goto out;

	if (fdata_kick_get(tick->tk_data)) {
		err = ENOTCONN;
		fticket_set_answered(tick);
		goto out;
	}

	err = msleep(tick, &tick->tk_aw_mtx, PCATCH, "fu_ans", 0);

out:
	mtx_unlock(&tick->tk_aw_mtx);

	if (! (err || fticket_answered(tick))) {
		/*
		 * Some deadlocky scenarios can get us here, like SIGKILLing
		 * the fusexmp daemon after a fuse dir has been null mounted
		 * over its original copy in the "normal" fs
		 *
		 * (I guess there is no need of kicking the daemon at this
		 * point...)
		 */
	        DEBUG2G("fuse requester was woken up but still no answer");
		err = ENXIO;
	}

	return (err);
}

static __inline int
fticket_aw_pull_uio(struct fuse_ticket *tick, struct uio *uio)
{
	int err = 0;
	size_t len;

	len = uio->uio_resid;

	if (len) {
		switch (tick->tk_aw_type) {
		case FT_A_FIOV:
			fiov_adjust(fticket_resp(tick), len);
			err = uiomove(fticket_resp(tick)->base, len, uio);
			break;
		case FT_A_BUF:
			tick->tk_aw_bufsize = len;
			err = uiomove(tick->tk_aw_bufdata, len, uio);
			break;
		default:
			panic("unknown answer type for fuse_ticket %p", tick);
		}
	}
	DEBUG("uio pulled, error val: %d\n",err);
	return (err);
}

int fticket_pull(struct fuse_ticket *tick, struct uio *uio)
{
	int err = 0;

	if (tick->tk_aw_ohead.error)
		return (0);

	err = fuse_body_audit(tick, uio->uio_resid);
	if (! err)
		err = fticket_aw_pull_uio(tick, uio);

	return (err);
}

/* <== fuse_ticket methods */

/* fuse_data methods ==> */

struct fuse_data *
fdata_alloc(struct cdev *fdev, struct ucred *cred)
{
	struct fuse_data *data;

	data = malloc(sizeof(struct fuse_data), M_FUSEMSG, M_WAITOK | M_ZERO);

	/* Setting up fields of mine */
	data->mpri = FM_NOMOUNTED;
	data->fdev = fdev;

	mtx_init(&data->ms_mtx, "fuse message list mutex", NULL, MTX_DEF);
	STAILQ_INIT(&data->ms_head);
	mtx_init(&data->ticket_mtx, "fuse ticketer mutex", NULL, MTX_DEF);
	STAILQ_INIT(&data->freetickets_head);
	TAILQ_INIT(&data->alltickets_head);
	mtx_init(&data->aw_mtx, "fuse answer list mutex", NULL, MTX_DEF);
	TAILQ_INIT(&data->aw_head);
	data->daemoncred = crhold(cred);

	sx_init(&data->mhierlock, "fuse hierarchy of mounts lock");
	LIST_INIT(&data->slaves_head);

	sx_init(&data->rename_lock, "fuse rename lock");

	return (data);
}

void
fdata_destroy(struct fuse_data *data)
{
	struct fuse_ticket *tick;

	/* Driving off stage all that stuff thrown at device... */
	mtx_destroy(&data->ms_mtx);
	mtx_destroy(&data->aw_mtx);
	mtx_destroy(&data->ticket_mtx);
	sx_destroy(&data->rename_lock);

	while ((tick = fuse_pop_allticks(data)))
		fticket_destroy(tick);

	crfree(data->daemoncred);

	sx_destroy(&data->mhierlock);

	free(data,M_FUSEMSG);
}

int
fdata_kick_get(struct fuse_data *data)
{
	DEBUG("0x%x\n", data->dataflag & FSESS_KICK);
	return (data->dataflag & FSESS_KICK);
}

void
fdata_kick_set(struct fuse_data *data)
{
	struct fuse_ticket *tick;

	DEBUG2G("banning daemon\n");

	mtx_lock(&data->ms_mtx);
	data->dataflag |= FSESS_KICK;
	wakeup_one(data);
	selwakeuppri(&data->ks_rsel, PZERO + 1);
	mtx_unlock(&data->ms_mtx);

	mtx_lock(&data->ticket_mtx);
	wakeup(&data->ticketer);
	mtx_unlock(&data->ticket_mtx);

	mtx_lock(&data->aw_mtx);
	TAILQ_FOREACH(tick, &data->aw_head, tk_aw_link)
		wakeup_one(tick);
	mtx_unlock(&data->aw_mtx);
}

/* <== fuse_data methods */


/*********************
 *
 * >>> "Multi-dispatch" routines
 *
 *********************/


static __inline void
fuse_push_freeticks(struct fuse_ticket *tick)
{
	STAILQ_INSERT_TAIL(&tick->tk_data->freetickets_head, tick,
	                   tk_freetickets_link);
	tick->tk_data->freeticket_counter++;
}

static __inline struct fuse_ticket *
fuse_pop_freeticks(struct fuse_data *data)
{
	struct fuse_ticket *tick;

	if ((tick = STAILQ_FIRST(&data->freetickets_head))) {
		STAILQ_REMOVE_HEAD(&data->freetickets_head, tk_freetickets_link);
		data->freeticket_counter--;
	}

	return tick;
}
/**/
static __inline void
fuse_push_allticks(struct fuse_ticket *tick)
{
	tick->tk_unique = tick->tk_data->ticketer++;
	TAILQ_INSERT_TAIL(&tick->tk_data->alltickets_head, tick, tk_alltickets_link);
}

static __inline void
fuse_remove_allticks(struct fuse_ticket *tick)
{
	tick->tk_data->deadticket_counter++;
	TAILQ_REMOVE(&tick->tk_data->alltickets_head, tick, tk_alltickets_link);
}

static struct fuse_ticket *
fuse_pop_allticks(struct fuse_data *data)
{
	struct fuse_ticket *tick;

	if ((tick = TAILQ_FIRST(&data->alltickets_head))) {
		fuse_remove_allticks(tick);
	}

	return (tick);
}

struct fuse_ticket *
fuse_ticket_fetch(struct fuse_data *data)
{
	struct fuse_ticket *tick;
	int err = 0;

	DEBUG("fetching ticket\n");
	if (data->freeticket_counter == 0) {
		tick = fticket_alloc(data);
		mtx_lock(&data->ticket_mtx);
		fuse_push_allticks(tick);
	} else {
		mtx_lock(&data->ticket_mtx);
		tick = fuse_pop_freeticks(data);
		KASSERT(tick, ("no free ticket available tho counter said there is"));
	}

#if _DEBUG_UNIQUE
	tick->tk_unique = tick->tk_unique % 10000 + ++data->msgcou * 10000;
#endif

	if (! (data->dataflag & FSESS_INITED) && data->ticketer > 1)
		err = msleep(&data->ticketer, &data->ticket_mtx,
		             PCATCH | PDROP, "fu_ini", 0);
	else {
		if (maxtickets &&
		    data->ticketer - data->deadticket_counter > maxtickets)
			err = 1;
		mtx_unlock(&data->ticket_mtx);
	}

	if (err)
		fdata_kick_set(data);

	return (tick);
}

void
fuse_ticket_drop(struct fuse_ticket *tick)
{
	int die = 0;

	/*
	 * Limit below should be tunable by a sysctl?
	 * Probably not worth for the effort.
         */
	if (maxfreetickets >= 0 &&
	    maxfreetickets <= tick->tk_data->freeticket_counter) {
		die = 1;
		DEBUG("ticket will die\n");
	} else
		fticket_refresh(tick);

	mtx_lock(&tick->tk_data->ticket_mtx);
	if (die) {
		fuse_remove_allticks(tick);
		mtx_unlock(&tick->tk_data->ticket_mtx);
		fticket_destroy(tick);
	} else {
		fuse_push_freeticks(tick);
		mtx_unlock(&tick->tk_data->ticket_mtx);
	}

	DEBUG("ticket removed\n");
}

void
fuse_ticket_drop_notowned(struct fuse_ticket *tick)
{
	if (tick->tk_flag & FT_NOTOWNED)
		fuse_ticket_drop(tick);
}

void
fuse_insert_callback(struct fuse_ticket *tick, fuse_handler_t *handler)
{
	/*
	 * If our session is defunct, then neither go on nor make fuss.
	 * Just return. (Making only fticket_wait_answer() fallible is good
	 * enough.)
	 */
	if (fdata_kick_get(tick->tk_data))
		return;

	tick->tk_aw_handler = handler;

	mtx_lock(&tick->tk_data->aw_mtx);
	fuse_aw_push(tick);
	mtx_unlock(&tick->tk_data->aw_mtx);
}

void
fuse_insert_message(struct fuse_ticket *tick)
{
	if (tick->tk_flag & FT_DIRTY)
		panic("ticket reused without being refreshed");
	tick->tk_flag |= FT_DIRTY;

	if (fdata_kick_get(tick->tk_data)) {
		fuse_ticket_drop_notowned(tick);
		return;
	}

	mtx_lock(&tick->tk_data->ms_mtx);
	fuse_ms_push(tick);
	DEBUG("ring the bell\n");
	wakeup_one(tick->tk_data);
	selwakeuppri(&tick->tk_data->ks_rsel, PZERO + 1);
	mtx_unlock(&tick->tk_data->ms_mtx);
}

static int
fuse_body_audit(struct fuse_ticket *tick, size_t blen)
{
	int err = 0;
	enum fuse_opcode opcode;

	opcode = fticket_opcode(tick);

	DEBUG("op %s (#%d) was sent to us with a body of size %d\n",
 (0 <= opcode && opcode <= fuse_opnames_entries) ? fuse_opnames[opcode] : "???",
 opcode, (int)blen);

	switch (opcode) {
	case FUSE_LOOKUP:
		err = blen == sizeof(struct fuse_entry_out) ? 0 : EINVAL;
		break;
	case FUSE_FORGET:
		panic("a handler has been intalled for FUSE_FORGET");
		break;
	case FUSE_GETATTR:
		err = blen == sizeof(struct fuse_attr_out) ? 0 : EINVAL;
		break;
	case FUSE_SETATTR:
		err = blen == sizeof(struct fuse_attr_out) ? 0 : EINVAL;
		break;
	case FUSE_READLINK:
		/*
		 * We use the same limit as Linux FUSE, except for that
		 * don't reserve the last byte for a terminating zero...
		 */
		err = PAGE_SIZE >= blen ? 0 : EINVAL;
		break;
	case FUSE_SYMLINK:
		err = blen == sizeof(struct fuse_entry_out) ? 0 : EINVAL;
		break;
	case FUSE_MKNOD:
		err = blen == sizeof(struct fuse_entry_out) ? 0 : EINVAL;
		break;
	case FUSE_MKDIR:
		err = blen == sizeof(struct fuse_entry_out) ? 0 : EINVAL;
		break;
	case FUSE_UNLINK:
		err = blen == 0 ? 0 : EINVAL;
		break;
	case FUSE_RMDIR:
		err = blen == 0 ? 0 : EINVAL;
		break;
	case FUSE_RENAME:
		err = blen == 0 ? 0 : EINVAL;
		break;
	case FUSE_LINK:
		err = blen == sizeof(struct fuse_entry_out) ? 0 : EINVAL;
		break;
	case FUSE_OPEN:
		err = blen == sizeof(struct fuse_open_out) ? 0 : EINVAL;
		break;
	case FUSE_READ:
		/*
		 * we do whatever crazyness is needed to read the original
		 * request size, starting from the callback node, and then
		 * check whether available data doesn't grow over that.
		 */
		err = ((struct fuse_read_in *)(
		        (char *)tick->tk_ms_fiov.base +
                        sizeof(struct fuse_in_header)
	              ))->size >= blen ? 0 : EINVAL;
		break;
	case FUSE_WRITE:
		err = blen == sizeof(struct fuse_write_out) ? 0 : EINVAL;
		break;
	case FUSE_STATFS:
#if FUSE_KERNELABI_GEQ(7, 4)
		if (fuse_libabi_geq(tick->tk_data, 7, 4))
			err = blen == sizeof(struct fuse_statfs_out) ? 0 : EINVAL;
		else
			err = blen == FUSE_COMPAT_STATFS_SIZE ? 0 : EINVAL;
#else
		err = blen == sizeof(struct fuse_statfs_out) ? 0 : EINVAL;
#endif
		break;
	case FUSE_FLUSH:
		err = blen == 0 ? 0 : EINVAL;
		break;
	case FUSE_RELEASE:
		err = blen == 0 ? 0 : EINVAL;
		break;
	case FUSE_FSYNC:
		err = blen == 0 ? 0 : EINVAL;
		break;
	case FUSE_SETXATTR:
		panic("FUSE_SETXATTR implementor has forgotten to define a response body format check");
		break;
	case FUSE_GETXATTR:
		panic("FUSE_GETXATTR implementor has forgotten to define a response body format check");
		break;
	case FUSE_LISTXATTR:
		panic("FUSE_LISTXATTR implementor has forgotten to define a response body format check");
		break;
	case FUSE_REMOVEXATTR:
		panic("FUSE_REMOVEXATTR implementor has forgotten to define a response body format check");
		break;
	case FUSE_INIT:
#if FUSE_KERNELABI_GEQ(7, 5)
		if (blen == sizeof(struct fuse_init_out) || blen == 8)
			err = 0;
		else
			err = EINVAL;
#else
		err = blen == sizeof(struct fuse_init_in_out) ? 0 : EINVAL;
#endif
		break;
	case FUSE_OPENDIR:
		err = blen == sizeof(struct fuse_open_out) ? 0 : EINVAL;
		break;
	case FUSE_READDIR:
		err = ((struct fuse_read_in *)(
		        (char *)tick->tk_ms_fiov.base +
                        sizeof(struct fuse_in_header)
	              ))->size >= blen ? 0 : EINVAL;
		break;
	case FUSE_RELEASEDIR:
		err = blen == 0 ? 0 : EINVAL;
		break;
	case FUSE_FSYNCDIR:
		err = blen == 0 ? 0 : EINVAL;
		break;
#if FUSE_HAS_ACCESS
	case FUSE_ACCESS:
		err = blen == 0 ? 0 : EINVAL;
		break;
#endif
#if FUSE_HAS_CREATE
	case FUSE_CREATE:
		err = blen == sizeof(struct fuse_entry_out) + sizeof(struct fuse_open_out) ? 0 : EINVAL;
		break;
#endif
#if FUSE_HAS_DESTROY
	case FUSE_DESTROY:
		err = blen == 0 ? 0 : EINVAL;
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
		panic("fuse opcodes out of sync");
	}

	if (err) {
#if _DEBUG2G
		DEBUG2G("op %s (#%d) with body size %d: invalid body size\n",
		        (0 <= opcode && opcode <= fuse_opnames_entries) ? fuse_opnames[opcode] : "???",
		         opcode, (int)blen);
#endif
		fdata_kick_set(tick->tk_data);
	}

	return (err);
}

static void
fuse_setup_ihead(struct fuse_in_header *ihead, struct fuse_ticket *tick,
                 uint64_t nid, enum fuse_opcode op, size_t blen,
                 pid_t pid, struct ucred *cred)
{
	ihead->len = sizeof(*ihead) + blen; /* actually not used by lib */
	ihead->unique = tick->tk_unique;
	ihead->nodeid = nid;
	ihead->opcode = op;
	ihead->pid = pid;
	ihead->uid = cred->cr_uid;
	ihead->gid = cred->cr_rgid;
	DEBUG2G("in header -- opcode: %2d (\"%s\"), unique: %llu, nodeid: %llu\n",
	      ihead->opcode,
	      fuse_opnames[ihead->opcode],
	      (unsigned long long)ihead->unique,
	      (unsigned long long)ihead->nodeid);
}

/********************
 *
 * >>> Callback handlers
 *
 ********************/

/*
 * fuse_standard_handler just pulls in data and wakes up pretender.
 * Doesn't try to interpret data, that's left for the pretender.
 * Though might do a basic size verification before the pull-in takes place
 */

static int
fuse_standard_handler(struct fuse_ticket *tick, struct uio *uio)
{
	int err = 0;
	int dropflag = 0;

	err = fticket_pull(tick, uio);

	mtx_lock(&tick->tk_aw_mtx);
	if (fticket_answered(tick))
		/* The requester was interrupted and she set the "answered" flag
		 * to notify us. In this case, we don't have to care about
		 * anything, just drop the ticket and get out as fast as we can.
		 */
		dropflag = 1;
	else {
		fticket_set_answered(tick);
		tick->tk_aw_errno = err;
		wakeup(tick);
	}
	mtx_unlock(&tick->tk_aw_mtx);

	if (dropflag)
		fuse_ticket_drop(tick);
	return (err);
}

/***********************************************************************
 *
 * >>>  High-level interface to the messaging facilities of fuse devices
 *
 ***********************************************************************/

static __inline void
__fdisp_make_pid(struct fuse_dispatcher *fdip, struct mount *mp,
                 enum fuse_opcode op, uint64_t nid, pid_t pid,
                 struct ucred *cred)
{
	struct fuse_data *data = mp->mnt_data;

	KASSERT(data, ("no data for mp %p", mp));
	KASSERT(data->mpri != FM_SECONDARY,
	        ("fdisp_make() on secondary mount %p", mp));
#if _DEBUG2G
	if (data->mpri == FM_NOMOUNTED)
		DEBUG2G("fuse data %p is not mounted at fdisp_make time!\n",
	                data);
#endif

	if (fdip->tick)
		fticket_refresh(fdip->tick);
	else
		fdip->tick = fuse_ticket_fetch(data);

	FUSE_DIMALLOC(&fdip->tick->tk_ms_fiov, fdip->finh,
	              fdip->indata, fdip->iosize);
	fuse_setup_ihead(fdip->finh, fdip->tick, nid, op, fdip->iosize, pid, cred);
}

void
fdisp_make_pid(struct fuse_dispatcher *fdip, struct mount *mp,
               enum fuse_opcode op, uint64_t nid, pid_t pid, struct ucred *cred)
{
	return (__fdisp_make_pid(fdip, mp, op, nid, pid, cred));
}

void
fdisp_make(struct fuse_dispatcher *fdip, struct mount *mp, enum fuse_opcode op,
           uint64_t nid, struct thread *td, struct ucred *cred)
{
	RECTIFY_TDCR(td, cred);
	return (__fdisp_make_pid(fdip, mp, op, nid, td->td_proc->p_pid, cred));
}

void
fdisp_make_vp(struct fuse_dispatcher *fdip, enum fuse_opcode op,
              struct vnode *vp, struct thread *td, struct ucred *cred)
{
	RECTIFY_TDCR(td, cred);
	return (__fdisp_make_pid(fdip, vp->v_mount, op, VTOI(vp),
	        td->td_proc->p_pid, cred));
}

int
fdisp_wait_answ(struct fuse_dispatcher *fdip)
{
	int err = 0;
	fdip->answ_stat = 0;

	fuse_insert_callback(fdip->tick, fuse_standard_handler);
	fuse_insert_message(fdip->tick);
	if ((err = fticket_wait_answer(fdip->tick))) {
		/* Uh-huh, we got interrupted... */

#ifndef DONT_TRY_HARD_PREVENT_IO_IN_VAIN
		struct fuse_ticket *tick;
		unsigned age;
#endif

		mtx_lock(&fdip->tick->tk_aw_mtx);
		if (fticket_answered(fdip->tick)) {
			/*
			 * Just between noticing the interrupt and getting here,
			 * the standard handler has completed his job.
			 * So we drop the ticket and exit as usual.
			 */
			mtx_unlock(&fdip->tick->tk_aw_mtx);
			goto out;
		} else {
			/*
			 * So we were faster than the standard handler.
			 * Then by setting the answered flag we get *him*
			 * to drop the ticket.
			 */
			age = fdip->tick->tk_age;
			fticket_set_answered(fdip->tick);
			mtx_unlock(&fdip->tick->tk_aw_mtx);
#ifndef DONT_TRY_HARD_PREVENT_IO_IN_VAIN
			/*
			 * If we are willing to pay with one more locking, we
			 * can save on I/O by getting the device write handler
			 * to drop the ticket. That is, if we are fast enough,
			 * the standard handler -- who does the uiomove --
			 * won't even be called. (No guarantee though for
			 * being fast.)
			 */

			DEBUG2G("interrupted, now trying to prevent io in vain (I'll tell you if it succeeds...)\n");
			mtx_lock(&fdip->tick->tk_data->aw_mtx);
			TAILQ_FOREACH(tick, &fdip->tick->tk_data->aw_head,
			              tk_aw_link) {
				if (tick == fdip->tick) {
					if (fdip->tick->tk_age == age) {
						DEBUG2G("preventing io in vain succeeded\n");
						fdip->tick->tk_aw_handler = NULL;
					}
					break;
				}
			}
			mtx_unlock(&fdip->tick->tk_data->aw_mtx);
#endif
			return (err);
		}
	}

	if (fdip->tick->tk_aw_errno) {
		/*
		 * Error with messaging, the VFS layer
		 * won't be particularly interested about
		 * its exact nature
		 */
		err = EIO;
		goto out;
	}

	if ((err = fdip->tick->tk_aw_ohead.error)) {
		/*
		 * This means a "proper" fuse syscall error.
		 * We record this value so the caller will
		 * be able to know it's not a boring messaging
		 * failure, if she wishes so (and if not, she can
		 * just simply propagate the return value of this routine).
 		 * [XXX Maybe a bitflag would do the job too,
		 * if other flags needed, this will be converted thusly.]
		 */
		fdip->answ_stat = err;
		goto out;
	}

	fdip->answ = fticket_resp(fdip->tick)->base;
	fdip->iosize = fticket_resp(fdip->tick)->len;

	return (0);

out:
	fuse_ticket_drop(fdip->tick);
	return (err);
}

#ifdef FMASTER
/*
 * Some functions need to be accessed from the fmaster code
 * which we'd like to keep static. As fmaster is optional,
 * we'll don't break this scheme for the sake of fmaster.
 *
 * As a compromise, we use globally visible wrappers for them.
 */

int  __fticket_aw_pull_uio(struct fuse_ticket *tick, struct uio *uio);
int  __fuse_body_audit(struct fuse_ticket *tick, size_t blen);
int  __fticket_wait_answer(struct fuse_ticket *tick);

fuse_handler_t __fuse_standard_handler;

int
__fticket_aw_pull_uio(struct fuse_ticket *tick, struct uio *uio)
{
	return (fticket_aw_pull_uio(tick, uio));
}

int
__fuse_body_audit(struct fuse_ticket *tick, size_t blen)
{
	return (fuse_body_audit(tick, blen));
}

int
__fticket_wait_answer(struct fuse_ticket *tick)
{
	return (fticket_wait_answer(tick));
}

int
__fuse_standard_handler(struct fuse_ticket *tick, struct uio *uio)
{
	return (fuse_standard_handler(tick, uio));
}
#endif /* FMASTER */
