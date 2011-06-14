/*
 * Copyright (C) 2006 Google. All Rights Reserved.
 * Amit Singh <singh@>
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
#include "fuse_internal.h"

static struct fuse_ticket *fticket_alloc(struct fuse_data *data);
static void                fticket_refresh(struct fuse_ticket *tick);
static void                fticket_destroy(struct fuse_ticket *tick);
static int                 fticket_wait_answer(struct fuse_ticket *tick);
static __inline__ int  fticket_aw_pull_uio(struct fuse_ticket *tick, struct uio *uio);
static __inline__ void fuse_push_freeticks(struct fuse_ticket *tick);

static __inline__ struct fuse_ticket *
fuse_pop_freeticks(struct fuse_data *data);

static __inline__ void     fuse_push_allticks(struct fuse_ticket *tick);
static __inline__ void     fuse_remove_allticks(struct fuse_ticket *tick);
static struct fuse_ticket *fuse_pop_allticks(struct fuse_data *data);

static int             fuse_body_audit(struct fuse_ticket *tick, size_t blen);
static __inline__ void fuse_setup_ihead(struct fuse_in_header *ihead,
                                        struct fuse_ticket *tick, uint64_t nid,
                                        enum fuse_opcode op, size_t blen,
                                        pid_t pid, struct ucred *cred);
static fuse_handler_t      fuse_standard_handler;

SYSCTL_NODE(_vfs, OID_AUTO, fuse, CTLFLAG_RW, 0, "FUSE tunables");
SYSCTL_STRING(_vfs_fuse, OID_AUTO, fuse4bsd_version, CTLFLAG_RD,
              FUSE4BSD_VERSION, 0, "fuse4bsd version");
static int fuse_max_freetickets = 1024;
SYSCTL_INT(_vfs_fuse, OID_AUTO, max_freetickets, CTLFLAG_RW,
            &fuse_max_freetickets, 0, "limit for number of free tickets kept");
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

void
fiov_init(struct fuse_iov *fiov, size_t size)
{
    debug_printf("fiov=%p, size=%x\n", fiov, size);

    fiov->len = 0;
    fiov->base = malloc(FU_AT_LEAST(size), M_FUSEMSG, M_WAITOK | M_ZERO);
    fiov->allocated_size = FU_AT_LEAST(size);
    fiov->credit = fuse_iov_credit;
}

void
fiov_teardown(struct fuse_iov *fiov)
{
    debug_printf("fiov=%p\n", fiov);

    free(fiov->base, M_FUSEMSG);
}

void
fiov_adjust(struct fuse_iov *fiov, size_t size)
{
    debug_printf("fiov=%p, size=%x\n", fiov, size);

    if (fiov->allocated_size < size ||
        (fuse_iov_permanent_bufsize >= 0 &&
         fiov->allocated_size - size > fuse_iov_permanent_bufsize &&
             --fiov->credit < 0)) {

        fiov->base = realloc(fiov->base, FU_AT_LEAST(size), M_FUSEMSG,
                             M_WAITOK | M_ZERO);
        if (!fiov->base) {
            panic("FUSE: realloc failed");
        }

        fiov->allocated_size = FU_AT_LEAST(size);
        fiov->credit = fuse_iov_credit;
    }

    fiov->len = size;
}

void
fiov_refresh(struct fuse_iov *fiov)
{
    debug_printf("fiov=%p\n", fiov);

    bzero(fiov->base, fiov->len);
    fiov_adjust(fiov, 0);
}

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

    debug_printf("data=%p\n", data);

    tick = malloc(sizeof(*tick), M_FUSEMSG, M_WAITOK | M_ZERO);

    tick->tk_unique = data->ticketer++;
    tick->tk_data = data;

    fiov_init(&tick->tk_ms_fiov, sizeof(struct fuse_in_header));
    tick->tk_ms_type = FT_M_FIOV;

    mtx_init(&tick->tk_aw_mtx, "fuse answer delivery mutex", NULL, MTX_DEF);
    fiov_init(&tick->tk_aw_fiov, 0);
    tick->tk_aw_type = FT_A_FIOV;

    return (tick);
}

static __inline void
fticket_refresh(struct fuse_ticket *tick)
{
    debug_printf("tick=%p\n", tick);

    fiov_refresh(&tick->tk_ms_fiov);
    tick->tk_ms_bufdata = NULL;
    tick->tk_ms_bufsize = 0;
    tick->tk_ms_type = FT_M_FIOV;

    bzero(&tick->tk_aw_ohead, sizeof(struct fuse_out_header));

    fiov_refresh(&tick->tk_aw_fiov);
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
    debug_printf("tick=%p\n", tick);

    fiov_teardown(&tick->tk_ms_fiov);

    mtx_destroy(&tick->tk_aw_mtx);
    fiov_teardown(&tick->tk_aw_fiov);

    free(tick, M_FUSEMSG);
}

static int
fticket_wait_answer(struct fuse_ticket *tick)
{
    int err = 0;

    debug_printf("tick=%p\n", tick);
    mtx_lock(&tick->tk_aw_mtx);

    if (fticket_answered(tick)) {
        goto out;
    }

    if (fdata_kick_get(tick->tk_data)) {
        err = ENOTCONN;
        fticket_set_answered(tick);
        goto out;
    }

    err = msleep(tick, &tick->tk_aw_mtx, PCATCH, "fu_ans", 0);

out:
    mtx_unlock(&tick->tk_aw_mtx);

    if (!(err || fticket_answered(tick))) {
        debug_printf("fuse requester was woken up but still no answer");
        err = ENXIO;
    }

    return (err);
}

static __inline int
fticket_aw_pull_uio(struct fuse_ticket *tick, struct uio *uio)
{
    int err = 0;
    size_t len = uio_resid(uio);

    debug_printf("tick=%p, uio=%p\n", tick, uio);

    if (len) {
        switch (tick->tk_aw_type) {
        case FT_A_FIOV:
            fiov_adjust(fticket_resp(tick), len);
            err = uiomove(fticket_resp(tick)->base, len, uio);
            if (err) {
                debug_printf("FT_A_FIOV: error is %d (%p, %d, %p)\n",
                             err, fticket_resp(tick)->base, len, uio);
            }
            break;

        case FT_A_BUF:
            tick->tk_aw_bufsize = len;
            err = uiomove(tick->tk_aw_bufdata, len, uio);
            if (err) {
                debug_printf("FT_A_BUF: error is %d (%p, %d, %p)\n",
                             err, tick->tk_aw_bufdata, len, uio);
            }
            break;

        default:
            panic("FUSE: unknown answer type for ticket %p", tick);
        }
    }

    return (err);
}

int
fticket_pull(struct fuse_ticket *tick, struct uio *uio)
{
    int err = 0;

    debug_printf("tick=%p, uio=%p\n", tick, uio);

    if (tick->tk_aw_ohead.error) {
        return (0);
    }

    err = fuse_body_audit(tick, uio_resid(uio));
    if (!err) {
        err = fticket_aw_pull_uio(tick, uio);
    }

    return (err);
}

struct fuse_data *
fdata_alloc(struct cdev *fdev, struct ucred *cred)
{
    struct fuse_data *data;

    debug_printf("fdev=%p, p=%p\n", fdev, p);

    data = malloc(sizeof(struct fuse_data), M_FUSEMSG, M_WAITOK | M_ZERO);

    data->mpri = FM_NOMOUNTED;
    data->fdev = fdev;
    data->dataflag = 0;
    mtx_init(&data->ms_mtx, "fuse message list mutex", NULL, MTX_DEF);
    STAILQ_INIT(&data->ms_head);
    mtx_init(&data->ticket_mtx, "fuse ticketer mutex", NULL, MTX_DEF);
    debug_printf("ALLOC_INIT data=%p ticket_mtx=%p\n", data, data->ticket_mtx);
    STAILQ_INIT(&data->freetickets_head);
    TAILQ_INIT(&data->alltickets_head);
    mtx_init(&data->aw_mtx, "fuse answer list mutex", NULL, MTX_DEF);
    TAILQ_INIT(&data->aw_head);
    data->ticketer = 0;
    data->freeticket_counter = 0;
    data->daemoncred = crhold(cred);

#ifdef FUSE_EXPLICIT_RENAME_LOCK
    sx_init(&data->rename_lock, "fuse rename lock");
#endif

    return (data);
}

void
fdata_destroy(struct fuse_data *data)
{
    struct fuse_ticket *tick;

    debug_printf("data=%p, destroy.mntco = %d\n", data, data->mntco);

    /* Driving off stage all that stuff thrown at device... */
    mtx_destroy(&data->ms_mtx);
    mtx_destroy(&data->aw_mtx);
    mtx_destroy(&data->ticket_mtx);
#ifdef FUSE_EXPLICIT_RENAME_LOCK
    sx_destroy(&data->rename_lock);
#endif

    while ((tick = fuse_pop_allticks(data))) {
        fticket_destroy(tick);
    }

    crfree(data->daemoncred);

    free(data,M_FUSEMSG);
}

int
fdata_kick_get(struct fuse_data *data)
{
    debug_printf("data=%p\n", data);

    return (data->dataflag & FSESS_KICK);
}

void
fdata_kick_set(struct fuse_data *data)
{
    debug_printf("data=%p\n", data);

    mtx_lock(&data->ms_mtx);
    if (fdata_kick_get(data)) { 
        mtx_unlock(&data->ms_mtx);
        return;
    }

    data->dataflag |= FSESS_KICK;
    wakeup_one(data);
    selwakeuppri(&data->ks_rsel, PZERO + 1);
    mtx_unlock(&data->ms_mtx);

    mtx_lock(&data->ticket_mtx);
    wakeup(&data->ticketer);
    mtx_unlock(&data->ticket_mtx);
}

static __inline void
fuse_push_freeticks(struct fuse_ticket *tick)
{
    debug_printf("tick=%p\n", tick);

    STAILQ_INSERT_TAIL(&tick->tk_data->freetickets_head, tick,
                       tk_freetickets_link);
    tick->tk_data->freeticket_counter++;
}

static __inline struct fuse_ticket *
fuse_pop_freeticks(struct fuse_data *data)
{
    struct fuse_ticket *tick;

    debug_printf("data=%p\n", data);

    if ((tick = STAILQ_FIRST(&data->freetickets_head))) {
        STAILQ_REMOVE_HEAD(&data->freetickets_head, tk_freetickets_link);
        data->freeticket_counter--;
    }

    if (STAILQ_EMPTY(&data->freetickets_head) &&
        (data->freeticket_counter != 0)) {
        panic("ticket count mismatch!");
    }

    return tick;
}

static __inline void
fuse_push_allticks(struct fuse_ticket *tick)
{
    debug_printf("tick=%p\n", tick);

    TAILQ_INSERT_TAIL(&tick->tk_data->alltickets_head, tick,
                      tk_alltickets_link);
}

static __inline void
fuse_remove_allticks(struct fuse_ticket *tick)
{
    debug_printf("tick=%p\n", tick);

    TAILQ_REMOVE(&tick->tk_data->alltickets_head, tick, tk_alltickets_link);
}

static struct fuse_ticket *
fuse_pop_allticks(struct fuse_data *data)
{
    struct fuse_ticket *tick;

    debug_printf("data=%p\n", data);

    if ((tick = TAILQ_FIRST(&data->alltickets_head))) {
        fuse_remove_allticks(tick);
    }

    return (tick);
}

struct fuse_ticket *
fuse_ticket_fetch(struct fuse_data *data)
{
    int err = 0;
    struct fuse_ticket *tick;

    debug_printf("data=%p\n", data);

    mtx_lock(&data->ticket_mtx);

    if (data->freeticket_counter == 0) {
        mtx_unlock(&data->ticket_mtx);
        tick = fticket_alloc(data);
        if (!tick) {
            panic("ticket allocation failed");
        }
        mtx_lock(&data->ticket_mtx);
        fuse_push_allticks(tick);
    } else {
        /* locked here */
        tick = fuse_pop_freeticks(data);
        if (!tick) {
            panic("no free ticket despite the counter's value");
        }
    }

    if (!(data->dataflag & FSESS_INITED) && data->ticketer > 1) {
        err = msleep(&data->ticketer, &data->ticket_mtx, PCATCH | PDROP,
                     "fu_ini", 0);
    } else {
        mtx_unlock(&data->ticket_mtx);
    }

    if (err) {
        fdata_kick_set(data);
    }

    return (tick);
}

void
fuse_ticket_drop(struct fuse_ticket *tick)
{
    int die = 0;

    debug_printf("tick=%p\n", tick);

    mtx_lock(&tick->tk_data->ticket_mtx);

    if (fuse_max_freetickets >= 0 &&
        fuse_max_freetickets <= tick->tk_data->freeticket_counter) {
        die = 1;
    } else {
        mtx_unlock(&tick->tk_data->ticket_mtx);
        fticket_refresh(tick);
        mtx_lock(&tick->tk_data->ticket_mtx);
    }

    /* locked here */

    if (die) {
        fuse_remove_allticks(tick);
        mtx_unlock(&tick->tk_data->ticket_mtx);
        fticket_destroy(tick);
    } else {
        fuse_push_freeticks(tick);
        mtx_unlock(&tick->tk_data->ticket_mtx);
    }
}

void
fuse_ticket_drop_invalid(struct fuse_ticket *tick)
{
    debug_printf("tick=%p\n", tick);

    if (tick->tk_flag & FT_INVAL) {
        fuse_ticket_drop(tick);
    }
}

void
fuse_insert_callback(struct fuse_ticket *tick, fuse_handler_t *handler)
{
    debug_printf("tick=%p, handler=%p\n", tick, handler);

    if (fdata_kick_get(tick->tk_data)) {
        return;
    }

    tick->tk_aw_handler = handler;

    mtx_lock(&tick->tk_data->aw_mtx);
    fuse_aw_push(tick);
    mtx_unlock(&tick->tk_data->aw_mtx);
}

void
fuse_insert_message(struct fuse_ticket *tick)
{
    debug_printf("tick=%p\n", tick);

    if (tick->tk_flag & FT_DIRTY) {
        panic("FUSE: ticket reused without being refreshed");
    }

    tick->tk_flag |= FT_DIRTY;

    if (fdata_kick_get(tick->tk_data)) {
        return;
    }

    mtx_lock(&tick->tk_data->ms_mtx);
    fuse_ms_push(tick);
    wakeup_one(tick->tk_data);
    selwakeuppri(&tick->tk_data->ks_rsel, PZERO + 1);
    mtx_unlock(&tick->tk_data->ms_mtx);
}

static int
fuse_body_audit(struct fuse_ticket *tick, size_t blen)
{
    int err = 0;
    enum fuse_opcode opcode;

    debug_printf("tick=%p, blen = %x\n", tick, blen);

    opcode = fticket_opcode(tick);

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
        if (fuse_libabi_geq(tick->tk_data, 7, 4))
            err = blen == sizeof(struct fuse_statfs_out) ? 0 : EINVAL;
        else
            err = blen == FUSE_COMPAT_STATFS_SIZE ? 0 : EINVAL;
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

    case FUSE_FLUSH:
        err = blen == 0 ? 0 : EINVAL;
        break;

    case FUSE_INIT:
        if (blen == sizeof(struct fuse_init_out) || blen == 8)
            err = 0;
        else
            err = EINVAL;
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

    case FUSE_GETLK:
        panic("FUSE: no response body format check for FUSE_GETLK");
        break;

    case FUSE_SETLK:
        panic("FUSE: no response body format check for FUSE_SETLK");
        break;

    case FUSE_SETLKW:
        panic("FUSE: no response body format check for FUSE_SETLKW");
        break;

    case FUSE_ACCESS:
        err = blen == 0 ? 0 : EINVAL;
        break;

    case FUSE_CREATE:
        err = blen == sizeof(struct fuse_entry_out) +
                      sizeof(struct fuse_open_out) ? 0 : EINVAL;
        break;

    case FUSE_DESTROY:
        break;

    default:
        panic("FUSE: opcodes out of sync");
    }

    return (err);
}

static void
fuse_setup_ihead(struct fuse_in_header *ihead,
                 struct fuse_ticket *tick,
                 uint64_t nid,
                 enum fuse_opcode op,
                 size_t blen,
                 pid_t pid, struct ucred *cred)
{
    ihead->len = sizeof(*ihead) + blen;
    ihead->unique = tick->tk_unique;
    ihead->nodeid = nid;
    ihead->opcode = op;

    debug_printf("ihead=%p, tick=%p, nid=%llx, op=%d, blen=%x, context=%p\n",
                 ihead, tick, nid, op, blen, context);

    ihead->pid = pid;
    ihead->uid = cred->cr_uid;
    ihead->gid = cred->cr_rgid;
}

/*
 * fuse_standard_handler just pulls indata and wakes up pretender.
 * Doesn't try to interpret data, that's left for the pretender.
 * Though might do a basic size verification before the pull-in takes place
 */

static int
fuse_standard_handler(struct fuse_ticket *tick, struct uio *uio)
{
    int err = 0;
    int dropflag = 0;

    debug_printf("tick=%p, uio=%p\n", tick, uio);

    err = fticket_pull(tick, uio);

    mtx_lock(&tick->tk_aw_mtx);

    if (fticket_answered(tick)) {
        /* The requester was interrupted and she set the "answered" flag
         * to notify us. In this case, we don't have to care about
         * anything, just drop the ticket and get out as fast as we can.
         */
        dropflag = 1;
    } else {
        fticket_set_answered(tick);
        tick->tk_aw_errno = err;
        wakeup(tick);
    }

    mtx_unlock(&tick->tk_aw_mtx);

    if (dropflag) {
        fuse_ticket_drop(tick);
    }

    return (err);
}

void
fdisp_make_pid(struct fuse_dispatcher *fdip,
               enum fuse_opcode op,
               struct mount *mp,
               uint64_t nid,
               pid_t pid,
               struct ucred *cred)
{
    struct fuse_data *data = fusefs_get_data(mp);

    debug_printf("fdip=%p, op=%d, mp=%p, nid=%llx, context=%p\n",
                 op, mp, nid, context);

    if (fdip->tick) {
        fticket_refresh(fdip->tick);
    } else {
        fdip->tick = fuse_ticket_fetch(data);
    }

    if (fdip->tick == 0) {
        panic("fuse_ticket_fetch() failed");
    }

    FUSE_DIMALLOC(&fdip->tick->tk_ms_fiov, fdip->finh,
                  fdip->indata, fdip->iosize);

    fuse_setup_ihead(fdip->finh, fdip->tick, nid, op, fdip->iosize, pid, cred);
}

void
fdisp_make(struct fuse_dispatcher *fdip,
           enum fuse_opcode op,
           struct mount *mp,
           uint64_t nid,
           struct thread *td,
           struct ucred *cred)
{
    RECTIFY_TDCR(td, cred);

    return (fdisp_make_pid(fdip, op, mp, nid, td->td_proc->p_pid, cred));
}

void
fdisp_make_vp(struct fuse_dispatcher *fdip,
              enum fuse_opcode op,
              struct vnode *vp,
              struct thread *td,
              struct ucred *cred)
{
    debug_printf("fdip=%p, op=%d, vp=%p, context=%p\n", fdip, op, vp, context);
    RECTIFY_TDCR(td, cred);
    return (fdisp_make_pid(fdip, op, vnode_mount(vp), VTOI(vp),
            td->td_proc->p_pid, cred));
}

int
fdisp_wait_answ(struct fuse_dispatcher *fdip)
{
    int err = 0;

    fdip->answ_stat = 0;
    fuse_insert_callback(fdip->tick, fuse_standard_handler);
    fuse_insert_message(fdip->tick);

    if ((err = fticket_wait_answer(fdip->tick))) { // interrupted

#ifndef DONT_TRY_HARD_PREVENT_IO_IN_VAIN
        struct fuse_ticket *tick;
        unsigned            age;
#endif

        debug_printf("IPC: interrupted, err = %d\n", err);

        mtx_lock(&fdip->tick->tk_aw_mtx);

        if (fticket_answered(fdip->tick)) {
            /*
             * Just between noticing the interrupt and getting here,
             * the standard handler has completed his job.
             * So we drop the ticket and exit as usual.
             */
            debug_printf("IPC: already answered\n");
            mtx_unlock(&fdip->tick->tk_aw_mtx);
            goto out;
        } else {
            /*
             * So we were faster than the standard handler.
             * Then by setting the answered flag we get *him*
             * to drop the ticket.
             */
            debug_printf("IPC: setting to answered\n");
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
            mtx_lock(&fdip->tick->tk_data->aw_mtx);
            TAILQ_FOREACH(tick, &fdip->tick->tk_data->aw_head, tk_aw_link) {
                if (tick == fdip->tick) {
                    if (fdip->tick->tk_age == age) {
                        debug_printf("IPC: preventing io in vain succeeded\n");
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

    debug_printf("IPC: not interrupted, err = %d\n", err);

    if (fdip->tick->tk_aw_errno) {
        debug_printf("IPC: explicit EIO-ing, tk_aw_errno = %d\n",
                      fdip->tick->tk_aw_errno);
        err = EIO;
        goto out;
    }

    if ((err = fdip->tick->tk_aw_ohead.error)) {
        debug_printf("IPC: setting status to %d\n",
                     fdip->tick->tk_aw_ohead.error);
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

    debug_printf("IPC: all is well\n");

    return (0);

out:
    debug_printf("IPC: dropping ticket, err = %d\n", err);
    fuse_ticket_drop(fdip->tick);

    return (err);
}
