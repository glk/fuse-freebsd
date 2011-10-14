/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
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
#include <vm/uma.h>

#include "fuse.h"
#include "fuse_node.h"
#include "fuse_ipc.h"
#include "fuse_internal.h"

#define FUSE_DEBUG_MODULE IPC
#include "fuse_debug.h"

static struct fuse_ticket *fticket_alloc(struct fuse_data *data);
static void                fticket_refresh(struct fuse_ticket *ftick);
static void                fticket_destroy(struct fuse_ticket *ftick);
static int                 fticket_wait_answer(struct fuse_ticket *ftick);
static __inline__ int      fticket_aw_pull_uio(struct fuse_ticket *ftick,
                                               struct uio *uio);

static int             fuse_body_audit(struct fuse_ticket *ftick, size_t blen);
static __inline__ void fuse_setup_ihead(struct fuse_in_header *ihead,
                                        struct fuse_ticket    *ftick,
                                        uint64_t               nid,
                                        enum fuse_opcode       op,
                                        size_t                 blen,
                                        pid_t                  pid,
                                        struct ucred          *cred);

static fuse_handler_t  fuse_standard_handler;

SYSCTL_NODE(_vfs, OID_AUTO, fuse, CTLFLAG_RW, 0, "FUSE tunables");
SYSCTL_STRING(_vfs_fuse, OID_AUTO, fuse4bsd_version, CTLFLAG_RD,
              FUSE4BSD_VERSION, 0, "fuse4bsd version");
static int fuse_ticket_count = 0;
SYSCTL_INT(_vfs_fuse, OID_AUTO, ticket_count, CTLFLAG_RW,
            &fuse_ticket_count, 0, "number of allocated tickets");
static long fuse_iov_permanent_bufsize = 1 << 19;
SYSCTL_LONG(_vfs_fuse, OID_AUTO, iov_permanent_bufsize, CTLFLAG_RW,
            &fuse_iov_permanent_bufsize, 0,
            "limit for permanently stored buffer size for fuse_iovs");
static int fuse_iov_credit = 16;
SYSCTL_INT(_vfs_fuse, OID_AUTO, iov_credit, CTLFLAG_RW,
            &fuse_iov_credit, 0,
            "how many times is an oversized fuse_iov tolerated");

MALLOC_DEFINE(M_FUSEMSG, "fuse_msgbuf", "fuse message buffer");
static uma_zone_t ticket_zone;

void
fiov_init(struct fuse_iov *fiov, size_t size)
{
    uint32_t msize = FU_AT_LEAST(size);

    debug_printf("fiov=%p, size=%zd\n", fiov, size);

    fiov->len = 0;

    fiov->base = malloc(msize, M_FUSEMSG, M_WAITOK | M_ZERO);

    fiov->allocated_size = msize;
    fiov->credit = fuse_iov_credit;
}

void
fiov_teardown(struct fuse_iov *fiov)
{
    debug_printf("fiov=%p\n", fiov);

    MPASS(fiov->base != NULL);
    free(fiov->base, M_FUSEMSG);
}

void
fiov_adjust(struct fuse_iov *fiov, size_t size)
{
    debug_printf("fiov=%p, size=%zd\n", fiov, size);

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

static int
fticket_ctor(void *mem, int size, void *arg, int flags)
{
    struct fuse_ticket *ftick = mem;
    struct fuse_data *data = arg;

    debug_printf("ftick=%p data=%p\n", ftick, data);

    FUSE_ASSERT_MS_DONE(ftick);
    FUSE_ASSERT_AW_DONE(ftick);

    mtx_lock(&data->ticket_mtx);
    ftick->tk_unique = data->ticketer++;
    mtx_unlock(&data->ticket_mtx);
    ftick->tk_data = data;

    fiov_init(&ftick->tk_ms_fiov, sizeof(struct fuse_in_header));
    ftick->tk_ms_type = FT_M_FIOV;

    mtx_init(&ftick->tk_aw_mtx, "fuse answer delivery mutex", NULL, MTX_DEF);
    fiov_init(&ftick->tk_aw_fiov, 0);
    ftick->tk_aw_type = FT_A_FIOV;

    refcount_init(&ftick->tk_refcount, 1);
    atomic_add_acq_int(&fuse_ticket_count, 1);

    return 0;
}

static void
fticket_dtor(void *mem, int size, void *arg)
{
    struct fuse_ticket *ftick = mem;

    debug_printf("ftick=%p\n", ftick);

    FUSE_ASSERT_MS_DONE(ftick);
    FUSE_ASSERT_AW_DONE(ftick);

    fiov_teardown(&ftick->tk_ms_fiov);
    fiov_teardown(&ftick->tk_aw_fiov);
    mtx_destroy(&ftick->tk_aw_mtx);

    atomic_subtract_acq_int(&fuse_ticket_count, 1);

    bzero(ftick, sizeof(struct fuse_ticket)); // XXX
}

static int
fticket_init(void *mem, int size, int flags)
{
    struct fuse_ticket *ftick = mem;

    DEBUG("ftick=%p\n", ftick);

    bzero(ftick, sizeof(struct fuse_ticket));

    return 0;
}

static void
fticket_fini(void *mem, int size)
{
    struct fuse_ticket *ftick = mem;

    DEBUG("ftick=%p\n", ftick);

}

static __inline struct fuse_ticket *
fticket_alloc(struct fuse_data *data)
{
    return uma_zalloc_arg(ticket_zone, data, M_WAITOK);
}

static __inline void
fticket_destroy(struct fuse_ticket *ftick)
{
    return uma_zfree(ticket_zone, ftick);
}

static __inline__
void
fticket_refresh(struct fuse_ticket *ftick)
{
    debug_printf("ftick=%p\n", ftick);

    FUSE_ASSERT_MS_DONE(ftick);
    FUSE_ASSERT_AW_DONE(ftick);

    fiov_refresh(&ftick->tk_ms_fiov);
    ftick->tk_ms_bufdata = NULL;
    ftick->tk_ms_bufsize = 0;
    ftick->tk_ms_type = FT_M_FIOV;

    bzero(&ftick->tk_aw_ohead, sizeof(struct fuse_out_header));

    fiov_refresh(&ftick->tk_aw_fiov);
    ftick->tk_aw_errno = 0;
    ftick->tk_aw_bufdata = NULL;
    ftick->tk_aw_bufsize = 0;
    ftick->tk_aw_type = FT_A_FIOV;

    ftick->tk_flag = 0;
}

static int
fticket_wait_answer(struct fuse_ticket *ftick)
{
    int err = 0;
    struct fuse_data *data;

    debug_printf("ftick=%p\n", ftick);
    fuse_lck_mtx_lock(ftick->tk_aw_mtx);

    if (fticket_answered(ftick)) {
        goto out;
    }

    data = ftick->tk_data;

    if (fdata_get_dead(data)) {
        err = ENOTCONN;
        fticket_set_answered(ftick);
        goto out;
    }

    err = msleep(ftick, &ftick->tk_aw_mtx, PCATCH, "fu_ans",
                 data->daemon_timeout * hz);
    if (err == EAGAIN) { /* same as EWOULDBLOCK */
#ifdef XXXIP /* die conditionally */
        if (!fdata_get_dead(data)) {
            fdata_set_dead(data);
        }
#endif
        err = ETIMEDOUT;
        fticket_set_answered(ftick);
    }

out:
    if (!(err || fticket_answered(ftick))) {
        debug_printf("FUSE: requester was woken up but still no answer");
        err = ENXIO;
    }

    fuse_lck_mtx_unlock(ftick->tk_aw_mtx);

    return err;
}

static __inline__
int
fticket_aw_pull_uio(struct fuse_ticket *ftick, struct uio *uio)
{
    int err = 0;
    size_t len = uio_resid(uio);

    debug_printf("ftick=%p, uio=%p\n", ftick, uio);

    if (len) {
        switch (ftick->tk_aw_type) {
        case FT_A_FIOV:
            fiov_adjust(fticket_resp(ftick), len);
            err = uiomove(fticket_resp(ftick)->base, len, uio);
            if (err) {
                debug_printf("FUSE: FT_A_FIOV: error is %d (%p, %zd, %p)\n",
                             err, fticket_resp(ftick)->base, len, uio);
            }
            break;

        case FT_A_BUF:
            ftick->tk_aw_bufsize = len;
            err = uiomove(ftick->tk_aw_bufdata, len, uio);
            if (err) {
                debug_printf("FUSE: FT_A_BUF: error is %d (%p, %zd, %p)\n",
                             err, ftick->tk_aw_bufdata, len, uio);
            }
            break;

        default:
            panic("FUSE: unknown answer type for ticket %p", ftick);
        }
    }

    return err;
}

int
fticket_pull(struct fuse_ticket *ftick, struct uio *uio)
{
    int err = 0;

    debug_printf("ftick=%p, uio=%p\n", ftick, uio);

    if (ftick->tk_aw_ohead.error) {
        return 0;
    }

    err = fuse_body_audit(ftick, uio_resid(uio));
    if (!err) {
        err = fticket_aw_pull_uio(ftick, uio);
    }

    return err;
}

struct fuse_data *
fdata_alloc(struct cdev *fdev, struct ucred *cred)
{
    struct fuse_data *data;

    debug_printf("fdev=%p\n", fdev);

    data = malloc(sizeof(struct fuse_data), M_FUSEMSG, M_WAITOK | M_ZERO);

    data->mpri = FM_NOMOUNTED;
    data->fdev = fdev;
    data->dataflags = 0;
    mtx_init(&data->ms_mtx, "fuse message list mutex", NULL, MTX_DEF);
    STAILQ_INIT(&data->ms_head);
    mtx_init(&data->ticket_mtx, "fuse ticketer mutex", NULL, MTX_DEF);
    debug_printf("ALLOC_INIT data=%p ticket_mtx=%p\n", data, &data->ticket_mtx);
    mtx_init(&data->aw_mtx, "fuse answer list mutex", NULL, MTX_DEF);
    TAILQ_INIT(&data->aw_head);
    data->ticketer = 0;
    data->daemoncred = crhold(cred);
    data->daemon_timeout = FUSE_DEFAULT_DAEMON_TIMEOUT;

#ifdef FUSE_EXPLICIT_RENAME_LOCK
    sx_init(&data->rename_lock, "fuse rename lock");
#endif

    return data;
}

void
fdata_destroy(struct fuse_data *data)
{
    debug_printf("data=%p, destroy.mntco = %d\n", data, data->mntco);

    /* Driving off stage all that stuff thrown at device... */
    mtx_destroy(&data->ms_mtx);
    mtx_destroy(&data->aw_mtx);
    mtx_destroy(&data->ticket_mtx);
#ifdef FUSE_EXPLICIT_RENAME_LOCK
    sx_destroy(&data->rename_lock);
#endif

    crfree(data->daemoncred);

    free(data,M_FUSEMSG);
}

void
fdata_set_dead(struct fuse_data *data)
{
    debug_printf("data=%p\n", data);

    fuse_lck_mtx_lock(data->ms_mtx);
    if (fdata_get_dead(data)) {
        fuse_lck_mtx_unlock(data->ms_mtx);
        return;
    }

    data->dataflags |= FSESS_DEAD;
    wakeup_one(data);
    selwakeuppri(&data->ks_rsel, PZERO + 1);
    fuse_lck_mtx_unlock(data->ms_mtx);

    fuse_lck_mtx_lock(data->ticket_mtx);
    wakeup(&data->ticketer);
    fuse_lck_mtx_unlock(data->ticket_mtx);
}

struct fuse_ticket *
fuse_ticket_fetch(struct fuse_data *data)
{
    int err = 0;
    struct fuse_ticket *ftick;

    debug_printf("data=%p\n", data);

    ftick = fticket_alloc(data);
    fuse_lck_mtx_lock(data->ticket_mtx);

    if (!(data->dataflags & FSESS_INITED) && data->ticketer > 1) {
        err = msleep(&data->ticketer, &data->ticket_mtx, PCATCH | PDROP,
                     "fu_ini", 0);
    } else {
        fuse_lck_mtx_unlock(data->ticket_mtx);
    }

    if (err) {
        fdata_set_dead(data);
    }

    return ftick;
}

int
fuse_ticket_drop(struct fuse_ticket *ftick)
{
    int die;

    die = refcount_release(&ftick->tk_refcount);
    debug_printf("ftick=%p refcount=%d\n", ftick, ftick->tk_refcount);
    if (die)
        fticket_destroy(ftick);

    return die;
}

void
fuse_insert_callback(struct fuse_ticket *ftick, fuse_handler_t *handler)
{
    debug_printf("ftick=%p, handler=%p data=%p\n", ftick, ftick->tk_data, handler);

    if (fdata_get_dead(ftick->tk_data)) {
        return;
    }

    ftick->tk_aw_handler = handler;

    fuse_lck_mtx_lock(ftick->tk_data->aw_mtx);
    fuse_aw_push(ftick);
    fuse_lck_mtx_unlock(ftick->tk_data->aw_mtx);
}

void
fuse_insert_message(struct fuse_ticket *ftick)
{
    debug_printf("ftick=%p\n", ftick);

    if (ftick->tk_flag & FT_DIRTY) {
        panic("FUSE: ticket reused without being refreshed");
    }

    ftick->tk_flag |= FT_DIRTY;

    if (fdata_get_dead(ftick->tk_data)) {
        return;
    }

    fuse_lck_mtx_lock(ftick->tk_data->ms_mtx);
    fuse_ms_push(ftick);
    wakeup_one(ftick->tk_data);
    selwakeuppri(&ftick->tk_data->ks_rsel, PZERO + 1);
    fuse_lck_mtx_unlock(ftick->tk_data->ms_mtx);
}

static int
fuse_body_audit(struct fuse_ticket *ftick, size_t blen)
{
    int err = 0;
    enum fuse_opcode opcode;

    debug_printf("ftick=%p, blen = %zu\n", ftick, blen);

    opcode = fticket_opcode(ftick);

    switch (opcode) {
    case FUSE_LOOKUP:
        err = (blen == sizeof(struct fuse_entry_out)) ? 0 : EINVAL;
        break;

    case FUSE_FORGET:
        panic("FUSE: a handler has been intalled for FUSE_FORGET");
        break;

    case FUSE_GETATTR:
        err = (blen == sizeof(struct fuse_attr_out)) ? 0 : EINVAL;
        break;

    case FUSE_SETATTR:
        err = (blen == sizeof(struct fuse_attr_out)) ? 0 : EINVAL;
        break;

    case FUSE_READLINK:
        err = (PAGE_SIZE >= blen) ? 0 : EINVAL;
        break;

    case FUSE_SYMLINK:
        err = (blen == sizeof(struct fuse_entry_out)) ? 0 : EINVAL;
        break;

    case FUSE_MKNOD:
        err = (blen == sizeof(struct fuse_entry_out)) ? 0 : EINVAL;
        break;

    case FUSE_MKDIR:
        err = (blen == sizeof(struct fuse_entry_out)) ? 0 : EINVAL;
        break;

    case FUSE_UNLINK:
        err = (blen == 0) ? 0 : EINVAL;
        break;

    case FUSE_RMDIR:
        err = (blen == 0) ? 0 : EINVAL;
        break;

    case FUSE_RENAME:
        err = (blen == 0) ? 0 : EINVAL;
        break;

    case FUSE_LINK:
        err = (blen == sizeof(struct fuse_entry_out)) ? 0 : EINVAL;
        break;

    case FUSE_OPEN:
        err = (blen == sizeof(struct fuse_open_out)) ? 0 : EINVAL;
        break;

    case FUSE_READ:
        err = (((struct fuse_read_in *)(
                (char *)ftick->tk_ms_fiov.base +
                        sizeof(struct fuse_in_header)
                  ))->size >= blen) ? 0 : EINVAL;
        break;

    case FUSE_WRITE:
        err = (blen == sizeof(struct fuse_write_out)) ? 0 : EINVAL;
        break;

    case FUSE_STATFS:
        if (fuse_libabi_geq(ftick->tk_data, 7, 4)) {
            err = (blen == sizeof(struct fuse_statfs_out)) ? 0 : EINVAL;
        } else {
            err = (blen == FUSE_COMPAT_STATFS_SIZE) ? 0 : EINVAL;
        }
        break;

    case FUSE_RELEASE:
        err = (blen == 0) ? 0 : EINVAL;
        break;

    case FUSE_FSYNC:
        err = (blen == 0) ? 0 : EINVAL;
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
        err = (blen == 0) ? 0 : EINVAL;
        break;

    case FUSE_INIT:
        if (blen == sizeof(struct fuse_init_out) || blen == 8) {
            err = 0;
        } else {
            err = EINVAL;
        }
        break;

    case FUSE_OPENDIR:
        err = (blen == sizeof(struct fuse_open_out)) ? 0 : EINVAL;
        break;

    case FUSE_READDIR:
        err = (((struct fuse_read_in *)(
                (char *)ftick->tk_ms_fiov.base +
                        sizeof(struct fuse_in_header)
                  ))->size >= blen) ? 0 : EINVAL;
        break;

    case FUSE_RELEASEDIR:
        err = (blen == 0) ? 0 : EINVAL;
        break;

    case FUSE_FSYNCDIR:
        err = (blen == 0) ? 0 : EINVAL;
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
        err = (blen == 0) ? 0 : EINVAL;
        break;

    case FUSE_CREATE:
        err = (blen == sizeof(struct fuse_entry_out) +
                           sizeof(struct fuse_open_out)) ? 0 : EINVAL;
        break;

    case FUSE_DESTROY:
        err = (blen == 0) ? 0 : EINVAL;
        break;

    default:
        panic("FUSE: opcodes out of sync (%d)\n", opcode);
    }

    return err;
}

static void
fuse_setup_ihead(struct fuse_in_header *ihead,
                 struct fuse_ticket    *ftick,
                 uint64_t               nid,
                 enum fuse_opcode       op,
                 size_t                 blen,
                 pid_t                  pid,
                 struct ucred          *cred)
{
    ihead->len = sizeof(*ihead) + blen;
    ihead->unique = ftick->tk_unique;
    ihead->nodeid = nid;
    ihead->opcode = op;

    debug_printf("ihead=%p, ftick=%p, nid=%ju, op=%d, blen=%zu\n",
                 ihead, ftick, (uintmax_t)nid, op, blen);

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
fuse_standard_handler(struct fuse_ticket *ftick, struct uio *uio)
{
    int err = 0;

    debug_printf("ftick=%p, uio=%p\n", ftick, uio);

    err = fticket_pull(ftick, uio);

    fuse_lck_mtx_lock(ftick->tk_aw_mtx);

    if (!fticket_answered(ftick)) {
        fticket_set_answered(ftick);
        ftick->tk_aw_errno = err;
        wakeup(ftick);
    }

    fuse_lck_mtx_unlock(ftick->tk_aw_mtx);

    return err;
}

void
fdisp_make_pid(struct fuse_dispatcher *fdip,
               enum fuse_opcode op,
               struct mount *mp,
               uint64_t nid,
               pid_t pid,
               struct ucred *cred)
{
    struct fuse_data *data = fuse_get_mpdata(mp);

    debug_printf("fdip=%p, op=%d, mp=%p, nid=%ju\n",
                 fdip, op, mp, (uintmax_t)nid);

    if (fdip->tick) {
        fticket_refresh(fdip->tick);
    } else {
        fdip->tick = fuse_ticket_fetch(data);
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

    return fdisp_make_pid(fdip, op, mp, nid, td->td_proc->p_pid, cred);
}

void
fdisp_make_vp(struct fuse_dispatcher *fdip,
              enum fuse_opcode op,
              struct vnode *vp,
              struct thread *td,
              struct ucred *cred)
{
    debug_printf("fdip=%p, op=%d, vp=%p\n", fdip, op, vp);
    RECTIFY_TDCR(td, cred);
    return fdisp_make_pid(fdip, op, vnode_mount(vp), VTOI(vp),
                          td->td_proc->p_pid, cred);
}

int
fdisp_wait_answ(struct fuse_dispatcher *fdip)
{
    int err = 0;

    fdip->answ_stat = 0;
    fuse_insert_callback(fdip->tick, fuse_standard_handler);
    fuse_insert_message(fdip->tick);

    if ((err = fticket_wait_answer(fdip->tick))) { // interrupted

        debug_printf("IPC: interrupted, err = %d\n", err);

        fuse_lck_mtx_lock(fdip->tick->tk_aw_mtx);

        if (fticket_answered(fdip->tick)) {
            /*
             * Just between noticing the interrupt and getting here,
             * the standard handler has completed his job.
             * So we drop the ticket and exit as usual.
             */
            debug_printf("IPC: already answered\n");
            fuse_lck_mtx_unlock(fdip->tick->tk_aw_mtx);
            goto out;
        } else {
            /*
             * So we were faster than the standard handler.
             * Then by setting the answered flag we get *him*
             * to drop the ticket.
             */
            debug_printf("IPC: setting to answered\n");
            fticket_set_answered(fdip->tick);
            fuse_lck_mtx_unlock(fdip->tick->tk_aw_mtx);
            return err;
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

    return 0;

out:
    debug_printf("IPC: dropping ticket, err = %d\n", err);

    return err;
}

void
fuse_ipc_init(void)
{
    ticket_zone = uma_zcreate("fuse_ticket", sizeof(struct fuse_ticket),
        fticket_ctor, fticket_dtor, fticket_init, fticket_fini,
        UMA_ALIGN_PTR, 0);
}

void
fuse_ipc_destroy(void)
{
    uma_zdestroy(ticket_zone);
}
