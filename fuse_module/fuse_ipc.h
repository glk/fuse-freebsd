/*
 * Copyright (C) 2006 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_IPC_H_
#define _FUSE_IPC_H_
/*
 * Messaging related stuff and parameters of a session
 */

/*
 * Basic data carrying thingy with managed allocations.
 * fiov_adjust() is the primary public interface.
 */
struct fuse_iov {
    /* "public" members, provide an interface similar to that of an iov */
    void   *base;
    size_t  len;		/* nominal length */
    /* "private" members */
    size_t  allocated_size;	/* size of allocated buffer */
    int     credit;		/* allow overruns of max permanent size
				   this many times */
};

void fiov_init(struct fuse_iov *fiov, size_t size);
void fiov_teardown(struct fuse_iov *fiov);
/* make fiov useable for others again */
void fiov_refresh(struct fuse_iov *fiov);
/* tune fiov so that its len will be set to size */
void fiov_adjust(struct fuse_iov *fiov, size_t size);

#define FUSE_DIMALLOC(fiov, spc1, spc2, amnt)          \
do {                                                   \
    fiov_adjust(fiov, (sizeof(*(spc1)) + (amnt)));     \
    (spc1) = (fiov)->base;                             \
    (spc2) = (char *)(fiov)->base + (sizeof(*(spc1))); \
} while (0)

#define FU_AT_LEAST(siz) max((siz), 128)

struct fuse_ticket;
struct fuse_data;

/*
 * As the last phase of a message passing, a function of this prototype is
 * called.
 */
typedef	int fuse_handler_t(struct fuse_ticket *tick, struct uio *uio);

/*
 * fuse_ticket is the basic data structure for kernel / userspace messaging
 */

struct fuse_ticket {
    /* fields giving the identity of the ticket */
    uint64_t                     tk_unique;
    struct fuse_data            *tk_data;
    int                          tk_flag;
    unsigned int                 tk_age;

    STAILQ_ENTRY(fuse_ticket)    tk_freetickets_link;
    TAILQ_ENTRY(fuse_ticket)     tk_alltickets_link;

    /* fields for initiating an upgoing message */
    struct fuse_iov              tk_ms_fiov;
    void                        *tk_ms_bufdata;
    unsigned long                tk_ms_bufsize;
    enum { FT_M_FIOV, FT_M_BUF } tk_ms_type;
    STAILQ_ENTRY(fuse_ticket)    tk_ms_link;

    /* fields for handling answers coming from userspace */
    struct fuse_iov              tk_aw_fiov;
    void                        *tk_aw_bufdata;
    unsigned long                tk_aw_bufsize;
    enum { FT_A_FIOV, FT_A_BUF } tk_aw_type;

    struct fuse_out_header       tk_aw_ohead;
    int                          tk_aw_errno;
    struct mtx                   tk_aw_mtx;
    fuse_handler_t              *tk_aw_handler;
    struct fuse_iov              tk_aw_handler_parm;
    TAILQ_ENTRY(fuse_ticket)     tk_aw_link;
};

#define FT_ANSW     0x01 /* request of ticket has already been answered */
#define FT_NOTOWNED 0x02 /* ticket is not owned */
#define FT_DIRTY    0x04 /* ticket has been used */

static __inline struct fuse_iov *
fticket_resp(struct fuse_ticket *tick)
{
    kdebug_printf("-> tick=%p\n", tick);
    return (&tick->tk_aw_fiov);
}

static __inline int
fticket_answered(struct fuse_ticket *tick)
{
    kdebug_printf("-> tick=%p\n", tick);
    return (tick->tk_flag & FT_ANSW);
}

static __inline void
fticket_set_answered(struct fuse_ticket *tick)
{
    kdebug_printf("-> tick=%p\n", tick);
    tick->tk_flag |= FT_ANSW;
}

static __inline enum fuse_opcode
fticket_opcode(struct fuse_ticket *tick)
{
    kdebug_printf("-> tick=%p\n", tick);
    return (((struct fuse_in_header *)(tick->tk_ms_fiov.base))->opcode);
}

static __inline void
fticket_disown(struct fuse_ticket *tick)
{
    kdebug_printf("-> tick=%p\n", tick);
    tick->tk_flag |= FT_NOTOWNED;
}

/* pull in userspace data from uio and pass it to tick */
int fticket_pull(struct fuse_ticket *tick, struct uio *uio);

enum mountpri { FM_NOMOUNTED, FM_PRIMARY, FM_SECONDARY };

/*
 * The data representing a FUSE session.
 * It contains the queues used in the communication
 * and the respective locks.
 */

struct fuse_data {
    enum mountpri              mpri;

    /* queue for upgoing messages */
    struct mtx                 ms_mtx;
    STAILQ_HEAD(, fuse_ticket) ms_head;

    /* queue of answer waiters */
    struct mtx                 aw_mtx;
    TAILQ_HEAD(, fuse_ticket)  aw_head;

    /* fuse_ticket repository */
    struct mtx                 ticket_mtx;
    STAILQ_HEAD(, fuse_ticket) freetickets_head;
    TAILQ_HEAD(, fuse_ticket)  alltickets_head;
    uint32_t                   freeticket_counter;
    uint32_t                   deadticket_counter;
    uint32_t                   ticketer;

#if _DEBUG_UNIQUE
    uint64_t                   msgcou;
#endif

    struct sx                  rename_lock;

    struct ucred *daemoncred;

    struct selinfo ks_rsel;

    int dataflag;

    struct cdev *fdev;
    struct mount *mp;
    struct vnode *rvp;

    /* mount info */
    int mntco;
    struct sx mhierlock;
    LIST_HEAD(, fuse_secondary_data) slaves_head;

    uint32_t                   fuse_libabi_major;
    uint32_t                   fuse_libabi_minor;

    unsigned                   max_write;
    unsigned                   max_read;
};

#define FSESS_KICK                0x0001 /* session is to be closed */
#define FSESS_OPENED              0x0002 /* the device of the session has been opened */
#define FSESS_NOFSYNC             0x0004 /* daemon doesn't implement fsync */
#define FSESS_NOFSYNCDIR          0x0008 /* daemon doesn't implement fsyncdir */
#define FSESS_NOACCESS            0x0010 /* daemon doesn't implement access */
#define FSESS_NOCREATE            0x0020 /* daemon doesn't implement create */
#define FSESS_INITED              0x0040 /* session has been inited */
#define FSESS_DAEMON_CAN_SPY      0x0080 /* let non-owners access this fs
                                            (and being observed by the daemon) */
#define FSESS_NEGLECT_SHARES      0x0100 /* presence of secondary mount is not
                                            considered as "fs is busy" */
#define FSESS_PRIVATE             0x0200 /* don't allow secondary mounts */
#define FSESS_PUSH_SYMLINKS_IN    0x0400 /* prefix absolute symlinks with mp */
#define FSESS_DEFAULT_PERMISSIONS 0x0800 /* kernel does permission checking, based
                                            on file mode */
#define FSESS_SYNC_UNMOUNT        0x1000 /* intends to do a synchronous unmount
                                            (ie, wait with unmount 'till daemon
                                            signals "ready") */
#define FSESS_CAN_SYNC_UNMOUNT    0x2000 /* capable of doing a sync unmount when
                                            the "sync_unmount" sysctl has
                                            obligated a privilege check */

static __inline struct fuse_data *
fusedev_get_data(struct cdev *fdev)
{
	return (fdev->si_drv1);
}

static __inline struct fuse_data *
fusefs_get_data(struct mount *mp)
{
    struct fuse_data *data = mp->mnt_data;
    kdebug_printf("-> mp=%p\n", mp);
    return (data->mpri == FM_PRIMARY ? data : NULL);
}

/* misc functions for managing queues and alike */

static __inline void
fuse_ms_push(struct fuse_ticket *tick)
{
    kdebug_printf("-> tick=%p\n", tick);
    STAILQ_INSERT_TAIL(&tick->tk_data->ms_head, tick, tk_ms_link);
}

static __inline struct fuse_ticket *
fuse_ms_pop(struct fuse_data *data)
{
    struct fuse_ticket *tick;

    kdebug_printf("-> data=%p\n", data);

    if ((tick = STAILQ_FIRST(&data->ms_head))) {
        STAILQ_REMOVE_HEAD(&data->ms_head, tk_ms_link);
    }
    return (tick);
}

static __inline void
fuse_aw_push(struct fuse_ticket *tick)
{
    kdebug_printf("-> tick=%p\n", tick);
    TAILQ_INSERT_TAIL(&tick->tk_data->aw_head, tick, tk_aw_link);
}

static __inline void
fuse_aw_remove(struct fuse_ticket *tick)
{
    kdebug_printf("-> tick=%p\n", tick);
    TAILQ_REMOVE(&tick->tk_data->aw_head, tick, tk_aw_link);
}

static __inline struct fuse_ticket *
fuse_aw_pop(struct fuse_data *data)
{
    struct fuse_ticket *tick;

    kdebug_printf("-> data=%p\n", data);

    if ((tick = TAILQ_FIRST(&data->aw_head))) {
        fuse_aw_remove(tick);
    }

    return (tick);
}

struct fuse_ticket *fuse_ticket_fetch(struct fuse_data *data);
void fuse_ticket_drop(struct fuse_ticket *tick);
void fuse_ticket_drop_notowned(struct fuse_ticket *tick);
void fuse_insert_callback(struct fuse_ticket *tick, fuse_handler_t *handler);
void fuse_insert_message(struct fuse_ticket *tick);

static __inline int
fuse_libabi_geq(struct fuse_data *data, uint32_t maj, uint32_t min)
{
    return (data->fuse_libabi_major > maj ||
            (data->fuse_libabi_major == maj && data->fuse_libabi_minor >= min));
}

/*
 * VFS private data for secondary mount
 */
struct fuse_secondary_data {
    enum mountpri     mpri;
    struct mount     *mp;
    struct fuse_data *master;

    LIST_ENTRY(fuse_secondary_data) slaves_link;
};

static __inline struct fuse_secondary_data *
fusefs_get_secdata(struct mount *mp)
{
    struct fuse_secondary_data *fsdat = mp->mnt_data;
    return (fsdat->mpri == FM_SECONDARY ? fsdat : NULL);
}

struct fuse_data *fdata_alloc(struct cdev *dev, struct ucred *cred);
void fdata_destroy(struct fuse_data *data);
/* see if session is to be closed */
int fdata_kick_get(struct fuse_data *data);
/* mark session to be closed */
void fdata_kick_set(struct fuse_data *data);

/*
 * Structure used by the high level interface to messaging
 */

struct fuse_dispatcher {
    /* fields for stage 1 (and 0, 2) */
    struct fuse_ticket    *tick;
    struct fuse_in_header *finh;

    void    *indata;
    size_t   iosize;
    uint64_t nodeid;
    /* fields for stage 2 */
    int      answ_stat;
    void    *answ;
};

/* High-level routines for different stages of message passing */

/* stage 0 */
static __inline void
fdisp_init(struct fuse_dispatcher *fdisp, size_t iosize)
{
    kdebug_printf("-> fdisp=%p, iosize=%x\n", fdisp, iosize);
    fdisp->iosize = iosize;
    fdisp->tick = NULL;
}

/* stage 1 */
void fdisp_make(struct fuse_dispatcher *fdip, struct mount *mp,
                enum fuse_opcode op, uint64_t nid, struct thread *td,
                struct ucred *cred);
/* a variant using pid instead of a thread */
void fdisp_make_pid(struct fuse_dispatcher *fdip, struct mount *mp,
                    enum fuse_opcode op, uint64_t nid, pid_t pid,
                    struct ucred *cred);
/* simpler, vp based variant */
void fdisp_make_vp(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                   struct vnode *vp, struct thread *td, struct ucred *cred);

/* stage 2 */
int  fdisp_wait_answ(struct fuse_dispatcher *fdip);

/* stage 0, 1, 2 together for the simple case when only a header is sent up */
static __inline int
fdisp_simple_putget(struct fuse_dispatcher *fdip, enum fuse_opcode op,
                    struct vnode *vp, struct thread *td, struct ucred *cred)
{
    kdebug_printf("-> fdip=%p, opcode=%d, vp=%p\n", fdip, op, vp);
    fdisp_init(fdip, 0);
    fdisp_make_vp(fdip, op, vp, td, cred);

    return (fdisp_wait_answ(fdip));
}

#endif /* _FUSE_IPC_H_ */
