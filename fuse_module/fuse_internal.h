/*
 * Copyright (C) 2006 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_INTERNAL_H_
#define _FUSE_INTERNAL_H_

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/vnode.h>

#include "fuse_ipc.h"
#include "fuse_node.h"

static __inline struct mount *
vnode_mount(struct vnode *vp)
{
	return (vp->v_mount);
}

static __inline enum vtype
vnode_vtype(struct vnode *vp)
{
    return (vp->v_type);
}

static __inline int
vnode_isvroot(struct vnode *vp)
{
    return ((vp->v_vflag & VV_ROOT) != 0 ? 1 : 0);
}

static __inline ssize_t
uio_resid(struct uio *uio)
{
    return (uio->uio_resid);
}

static __inline off_t
uio_offset(struct uio *uio)
{
    return (uio->uio_offset);
}

static __inline void
uio_setoffset(struct uio *uio, off_t offset)
{
    uio->uio_offset = offset;
}

/* XXX */
struct fuse_pidcred {
	pid_t pid;
	struct ucred cred;
};

/* access */

#define FACCESS_VA_VALID   0x01 /* flag to sign to reuse cached attributes
                                   regardless of cache timeout */
#define FACCESS_DO_ACCESS  0x02 /* flag showing if we are to do access check */
#define FACCESS_STICKY     0x04 /* do sticky dir permission check */
#define FACCESS_CHOWN      0x08 /* do permission check for owner changing */
#define FACCESS_NOCHECKSPY 0x10 /* don't check if daemon is allowed to spy on
                                   user */
#define FACCESS_SETGID     0x12 /* do permission check for setting setgid flag */

#define FACCESS_XQUERIES FACCESS_STICKY | FACCESS_CHOWN | FACCESS_SETGID

#define FVP_ACCESS_NOOP   0x01 /* vnode based control flag for doing access check */

struct fuse_access_param {
    uid_t xuid;
    gid_t xgid;
    unsigned facc_flags;
};

int
fuse_internal_access(struct vnode *vp,
                     mode_t mode,
                     struct ucred *cred,
                     struct thread *td,
                     struct fuse_access_param *facp);

/* attributes */

static __inline
void
fuse_internal_attr_fat2vat(struct mount *mp,
                           struct fuse_attr *fat,
                           struct vattr *vap)
{
    DEBUG("node #%llu, mode 0%o\n", (unsigned long long)fat->ino, fat->mode);

    vattr_null(vap);

    vap->va_fsid = mp->mnt_stat.f_fsid.val[0];
    vap->va_fileid = fat->ino; /* XXX cast from 64 bits to 32 */
    vap->va_mode = fat->mode & ~S_IFMT;
    vap->va_nlink     = fat->nlink;
    vap->va_uid       = fat->uid;
    vap->va_gid       = fat->gid;
    vap->va_rdev      = fat->rdev;
    vap->va_size      = fat->size;
    vap->va_atime.tv_sec  = fat->atime; /* XXX on some platforms cast from 64 bits to 32 */
    vap->va_atime.tv_nsec = fat->atimensec;
    vap->va_mtime.tv_sec  = fat->mtime;
    vap->va_mtime.tv_nsec = fat->mtimensec;
    vap->va_ctime.tv_sec  = fat->ctime;
    vap->va_ctime.tv_nsec = fat->ctimensec;
    vap->va_blocksize = PAGE_SIZE;
    vap->va_type = IFTOVT(fat->mode);

#if (S_BLKSIZE == 512)
    /* Optimize this case */
    vap->va_bytes = fat->blocks << 9;
#else
    vap->va_bytes = fat->blocks * S_BLKSIZE;
#endif

    vap->va_flags = 0;
}

#define timespecadd(vvp, uvp)                  \
    do {                                       \
           (vvp)->tv_sec += (uvp)->tv_sec;     \
           (vvp)->tv_nsec += (uvp)->tv_nsec;   \
           if ((vvp)->tv_nsec >= 1000000000) { \
               (vvp)->tv_sec++;                \
               (vvp)->tv_nsec -= 1000000000;   \
           }                                   \
    } while (0)

#define cache_attrs(vp, fuse_out) do {                                         \
    struct timespec uptsp_ ## __func__;                                        \
                                                                               \
    VTOFUD(vp)->cached_attrs_valid.tv_sec = (fuse_out)->attr_valid;            \
    VTOFUD(vp)->cached_attrs_valid.tv_nsec = (fuse_out)->attr_valid_nsec;      \
    nanouptime(&uptsp_ ## __func__);                                           \
                                                                               \
    timespecadd(&VTOFUD(vp)->cached_attrs_valid, &uptsp_ ## __func__);         \
                                                                               \
    fuse_internal_attr_fat2vat((vp)->v_mount, &(fuse_out)->attr, VTOVA(vp));   \
} while (0)

/* fsync */

int
fuse_internal_fsync_callback(struct fuse_ticket *tick, struct uio *uio);

/* readdir */

struct pseudo_dirent {
    uint32_t d_namlen;
};

int
fuse_internal_readdir_processdata(struct uio *uio,
                                  size_t reqsize,
                                  void *buf,
                                  size_t bufsize,
                                  void *param);

/* remove */

int
fuse_internal_remove(struct vnode *dvp,
                     struct vnode *vp,
                     struct componentname *cnp,
                     enum fuse_opcode op);

/* rename */

int
fuse_internal_rename(struct vnode *fdvp,
                     struct componentname *fcnp,
                     struct vnode *tdvp,
                     struct componentname *tcnp);

/* strategy */




/* entity creation */

static __inline
int
fuse_internal_checkentry(struct fuse_entry_out *feo, enum vtype vtyp)
{
    debug_printf("feo=%p, vtype=%d\n", feo, vtyp);

    if (vtyp != IFTOVT(feo->attr.mode)) {
        debug_printf("EINVAL -- %x != %x\n", vtype, IFTOVT(feo->attr.mode));
        return (EINVAL);
    }

    if (feo->nodeid == FUSE_NULL_ID) {
        debug_printf("EINVAL -- feo->nodeid is NULL\n");
        return (EINVAL);
    }

    if (feo->nodeid == FUSE_ROOT_ID) {
        debug_printf("EINVAL -- feo->nodeid is FUSE_ROOT_ID\n");
        return (EINVAL);
    }

    return (0);
}

int
fuse_internal_newentry(struct vnode *dvp,
                       struct vnode **vpp,
                       struct componentname *cnp,
                       enum fuse_opcode op,
                       void *buf,
                       size_t bufsize,
                       enum vtype vtyp);

void
fuse_internal_newentry_makerequest(struct mount *mp,
                                   uint64_t dnid,
                                   struct componentname *cnp,
                                   enum fuse_opcode op,
                                   void *buf,
                                   size_t bufsize,
                                   struct fuse_dispatcher *fdip);

int
fuse_internal_newentry_core(struct vnode *dvp,
                            struct vnode **vpp,
                            enum vtype vtyp,
                            struct fuse_dispatcher *fdip);

/* entity destruction */

int
fuse_internal_forget_callback(struct fuse_ticket *tick, struct uio *uio);

void
fuse_internal_forget_send(struct mount *mp,
                          struct thread *td,
                          struct ucred *cred,
                          uint64_t nodeid,
                          uint64_t nlookup,
                          struct fuse_dispatcher *fdip);

/* fuse start/stop */

int fuse_internal_init_callback(struct fuse_ticket *tick, struct uio *uio);
void fuse_internal_send_init(struct fuse_data *data, struct thread *td);

#endif /* _FUSE_INTERNAL_H_ */
