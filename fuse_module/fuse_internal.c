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
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/dirent.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/sysctl.h>
#include <sys/priv.h>

#include "fuse.h"
#include "fuse_file.h"
#include "fuse_internal.h"
#include "fuse_ipc.h"
#include "fuse_node.h"
#include "fuse_file.h"
#include "fuse_param.h"

#ifdef ZERO_PAD_INCOMPLETE_BUFS
static int isbzero(void *buf, size_t len);
#endif

/* access */

static __inline int     fuse_check_spyable(struct fuse_dispatcher *fdip,
                                           struct mount *mp, struct thread *td,
                                           struct ucred *cred);
static __inline int     fuse_match_cred(struct ucred *daemoncred,
                                        struct ucred *usercred);

int
fuse_internal_access(struct vnode *vp,
                     mode_t mode,
                     struct ucred *cred,
                     struct thread *td,
                     struct fuse_access_param *facp)
{
    int err = 0;
    struct fuse_dispatcher fdi;

    /*
     * Disallow write attempts on read-only file systems; unless the file
     * is a socket, fifo, or a block or character device resident on the
     * file system.
     */

    DEBUG("ro? %#x vp #%llu mode %#x\n",
          vp->v_mount->mnt_flag & MNT_RDONLY, VTOILLU(vp), mode);

    RECTIFY_TDCR(td, cred);

    if (mode & VWRITE) {
            switch (vp->v_type) {
            case VDIR:
            case VLNK:
            case VREG:
                    if (vp->v_mount->mnt_flag & MNT_RDONLY) {
                            DEBUG("no write access (read-only fs)\n");
                            return (EROFS);
                    }
                    break;
            default:
                    break;
            }
    }

    bzero(&fdi, sizeof(fdi));
    if (vp->v_vflag & VV_ROOT && ! (facp->facc_flags & FACCESS_NOCHECKSPY)) {
            if ((err = fuse_check_spyable(&fdi, vp->v_mount, td, cred)))
                    return (err);
            facp->facc_flags |= FACCESS_NOCHECKSPY;
    }

    if (fusefs_get_data(vp->v_mount)->dataflag & FSESS_DEFAULT_PERMISSIONS ||
        /*
         * According to Linux code, we fall back to in-kernel check
         * when it comes to executing a file
         */
        (vp->v_type == VREG && mode == VEXEC)) {
            /* We are to do the check in-kernel */

            if (! (facp->facc_flags & FACCESS_VA_VALID)) {
                    err = VOP_GETATTR(vp, VTOVA(vp), cred);
                    if (err)
                            return (err);
                    facp->facc_flags |= FACCESS_VA_VALID;
            }

            err = vaccess(VTOVA(vp)->va_type,
                          VTOVA(vp)->va_mode,
                          VTOVA(vp)->va_uid,
                          VTOVA(vp)->va_gid,
                          mode, cred, NULL);

            if (err)
                    return (err);

            if (facp->facc_flags & FACCESS_STICKY) {
                    if (vp->v_type == VDIR && VTOVA(vp)->va_mode & S_ISTXT &&
                        mode == VWRITE) {
                            if (cred->cr_uid != facp->xuid &&
                                cred->cr_uid != VTOVA(vp)->va_uid)
                                    err = priv_check_cred(cred,
                                                          PRIV_VFS_ADMIN,
                                                          0);
                    }
                    /*
                     * We return here because this flags is exlusive
                     * with the others
                     */
                    KASSERT(facp->facc_flags == FACCESS_STICKY,
                            ("sticky access check comes in mixed"));
                    return (err);
            }

            if (mode != VADMIN)
                    return (err);

            if (facp->facc_flags & FACCESS_CHOWN) {
                    if ((cred->cr_uid != facp->xuid &&
                             facp->xuid != (uid_t)VNOVAL) ||
                        (cred->cr_gid != facp->xgid &&
                             facp->xgid != (gid_t)VNOVAL &&
                             ! groupmember(facp->xgid, cred)))
                            err = priv_check_cred(cred, PRIV_VFS_CHOWN, 0);
                    if (err)
                            return (err);
            }

            if (facp->facc_flags & FACCESS_SETGID) {
                    gid_t sgid = facp->xgid;

                    if (sgid == (gid_t)VNOVAL)
                            sgid = VTOVA(vp)->va_gid;

                    if (! groupmember(sgid, cred))
                            err = priv_check_cred(cred, PRIV_VFS_SETGID, 0);
                    return (err);
            }

    } else {
#if FUSE_HAS_ACCESS
            struct fuse_access_in *fai;

            if (! (facp->facc_flags & FACCESS_DO_ACCESS))
                    return (0);

            if (fusefs_get_data(vp->v_mount)->dataflag & FSESS_NOACCESS)
                    return (0);

            fdisp_init(&fdi, sizeof(*fai));
            fdisp_make_vp(&fdi, FUSE_ACCESS, vp, td, cred);

            fai = fdi.indata;

            fai->mask = F_OK;
            if (mode & VREAD)
                    fai->mask |= R_OK;
            if (mode & VWRITE)
                    fai->mask |= W_OK;
            if (mode & VEXEC)
                    fai->mask |= X_OK;

            if (! (err = fdisp_wait_answ(&fdi)))
                    fuse_ticket_drop(fdi.tick);

            if (err == ENOSYS) {
                    fusefs_get_data(vp->v_mount)->dataflag |= FSESS_NOACCESS;
                    err = 0;
            }
#endif
    }
    return err;
}

/*
 * An access check routine based on fuse_allow_task() of the Linux module.
 * Now we use this one rather than the more permissive function we used to
 * (and which seemed more logical to me), to ensure uniform behaviour on Linux
 * and FreeBSD.
 *
 * Non-null return value indicates error (ie., "not allowed").
 */
static __inline int
fuse_match_cred(struct ucred *basecred, struct ucred *usercred)
{
	if (basecred->cr_uid == usercred->cr_uid             &&
	    basecred->cr_uid == usercred->cr_ruid            &&
	    basecred->cr_uid == usercred->cr_svuid           &&
	    basecred->cr_groups[0] == usercred->cr_groups[0] &&
	    basecred->cr_groups[0] == usercred->cr_rgid      &&
	    basecred->cr_groups[0] == usercred->cr_svgid)
		return (0);

	return (EPERM);
}


static __inline int
fuse_check_spyable(struct fuse_dispatcher *fdip, struct mount *mp,
                   struct thread *td, struct ucred *cred)
{
	return (0);
}

/* fsync */

int
fuse_internal_fsync_callback(struct fuse_ticket *tick, struct uio *uio)
{
    fuse_trace_printf_func();

    if (tick->tk_aw_ohead.error == ENOSYS) {
        tick->tk_data->dataflag |= (fticket_opcode(tick) == FUSE_FSYNC) ?
                                        FSESS_NOFSYNC : FSESS_NOFSYNCDIR;
    }

    fuse_ticket_drop(tick);

    return 0;
}

int
fuse_internal_fsync(struct vnode           *vp,
                    struct thread          *td,
                    struct ucred           *cred,
                    struct fuse_filehandle *fufh,
                    void                   *param)
{
    int op = FUSE_FSYNC;
    struct fuse_fsync_in *ffsi;
    struct fuse_dispatcher *fdip = param;

    fuse_trace_printf_func();

    fdip->iosize = sizeof(*ffsi);
    fdip->tick = NULL;
    if (vnode_vtype(vp) == VDIR) {
        op = FUSE_FSYNCDIR;
    }
    
    fdisp_make_vp(fdip, op, vp, td, cred);
    ffsi = fdip->indata;
    ffsi->fh = fufh->fh_id;

    ffsi->fsync_flags = 1;
  
    fuse_insert_callback(fdip->tick, fuse_internal_fsync_callback);
    fuse_insert_message(fdip->tick);

    return 0;

}

/* readdir */

int
fuse_internal_readdir(struct vnode           *vp,
                      struct uio             *uio,
                      struct fuse_filehandle *fufh,
                      struct fuse_iov        *cookediov)
{
    int err = 0;
    struct fuse_dispatcher fdi;
    struct fuse_read_in   *fri;

    if (uio_resid(uio) == 0) {
        return (0);
    }

    fdisp_init(&fdi, 0);

    /* Note that we DO NOT have a UIO_SYSSPACE here (so no need for p2p I/O). */

    while (uio_resid(uio) > 0) {

        fdi.iosize = sizeof(*fri);
        fdisp_make_vp(&fdi, FUSE_READDIR, vp, NULL, NULL);

        fri = fdi.indata;
        fri->fh = fufh->fh_id;
        fri->offset = uio_offset(uio);
        fri->size = min(uio_resid(uio), FUSE_DEFAULT_IOSIZE); // mp->max_read

        if ((err = fdisp_wait_answ(&fdi))) {
            goto out;
        }

        if ((err = fuse_internal_readdir_processdata(uio, fri->size, fdi.answ,
                                                     fdi.iosize, cookediov))) {
            break;
        }
    }

    fuse_ticket_drop(fdi.tick);

out:
    return ((err == -1) ? 0 : err);
}

int
fuse_internal_readdir_processdata(struct uio *uio,
                                  size_t reqsize,
                                  void *buf,
                                  size_t bufsize,
                                  void *param)
{
    int err = 0;
    int cou = 0;
    int bytesavail;
    size_t freclen;

    struct dirent      *de;
    struct fuse_dirent *fudge;
    struct fuse_iov    *cookediov = param;
    
    if (bufsize < FUSE_NAME_OFFSET) {
        return (-1);
    }

    for (;;) {

        if (bufsize < FUSE_NAME_OFFSET) {
            err = -1;
            break;
        }

        cou++;

        fudge = (struct fuse_dirent *)buf;
        freclen = FUSE_DIRENT_SIZE(fudge);

        if (bufsize < freclen) {
            err = ((cou == 1) ? -1 : 0);
            break;
        }

#ifdef ZERO_PAD_INCOMPLETE_BUFS
        if (isbzero(buf, FUSE_NAME_OFFSET)) {
            err = -1;
            break;
        }
#endif

        if (!fudge->namelen || fudge->namelen > MAXNAMLEN) {
            err = EINVAL;
            break;
        }

        bytesavail = GENERIC_DIRSIZ((struct pseudo_dirent *)&fudge->namelen); 

        if (bytesavail > uio_resid(uio)) {
            err = -1;
            break;
        }

        fiov_refresh(cookediov);
        fiov_adjust(cookediov, bytesavail);

        de = (struct dirent *)cookediov->base;
        de->d_fileno = fudge->ino; /* XXX cast from 64 to 32 bits */
        de->d_reclen = bytesavail;
        de->d_type = fudge->type; 
        de->d_namlen = fudge->namelen;
        memcpy((char *)cookediov->base + sizeof(struct dirent) - MAXNAMLEN - 1,
               (char *)buf + FUSE_NAME_OFFSET, fudge->namelen);
        ((char *)cookediov->base)[bytesavail] = '\0';

        err = uiomove(cookediov->base, cookediov->len, uio);
        if (err) {
            break;
        }

        buf = (char *)buf + freclen;
        bufsize -= freclen;
        uio_setoffset(uio, fudge->off);
    }

    return (err);
}

/* remove */

#ifdef XXXIP
static int
fuse_unlink_callback(struct vnode *vp, void *cargs)
{
    struct vattr *vap;
    uint64_t target_nlink;

    vap = VTOVA(vp);

    target_nlink = *(uint64_t *)cargs;

    if ((vap->va_nlink == target_nlink) && (vnode_vtype(vp) == VREG)) {
        fuse_invalidate_attr(vp);
    }

    return 0;
}
#endif

#define INVALIDATE_CACHED_VATTRS_UPON_UNLINK 1
int
fuse_internal_remove(struct vnode *dvp,
                     struct vnode *vp,
                     struct componentname *cnp,
                     enum fuse_opcode op)
{
    struct fuse_dispatcher fdi;
    struct vattr *vap = VTOVA(vp);
#if INVALIDATE_CACHED_VATTRS_UPON_UNLINK
    int need_invalidate = 0;
    uint64_t target_nlink = 0;
#endif
    int err = 0;

    debug_printf("dvp=%p, cnp=%p, op=%d\n", vp, cnp, op);

    fdisp_init(&fdi, cnp->cn_namelen + 1);
    fdisp_make_vp(&fdi, op, dvp, curthread, NULL);

    memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
    ((char *)fdi.indata)[cnp->cn_namelen] = '\0';

#if INVALIDATE_CACHED_VATTRS_UPON_UNLINK
    if (vap->va_nlink > 1) {
        need_invalidate = 1;
        target_nlink = vap->va_nlink;
    }
#endif

    if (!(err = fdisp_wait_answ(&fdi))) {
        fuse_ticket_drop(fdi.tick);
    }

    fuse_invalidate_attr(dvp);
    fuse_invalidate_attr(vp);

#if INVALIDATE_CACHED_VATTRS_UPON_UNLINK
#ifdef XXXIP
    if (need_invalidate && !err) {
        vnode_iterate(vnode_mount(vp), 0, fuse_unlink_callback,
                      (void *)&target_nlink);
    }
#endif
#endif

    return (err);
}

/* rename */

int
fuse_internal_rename(struct vnode *fdvp,
                     struct componentname *fcnp,
                     struct vnode *tdvp,
                     struct componentname *tcnp)
{
    struct fuse_dispatcher fdi;
    struct fuse_rename_in *fri;
    int err = 0;

    fdisp_init(&fdi, sizeof(*fri) + fcnp->cn_namelen + tcnp->cn_namelen + 2);
    fdisp_make_vp(&fdi, FUSE_RENAME, fdvp, curthread, NULL);

    fri = fdi.indata;
    fri->newdir = VTOI(tdvp);
    memcpy((char *)fdi.indata + sizeof(*fri), fcnp->cn_nameptr,
           fcnp->cn_namelen);
    ((char *)fdi.indata)[sizeof(*fri) + fcnp->cn_namelen] = '\0';
    memcpy((char *)fdi.indata + sizeof(*fri) + fcnp->cn_namelen + 1,
           tcnp->cn_nameptr, tcnp->cn_namelen);
    ((char *)fdi.indata)[sizeof(*fri) + fcnp->cn_namelen +
                         tcnp->cn_namelen + 1] = '\0';
        
    if (!(err = fdisp_wait_answ(&fdi))) {
        fuse_ticket_drop(fdi.tick);
    }

    fuse_invalidate_attr(fdvp);
    if (tdvp != fdvp) {
        fuse_invalidate_attr(tdvp);
    }

    return (err);
}

/* strategy */

/* entity creation */

void
fuse_internal_newentry_makerequest(struct mount *mp,
                                   uint64_t dnid,
                                   struct componentname *cnp,
                                   enum fuse_opcode op,
                                   void *buf,
                                   size_t bufsize,
                                   struct fuse_dispatcher *fdip)
{
    debug_printf("fdip=%p, context=%p\n", fdip, context);

    fdip->iosize = bufsize + cnp->cn_namelen + 1;

    fdisp_make(fdip, mp, op, dnid, curthread, NULL);
    memcpy(fdip->indata, buf, bufsize);

    memcpy((char *)fdip->indata + bufsize, cnp->cn_nameptr, cnp->cn_namelen);
    ((char *)fdip->indata)[bufsize + cnp->cn_namelen] = '\0';

    fdip->iosize = bufsize + cnp->cn_namelen + 1;
}

int
fuse_internal_newentry_core(struct vnode *dvp,
                            struct vnode **vpp,
                            struct componentname   *cnp,
                            enum vtype vtyp,
                            struct fuse_dispatcher *fdip)
{
    int err = 0;
    struct fuse_entry_out *feo;
    struct mount *mp = vnode_mount(dvp);

    debug_printf("fdip=%p\n", fdip);

    if ((err = fdisp_wait_answ(fdip))) {
        return (err);
    }
        
    feo = fdip->answ;

    if ((err = fuse_internal_checkentry(feo, vtyp))) {
        goto out;
    }

    err = fuse_vnode_get(mp, feo->nodeid, dvp, vpp, cnp,
	vtyp, 0);
    if (err) {
        fuse_internal_forget_send(mp, curthread, NULL, feo->nodeid, 1, fdip);
        return err;
    }

    cache_attrs(*vpp, feo);

out:
    fuse_ticket_drop(fdip->tick);

    return err;
}

int
fuse_internal_newentry(struct vnode *dvp,
                       struct vnode **vpp,
                       struct componentname *cnp,
                       enum fuse_opcode op,
                       void *buf,
		       size_t bufsize,
                       enum vtype vtyp)
{
    int err;
    struct fuse_dispatcher fdi;

    fdisp_init(&fdi, 0);
    fuse_internal_newentry_makerequest(vnode_mount(dvp), VTOI(dvp), cnp,
	                               op, buf, bufsize, &fdi);
    err = fuse_internal_newentry_core(dvp, vpp, cnp, vtyp, &fdi);
    fuse_invalidate_attr(dvp);

    return (err);
}

/* entity destruction */

int
fuse_internal_forget_callback(struct fuse_ticket *tick, struct uio *uio)
{
    struct fuse_dispatcher fdi;

    debug_printf("tick=%p, uio=%p\n", tick, uio);

    fdi.tick = tick;
    fuse_internal_forget_send(tick->tk_data->mp, curthread, NULL,
                     ((struct fuse_in_header *)tick->tk_ms_fiov.base)->nodeid,
                     1, &fdi);

    return 0;
}

void
fuse_internal_forget_send(struct mount *mp,
                          struct thread *td,
                          struct ucred *cred,
                          uint64_t nodeid,
                          uint64_t nlookup,
                          struct fuse_dispatcher *fdip)
{
    struct fuse_forget_in *ffi;

    debug_printf("mp=%p, nodeid=%llx, nlookup=%lld, fdip=%p\n",
                 mp, nodeid, nlookup, fdip);

    /*
     * KASSERT(nlookup > 0, ("zero-times forget for vp #%llu",
     *         (long long unsigned) nodeid));
     */

    fdisp_init(fdip, sizeof(*ffi));
    fdisp_make(fdip, mp, FUSE_FORGET, nodeid, td, cred);

    ffi = fdip->indata;
    ffi->nlookup = nlookup;

    fticket_invalidate(fdip->tick);
    fuse_insert_message(fdip->tick);
}

/* fuse start/stop */

int
fuse_internal_init_callback(struct fuse_ticket *tick, struct uio *uio)
{
    int err = 0;
    struct fuse_data     *data = tick->tk_data;
    struct fuse_init_out *fiio;

    if ((err = tick->tk_aw_ohead.error)) {
        goto out;
    }

    if ((err = fticket_pull(tick, uio))) {
        goto out;
    }

    fiio = fticket_resp(tick)->base;

    /* XXX: Do we want to check anything further besides this? */
    if (fiio->major < 7) {
        debug_printf("userpace version too low\n");
        err = EPROTONOSUPPORT;
        goto out;
    }

    data->fuse_libabi_major = fiio->major;
    data->fuse_libabi_minor = fiio->minor;

    if (fuse_libabi_geq(data, 7, 5)) {
        if (fticket_resp(tick)->len == sizeof(struct fuse_init_out)) {
            data->max_write = fiio->max_write;
        } else {
            err = EINVAL;
        }
    } else {
        /* Old fix values */
        data->max_write = 4096;
    }

out:
    fuse_ticket_drop(tick);

    if (err) {
        fdata_kick_set(data);
    }

    mtx_lock(&data->ticket_mtx);
    data->dataflag |= FSESS_INITED;
    wakeup(&data->ticketer);
    mtx_unlock(&data->ticket_mtx);

    return (0);
}

void
fuse_internal_send_init(struct fuse_data *data, struct thread *td)
{
    struct fuse_init_in   *fiii;
    struct fuse_dispatcher fdi;

    fdisp_init(&fdi, sizeof(*fiii));
    fdisp_make(&fdi, data->mp, FUSE_INIT, 0, td, NULL);
    fiii = fdi.indata;
    fiii->major = FUSE_KERNEL_VERSION;
    fiii->minor = FUSE_KERNEL_MINOR_VERSION;
    fiii->max_readahead = FUSE_DEFAULT_IOSIZE * 16;
    fiii->flags = 0;

    fuse_insert_callback(fdi.tick, fuse_internal_init_callback);
    fuse_insert_message(fdi.tick);
}

#ifdef ZERO_PAD_INCOMPLETE_BUFS
static int
isbzero(void *buf, size_t len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        if (((char *)buf)[i])
            return (0);
    }

    return (1);
}
#endif
