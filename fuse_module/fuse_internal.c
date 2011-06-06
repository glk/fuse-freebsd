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
#include "fuse_node.h"
#include "fuse_ipc.h"
#include "fuse_internal.h"

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
	struct fuse_data *data = fusefs_get_data(mp);
	struct fuse_secondary_data *x_fsdat;
	int denied;

	if (data->dataflag & FSESS_DAEMON_CAN_SPY)
		return (0);

	/*
	 * The policy is to forbid a user from using the filesystem,
	 * unless she has it mounted.
	 *
	 * This is primarily to
	 * protect her from the daemon spying on her I/O
	 * operations. Although this is not a concern if the user
	 * is more privileged than the daemon, we consistently
	 * demand the per-user mount, in order to be compatible
	 * with the Linux implementation.
	 *
	 * Secondary mounts let arbitrary number of users mount and
	 * use the filesystem. However, the primary mounter must explicitly
	 * allow secondary mounts. This is again for providing Linux like
	 * defaults.
	 */

	denied = fuse_match_cred(mp->mnt_cred, cred);
	if (! denied)
		goto allow;

	LIST_FOREACH(x_fsdat, &data->slaves_head, slaves_link) {
		denied = fuse_match_cred(x_fsdat->mp->mnt_cred, cred);
		if (! denied)
			goto allow;
	}

	return (EACCES);

allow:
	return (0);
}

/* fsync */

int
fuse_internal_fsync_callback(struct fuse_ticket *tick, struct uio *uio)
{
    if (tick->tk_aw_ohead.error == ENOSYS)
        tick->tk_data->dataflag |=
         fticket_opcode(tick) == FUSE_FSYNC ?
         FSESS_NOFSYNC : FSESS_NOFSYNCDIR;

    fuse_ticket_drop(tick);
    return (0);
}

/* readdir */

int
fuse_internal_readdir_processdata(struct uio *uio,
                                  size_t reqsize,
                                  void *buf,
                                  size_t bufsize,
                                  void *param)
{
    /*
     * The daemon presents us with a virtual geometry when reading dirents.
     * This info is stored in the "off" field of fuse_dirent (which is the
     * struct we can read from her). "off" shows the absolut position of
     * the next entry (by definition). So I might pull 40 actual bytes from
     * the daemon, that might count as 60 by her virtual geometry, and when
     * I translate fuse_dirents to POSIX dirents, I have 20 bytes to pass
     * to the userspace reader.
     *	
     * How to keep these in sync? We don't want to make the general read
     * routine complex (to which here we serve a background, and which
     * naively treats reading by a liner logic). So we artifically inflate
     * dirents: we pad them with as much zeros as we need them to get to
     * next offset (as the deamon declared), and we pass it to the reader
     * thusly (this will work as fuse dirents are bigger than std ones). So
     * we do more IO with the reader than absolutely necessary, but it's
     * hardly a problem as the expensive thing is reading from the daemon,
     * not sending data to the reader.
     *
     * There is no use to change this simple geometry translation scheme
     * 'till we do page caching. [We do now, but it's still fine as is.]
     */
    int err = 0;
    int cou = 0;
    int bytesavail;
    size_t freclen;

    struct dirent      *de;
    struct fuse_dirent *fudge;
    struct fuse_iov    *cookediov = param;
    
    KASSERT(bufsize <= reqsize, ("read more than asked for?"));

    DEBUG2G("starting\n");

    /*
     * Sanity check: if this fails, we would overrun the allocated space
     * upon entering the loop below, so we'd better leave right now.
     * If so, we return -1 to terminate reading.
     */
    if (bufsize < FUSE_NAME_OFFSET) {
        return (-1);
    }

    DEBUG2G("entering loop with bufsize %d\n", (int)bufsize);

    /*
     * Can we avoid infite loops? An infinite loop could occur only if we
     * leave this function with 0 return value, because otherwise we wont't
     * be called again. But both 0 exit points imply that some data has
     * been consumed... because
     *   1) if a turn is not aborted, it consumes positive amount of data
     *   2) the 0 jump-out from within the loop can't occur in the first
     *      turn
     *   3) if we exit 0 after the loop is over, then at least one turn
     *      was completed, otherwise we hed exited above with -1.
     */  

    for (;;) {

        if (bufsize < FUSE_NAME_OFFSET) {
            err = -1;
            break;
        }

        cou++;

        fudge = (struct fuse_dirent *)buf;
        freclen = FUSE_DIRENT_SIZE(fudge);

        DEBUG("bufsize %d, freclen %d\n", (int)bufsize, (int)freclen);

        /*
         * Here is an exit condition: we terminate the whole reading
         * process if a fresh chunk of buffer is already too short to
         * cut out an entry.
         * (It it was not the first turn in the loop, nevermind,
         * return with asking for more)
         */
        if (bufsize < freclen) {
            err = ((cou == 1) ? -1 : 0);
            break;
        }

#if FUSELIB_CONFORM_BIOREAD
        if (isbzero(buf, FUSE_NAME_OFFSET)) {
            err = -1;
            break;
        }
#endif

        /* Sanity checks */

        if (!fudge->namelen || fudge->namelen > MAXNAMLEN) {
            DEBUG2G("bogus namelen %d at turn %d\n",
                    fudge->namelen, cou);
            err = EINVAL;
            break;
        }

        bytesavail = GENERIC_DIRSIZ((struct pseudo_dirent *)&fudge->namelen); 

        /*
         * Exit condition 2: if the pretended amount of input is more
         * than that the userspace wants, then it's time to stop
         * reading.
         */  
        if (bytesavail > uio->uio_resid) {
            DEBUG2G("leaving at %d-th item as we have %d bytes but only %d is asked for\n",
                    cou, bytesavail, uio->uio_resid);
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

        DEBUG("bytesavail %d, fudge->off %llu, fudge->namelen %d, uio->uio_offset %d, name %s\n",
              bytesavail, (unsigned long long)fudge->off, fudge->namelen, (int)uio->uio_offset,
              (char *)cookediov->base + sizeof(struct dirent) - MAXNAMLEN - 1);

        err = uiomove(cookediov->base, cookediov->len, uio);
        if (err) {
            break;
        }

        buf = (char *)buf + freclen;
        bufsize -= freclen;
        uio->uio_offset = fudge->off;
    }

    return (err);
}

/* remove */

int
fuse_internal_remove(struct vnode *dvp,
                     struct vnode *vp,
                     struct componentname *cnp,
                     enum fuse_opcode op)
{
    struct fuse_dispatcher fdi;
    int err = 0;

    debug_printf("dvp=%p, cnp=%p, op=%d, context=%p\n", vp, cnp, op, context);

    fdisp_init(&fdi, cnp->cn_namelen + 1);
    fdisp_make_vp(&fdi, op, dvp, curthread, NULL);

    memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
    ((char *)fdi.indata)[cnp->cn_namelen] = '\0';

    if (!(err = fdisp_wait_answ(&fdi))) {
        fuse_ticket_drop(fdi.tick);
    }

    fuse_invalidate_attr(dvp);
    fuse_invalidate_attr(vp);

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
}

int
fuse_internal_newentry_core(struct vnode *dvp,
                            struct vnode **vpp,
                            enum vtype vtyp,
                            struct fuse_dispatcher *fdip)
{
    int err = 0;
    struct fuse_entry_out *feo;
    struct mount *mp = dvp->v_mount;

    debug_printf("fdip=%p\n", fdip);

    KASSERT(! (mp->mnt_flag & MNT_RDONLY),
            ("request for new entry in a read-only mount"));

    if ((err = fdisp_wait_answ(fdip))) {
        return (err);
    }
        
    feo = fdip->answ;

    if ((err = fuse_internal_checkentry(feo, vtyp))) {
        goto out;
    }

    /*
     * The Linux code doesn't seem to make a fuss about
     * getting a nodeid for a new entry which is  already
     * in use. Therefore we used to do the same.
     * This is not possible with our implementation of
     * atomic create+open; so, even if we could ignore this
     * fuzz here, we don't do, for the sake of consistency.
     */
    err = fuse_vget_i(mp, curthread, feo->nodeid, vtyp, vpp,
                      VG_FORCENEW, VTOI(dvp));

    if (err) {
        DEBUG2G("failed to fetch vnode for nodeid\n");
        fuse_internal_forget_send(mp, curthread, NULL, feo->nodeid, 1, fdip);
        return err;
    }

    VTOFUD(*vpp)->nlookup++;
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
    fuse_internal_newentry_makerequest(dvp->v_mount, VTOI(dvp), cnp,
	                               op, buf, bufsize, &fdi);
    err = fuse_internal_newentry_core(dvp, vpp, vtyp, &fdi);
    fuse_invalidate_attr(dvp);

    return (err);
}

/* entity destruction */

static void
fuse_internal_forget_send_pid(struct mount *mp,
                          pid_t pid,
                          struct ucred *cred,
                          uint64_t nodeid,
                          uint64_t nlookup,
                          struct fuse_dispatcher *fdip)
{
    struct fuse_forget_in *ffi;

    KASSERT(nlookup > 0, ("zero-times forget for vp #%llu",
            (long long unsigned) nodeid));

    DEBUG("sending FORGET with %llu lookups\n", (unsigned long long)nlookup);

    fdisp_init(fdip, sizeof(*ffi));
    fdisp_make_pid(fdip, mp, FUSE_FORGET, nodeid, pid, cred);

    ffi = fdip->indata;
    ffi->nlookup = nlookup;

    fticket_disown(fdip->tick);
    fuse_insert_message(fdip->tick);
}

int
fuse_internal_forget_callback(struct fuse_ticket *tick,
                              struct uio *uio)
{
    struct fuse_dispatcher fdi;
    struct fuse_pidcred *pidcred;

    /*
     * XXX I think I'm right to send a forget regardless of possible
     * errors, but...
     */

    fdi.tick = tick;
    pidcred = tick->tk_aw_handler_parm.base;

    fuse_internal_forget_send_pid(tick->tk_data->mp, pidcred->pid, &pidcred->cred,
               ((struct fuse_in_header *)tick->tk_ms_fiov.base)->nodeid,
               1, &fdi);

    return (0);
}

void
fuse_internal_forget_send(struct mount *mp,
                          struct thread *td,
                          struct ucred *cred,
                          uint64_t nodeid,
                          uint64_t nlookup,
                          struct fuse_dispatcher *fdip)
{
    RECTIFY_TDCR(td, cred);
    return (fuse_internal_forget_send_pid(mp, td->td_proc->p_pid, cred, nodeid,
                                   nlookup, fdip));
}

/* fuse start/stop */

int
fuse_internal_init_callback(struct fuse_ticket *tick, struct uio *uio)
{
    int err = 0;
    struct fuse_data     *data = tick->tk_data;
#if FUSE_KERNELABI_GEQ(7, 5)
    struct fuse_init_out *fiio;
#else
    struct fuse_init_in_out *fiio;
#endif

    if ((err = tick->tk_aw_ohead.error)) {
        goto out;
    }

    if ((err = fticket_pull(tick, uio))) {
        goto out;
    }

    fiio = fticket_resp(tick)->base;

    /* XXX is the following check adequate? */
    if (fiio->major < 7) {
        DEBUG2G("userpace version too low\n");
        err = EPROTONOSUPPORT;
        goto out;
    }

    data->fuse_libabi_major = fiio->major;
    data->fuse_libabi_minor = fiio->minor;

    if (FUSE_KERNELABI_GEQ(7, 5) && fuse_libabi_geq(data, 7, 5)) {
#if FUSE_KERNELABI_GEQ(7, 5)
        if (fticket_resp(tick)->len == sizeof(struct fuse_init_out)) {
            data->max_write = fiio->max_write;
        } else {
            err = EINVAL;
        }
#endif
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
#if FUSE_KERNELABI_GEQ(7, 5)
    struct fuse_init_in   *fiii;
#else
    struct fuse_init_in_out *fiii;
#endif
    struct fuse_dispatcher fdi;

    fdisp_init(&fdi, sizeof(*fiii));
    fdisp_make(&fdi, data->mp, FUSE_INIT, 0, td, NULL);
    fiii = fdi.indata;
    fiii->major = FUSE_KERNEL_VERSION;
    fiii->minor = FUSE_KERNEL_MINOR_VERSION;

    fuse_insert_callback(fdi.tick, fuse_internal_init_callback);
    fuse_insert_message(fdi.tick);
}
