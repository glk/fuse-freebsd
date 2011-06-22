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

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vnode_pager.h>
#include <vm/vm_object.h>

#include "fuse.h"
#include "fuse_file.h"
#include "fuse_internal.h"
#include "fuse_ipc.h"
#include "fuse_node.h"
#include "fuse_io.h"

#include <sys/priv.h>

#define FUSE_DEBUG_MODULE VNOPS
#include "fuse_debug.h"

/* vnode ops */
static vop_access_t   fuse_vnop_access;
static vop_close_t    fuse_vnop_close;
static vop_create_t   fuse_vnop_create;
static vop_fsync_t    fuse_vnop_fsync;
static vop_getattr_t  fuse_vnop_getattr;
static vop_inactive_t fuse_vnop_inactive;
static vop_link_t     fuse_vnop_link;
static vop_lookup_t   fuse_vnop_lookup;
static vop_mkdir_t    fuse_vnop_mkdir;
static vop_mknod_t    fuse_vnop_mknod;
static vop_open_t     fuse_vnop_open;
static vop_read_t     fuse_vnop_read;
static vop_readdir_t  fuse_vnop_readdir;
static vop_readlink_t fuse_vnop_readlink;
static vop_reclaim_t  fuse_vnop_reclaim;
static vop_remove_t   fuse_vnop_remove;
static vop_rename_t   fuse_vnop_rename;
static vop_rmdir_t    fuse_vnop_rmdir;
static vop_setattr_t  fuse_vnop_setattr;
static vop_strategy_t fuse_vnop_strategy;
static vop_symlink_t  fuse_vnop_symlink;
static vop_write_t    fuse_vnop_write;
static vop_getpages_t fuse_vnop_getpages;
static vop_putpages_t fuse_vnop_putpages;
static vop_print_t    fuse_vnop_print;
static vop_unlock_t   fuse_vnop_unlock;

struct vop_vector fuse_vnops = {
	.vop_default       = &default_vnodeops,
	.vop_access        = fuse_vnop_access,
	.vop_close         = fuse_vnop_close,
	.vop_create        = fuse_vnop_create,
	.vop_fsync         = fuse_vnop_fsync,
	.vop_getattr       = fuse_vnop_getattr,
	.vop_inactive      = fuse_vnop_inactive,
	.vop_link          = fuse_vnop_link,
	.vop_lookup        = fuse_vnop_lookup,
	.vop_mkdir         = fuse_vnop_mkdir,
	.vop_mknod         = fuse_vnop_mknod,
	.vop_open          = fuse_vnop_open,
	.vop_pathconf      = vop_stdpathconf,
	.vop_read          = fuse_vnop_read,
	.vop_readdir       = fuse_vnop_readdir,
	.vop_readlink      = fuse_vnop_readlink,
	.vop_reclaim       = fuse_vnop_reclaim,
	.vop_remove        = fuse_vnop_remove,
	.vop_rename        = fuse_vnop_rename,
	.vop_rmdir         = fuse_vnop_rmdir,
	.vop_setattr       = fuse_vnop_setattr,
	.vop_strategy      = fuse_vnop_strategy,
	.vop_symlink       = fuse_vnop_symlink,
	.vop_write         = fuse_vnop_write,
	.vop_getpages      = fuse_vnop_getpages,
	.vop_putpages      = fuse_vnop_putpages,
	.vop_print         = fuse_vnop_print,
	.vop_unlock        = fuse_vnop_unlock,
};

static uint64_t fuse_lookup_cache_hits = 0;
SYSCTL_QUAD(_vfs_fuse, OID_AUTO, lookup_cache_hits, CTLFLAG_RD,
            &fuse_lookup_cache_hits, 0, "");

static uint64_t fuse_lookup_cache_misses  = 0;
SYSCTL_QUAD(_vfs_fuse, OID_AUTO, lookup_cache_misses, CTLFLAG_RD,
            &fuse_lookup_cache_misses, 0, "");

int fuse_pbuf_freecnt = -1;

/*
    struct vnop_access_args {
        struct vnode *a_vp;
#if VOP_ACCESS_TAKES_ACCMODE_T
        accmode_t a_accmode;
#else
        int a_mode;
#endif
        struct ucred *a_cred;
        struct thread *a_td;
    };
*/
static int
fuse_vnop_access(struct vop_access_args *ap)
{
    struct vnode *vp      = ap->a_vp;
    int           accmode = ap->a_accmode;

    struct fuse_access_param facp;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        if (vnode_isvroot(vp)) {
            return 0;
        }
        return EBADF;
    }

    if (vnode_islnk(vp)) {
        return 0;
    }

    bzero(&facp, sizeof(facp));

    if (fvdat->flags & FVP_ACCESS_NOOP) {
        fvdat->flags &= ~FVP_ACCESS_NOOP;
    } else {
        facp.facc_flags |= FACCESS_DO_ACCESS;
    }   

    return fuse_internal_access(vp, accmode, &facp, ap->a_td, ap->a_cred);
}

/*
    struct vnop_close_args {
	struct vnode *a_vp;
	int  a_fflag;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_close(struct vop_close_args *ap)
{
    struct vnode *vp      = ap->a_vp;
    int           fflag   = ap->a_fflag;
    int isdir = (vnode_isdir(vp)) ? 1 : 0;
    fufh_type_t fufh_type;

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh = NULL;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        return 0;
    }

    if (isdir) {
        fufh_type = FUFH_RDONLY;
    } else {
        fufh_type = fuse_filehandle_xlate_from_fflags(fflag);
    }

    fufh = &(fvdat->fufh[fufh_type]);

    if (!(fufh->fufh_flags & FUFH_VALID)) {
        panic("fufh type %d found to be invalid in close\n", fufh_type);
    }

    fufh->open_count--;

    if ((fufh->open_count == 0) && !(fufh->fufh_flags & FUFH_MAPPED)) {
        (void)fuse_filehandle_put(vp, NULL, NULL, fufh_type, 0);
    }

    return 0;
}

/*
    struct vnop_create_args {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
    };
*/
static int
fuse_vnop_create(struct vop_create_args *ap)
{
    struct vnode         *dvp     = ap->a_dvp;
    struct vnode        **vpp     = ap->a_vpp;
    struct componentname *cnp     = ap->a_cnp;
    struct vattr         *vap     = ap->a_vap;
    struct thread        *td      = cnp->cn_thread;
    struct ucred         *cred    = cnp->cn_cred;

    struct fuse_open_in    *foi;
    struct fuse_mknod_in    fmni;
    struct fuse_entry_out  *feo;
    struct fuse_dispatcher  fdi;
    struct fuse_dispatcher *fdip = &fdi;

    int err;
    int gone_good_old = 0;

    struct mount *mp = vnode_mount(dvp);
    uint64_t parentnid = VTOFUD(dvp)->nid;
    mode_t mode = MAKEIMODE(vap->va_type, vap->va_mode);

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(dvp)) {
        panic("FUSE: fuse_vnop_create(): called on a dead file system");
    }

    bzero(&fdi, sizeof(fdi));

    // XXX: Will we ever want devices?
    if ((vap->va_type != VREG) ||
        fusefs_get_data(mp)->dataflags & FSESS_NOCREATE) {
        goto good_old;
    }

    debug_printf("parent nid = %ju, mode = %x\n", (uintmax_t)parentnid, mode);

    fdisp_init(fdip, sizeof(*foi) + cnp->cn_namelen + 1);
    if (fusefs_get_data(vnode_mount(dvp))->dataflags & FSESS_NOCREATE) {
        debug_printf("eh, daemon doesn't implement create?\n");
        goto good_old;
    }

    fdisp_make(fdip, FUSE_CREATE, vnode_mount(dvp), parentnid, td, cred);

    foi = fdip->indata;
    foi->mode = mode;
    foi->flags = O_CREAT | O_RDWR;

    memcpy((char *)fdip->indata + sizeof(*foi), cnp->cn_nameptr,
           cnp->cn_namelen);
    ((char *)fdip->indata)[sizeof(*foi) + cnp->cn_namelen] = '\0';

    err = fdisp_wait_answ(fdip);

    if (err == ENOSYS) {
        debug_printf("create: got ENOSYS from daemon\n");
        fusefs_get_data(vnode_mount(dvp))->dataflags |= FSESS_NOCREATE;
        fdip->tick = NULL;
        goto good_old;
    } else if (err) {
        debug_printf("create: darn, got err=%d from daemon\n", err);
        goto undo;
    }

    goto bringup;

good_old:
    gone_good_old = 1;
    fmni.mode = mode; /* fvdat->flags; */
    fmni.rdev = 0;
    fuse_internal_newentry_makerequest(vnode_mount(dvp), parentnid, cnp,
                                       FUSE_MKNOD, &fmni, sizeof(fmni),
                                       fdip);
    err = fdisp_wait_answ(fdip);
    if (err) {
        goto undo;
    }

bringup:
    feo = fdip->answ;

    if ((err = fuse_internal_checkentry(feo, VREG))) {
        fuse_ticket_drop(fdip->tick);
        goto undo;
    }

    err = fuse_vnode_get(mp, feo->nodeid, dvp, vpp, cnp, VREG, /*size*/0);
    if (!err && !gone_good_old) {
        VTOFUD(*vpp)->flag |= FN_CREATING;
    }
    if (err) {
       if (gone_good_old) {
           fuse_internal_forget_send(mp, td, cred, feo->nodeid, 1, fdip);
       } else {
           struct fuse_release_in *fri;
           uint64_t nodeid = feo->nodeid;
           uint64_t fh_id = ((struct fuse_open_out *)(feo + 1))->fh;

           fdisp_init(fdip, sizeof(*fri));
           fdisp_make(fdip, FUSE_RELEASE, mp, nodeid, td, cred);
           fri = fdip->indata;
           fri->fh = fh_id;
           fri->flags = OFLAGS(mode);
           fuse_insert_callback(fdip->tick, fuse_internal_forget_callback);
           fuse_insert_message(fdip->tick);
       }
       return err;
    }

    fdip->answ = gone_good_old ? NULL : feo + 1;

    if (!gone_good_old) {

        uint64_t x_fh_id = ((struct fuse_open_out *)(feo + 1))->fh;
        uint32_t x_open_flags = ((struct fuse_open_out *)(feo + 1))->open_flags;
        struct fuse_vnode_data *fvdat = VTOFUD(*vpp);
        struct fuse_filehandle *fufh = &(fvdat->fufh[FUFH_RDWR]);

        fufh->fh_id = x_fh_id;
        fufh->open_flags = x_open_flags;

#if 0
        struct fuse_dispatcher x_fdi;
        struct fuse_release_in *x_fri;
        fdisp_init(&x_fdi, sizeof(*x_fri));
        fdisp_make_vp(&x_fdi, FUSE_RELEASE, *vpp, context);
        x_fri = x_fdi.indata;
        x_fri->fh = x_fh_id;
        x_fri->flags = O_WRONLY;
        fuse_insert_callback(x_fdi.tick, NULL);
        fuse_insert_message(x_fdi.tick);
#endif
    }

    return 0;

undo:
    return err;
}

/*
 * Our vnop_fsync roughly corresponds to the FUSE_FSYNC method. The Linux
 * version of FUSE also has a FUSE_FLUSH method.
 *
 * On Linux, fsync() synchronizes a file's complete in-core state with that
 * on disk. The call is not supposed to return until the system has completed 
 * that action or until an error is detected.
 *
 * Linux also has an fdatasync() call that is similar to fsync() but is not
 * required to update the metadata such as access time and modification time.
 */

/*
    struct vnop_fsync_args {
	struct vnodeop_desc *a_desc;
	struct vnode * a_vp;
	struct ucred * a_cred;
	int  a_waitfor;
	struct thread * a_td;
    };
*/
static int
fuse_vnop_fsync(struct vop_fsync_args *ap)
{
    struct vnode *vp      = ap->a_vp;
    struct thread *td     = ap->a_td;

    struct fuse_dispatcher fdi;
    struct fuse_filehandle *fufh;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    int type, err = 0;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        return 0;
    }

    if ((err = vop_stdfsync(ap)))
        return err;

    if (!(fusefs_get_data(vnode_mount(vp))->dataflags &
        (vnode_vtype(vp) == VDIR ? FSESS_NOFSYNCDIR : FSESS_NOFSYNC))) {
        goto out;
    }

    fdisp_init(&fdi, 0);
    for (type = 0; type < FUFH_MAXTYPE; type++) {
        fufh = &(fvdat->fufh[type]);
        if (fufh->fufh_flags & FUFH_VALID) {
            fuse_internal_fsync(vp, td, NULL, fufh, &fdi);
        }
    }

out:
    return 0;
}

/*
    struct vnop_getattr_args {
	struct vnode *a_vp;
	struct vattr *a_vap;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_getattr(struct vop_getattr_args *ap)
{
    struct vnode      *vp      = ap->a_vp;
    struct vattr      *vap     = ap->a_vap;
    struct ucred      *cred    = ap->a_cred;
    struct thread     *td      = curthread;

    int err = 0;
    int dataflags;
    struct timespec uptsp;
    struct fuse_dispatcher fdi;

    fuse_trace_printf_vnop();

    dataflags = fusefs_get_data(vnode_mount(vp))->dataflags;

    /* Note that we are not bailing out on a dead file system just yet. */

    /* look for cached attributes */
    nanouptime(&uptsp);
    if (fuse_timespec_cmp(&uptsp, &VTOFUD(vp)->cached_attrs_valid, <=)) {
        if (vap != VTOVA(vp)) {
            memcpy(vap, VTOVA(vp), sizeof(*vap));
        }
        debug_printf("fuse_getattr a: returning 0\n");
        return 0;
    }

    if (!(dataflags & FSESS_INITED)) {
        if (!vnode_isvroot(vp)) {
            fdata_kick_set(fusefs_get_data(vnode_mount(vp)));
            err = ENOTCONN;
            debug_printf("fuse_getattr b: returning ENOTCONN\n");
            return err;
        } else {
            goto fake;
        }
    }

    if ((err = fdisp_simple_putget_vp(&fdi, FUSE_GETATTR, vp, td, cred))) {
        if ((err == ENOTCONN) && vnode_isvroot(vp)) {
            /* see comment at similar place in fuse_statfs() */
            goto fake;
        }
        debug_printf("fuse_getattr c: returning ENOTCONN\n");
        return err;
    }

    cache_attrs(vp, (struct fuse_attr_out *)fdi.answ);
    if (vap != VTOVA(vp)) {
        memcpy(vap, VTOVA(vp), sizeof(*vap));
    }

    if (vnode_isreg(vp)) {
        /*
         * This is for those cases when the file size changed without us
         * knowing, and we want to catch up.
         */
        struct fuse_vnode_data *fvdat = VTOFUD(vp);
        off_t new_filesize = ((struct fuse_attr_out *)fdi.answ)->attr.size;

        if (fvdat->filesize != new_filesize) {
            fvdat->filesize = new_filesize;
            vnode_pager_setsize(vp, new_filesize);
        }
    }

    fuse_ticket_drop(fdi.tick);

    if (vnode_vtype(vp) != vap->va_type) {
        if ((vnode_vtype(vp) == VNON) && (vap->va_type != VNON)) {
            /*
             * We should be doing the following:
             *
             * vp->vtype = vap->v_type
             */
        } else {
            /* stale vnode */
            // XXX: vnode should be ditched.
            debug_printf("fuse_getattr d: returning ENOTCONN\n");
            return ENOTCONN;
        }
    }

    debug_printf("fuse_getattr e: returning 0\n");

    return 0;

fake:
    bzero(vap, sizeof(*vap));
    vap->va_type = vnode_vtype(vp);

    return 0;
}

/*
    struct vnop_inactive_args {
	struct vnode *a_vp;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_inactive(struct vop_inactive_args *ap)
{
    struct vnode *vp      = ap->a_vp;
    struct thread *td     = ap->a_td;

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh = NULL;

    int type;

    fuse_trace_printf_vnop();

    for (type = 0; type < FUFH_MAXTYPE; type++) {
        fufh = &(fvdat->fufh[type]);
        if (fufh->fufh_flags & FUFH_VALID) {
            fufh->fufh_flags &= ~FUFH_MAPPED;
            fufh->open_count = 0;
            (void)fuse_filehandle_put(vp, td, NULL, type, 0);
        }
    }

    return 0;
}

/*
    struct vnop_link_args {
	struct vnode *a_tdvp;
	struct vnode *a_vp;
	struct componentname *a_cnp;
    };
*/
static int
fuse_vnop_link(struct vop_link_args *ap)
{
    struct vnode         *vp      = ap->a_vp;
    struct vnode         *tdvp    = ap->a_tdvp;
    struct componentname *cnp     = ap->a_cnp;

    struct fuse_dispatcher fdi;
    struct fuse_entry_out *feo;
    struct fuse_link_in    fli;

    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        panic("fuse_vnop_link(): called on a dead file system");
    }

    if (vnode_mount(tdvp) != vnode_mount(vp)) {
        return EXDEV;
    }

    fli.oldnodeid = VTOI(vp);

    fdisp_init(&fdi, 0);
    fuse_internal_newentry_makerequest(vnode_mount(tdvp), VTOI(tdvp), cnp,
                                       FUSE_LINK, &fli, sizeof(fli), &fdi);
    if ((err = fdisp_wait_answ(&fdi))) {
        return err;
    }

    feo = fdi.answ;

    err = fuse_internal_checkentry(feo, vnode_vtype(vp));
    fuse_ticket_drop(fdi.tick);
    fuse_invalidate_attr(tdvp);
    fuse_invalidate_attr(vp);

    if (err == 0) {
        VTOFUD(vp)->nlookup++;
    }

    return err;
}

/*
    struct vnop_lookup_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
    };
*/
int
fuse_vnop_lookup(struct vop_lookup_args *ap)
{
    struct vnode *dvp         = ap->a_dvp;
    struct vnode **vpp        = ap->a_vpp;
    struct componentname *cnp = ap->a_cnp;
    struct thread *td         = cnp->cn_thread;
    struct ucred *cred        = cnp->cn_cred;

    int nameiop               = cnp->cn_nameiop;
    int flags                 = cnp->cn_flags;
    int wantparent            = flags & (LOCKPARENT|WANTPARENT);
    int islastcn              = flags & ISLASTCN;
    struct mount *mp          = vnode_mount(dvp);

    int err                   = 0;
    int lookup_err            = 0;
    struct vnode *vp          = NULL;
    uint64_t size             = 0;

    struct fuse_dispatcher fdi;
    enum   fuse_opcode     op;

    uint64_t nid;
    struct fuse_access_param facp;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(dvp)) {
        *vpp = NULL;
        return ENXIO;
    }

    if (!vnode_isdir(dvp)) {
        return ENOTDIR;
    }

    if (islastcn && vfs_isrdonly(mp) && (nameiop != LOOKUP)) {
        return EROFS;
    }

    /*
     * We do access check prior to doing anything else only in the case
     * when we are at fs root (we'd like to say, "we are at the first
     * component", but that's not exactly the same... nevermind).
     * See further comments at further access checks.
     */

    bzero(&facp, sizeof(facp));
    if (vnode_isvroot(dvp)) { /* early permission check hack */
        if ((err = fuse_internal_access(dvp, VEXEC, &facp, td, cred))) {
            return err;
        }
    }

    if (flags & ISDOTDOT) {
        nid = VTOFUD(dvp)->parent_nid;
        if (nid == 0) {
            return ENOENT;
        }
        fdisp_init(&fdi, 0);
        op = FUSE_GETATTR;
        goto calldaemon;
    } else if (cnp->cn_namelen == 1 && *(cnp->cn_nameptr) == '.') {
        nid = VTOI(dvp);
        fdisp_init(&fdi, 0);
        op = FUSE_GETATTR;
        goto calldaemon;
    } else {
        err = cache_lookup(dvp, vpp, cnp);
        switch (err) {

        case -1: /* positive match */
            fuse_lookup_cache_hits++;
            return 0;

        case 0: /* no match in cache */
            fuse_lookup_cache_misses++;
            break;

        case ENOENT: /* negative match */
             /* fall through */
        default:
             return err;
        }
    }

    nid = VTOI(dvp);
    fdisp_init(&fdi, cnp->cn_namelen + 1);
    op = FUSE_LOOKUP;

calldaemon:
    fdisp_make(&fdi, op, mp, nid, td, cred);

    if (op == FUSE_LOOKUP) {
        memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
        ((char *)fdi.indata)[cnp->cn_namelen] = '\0';
    }

    lookup_err = fdisp_wait_answ(&fdi);

    if ((op == FUSE_LOOKUP) && !lookup_err) { /* lookup call succeeded */
        nid = ((struct fuse_entry_out *)fdi.answ)->nodeid;
        size = ((struct fuse_entry_out *)fdi.answ)->attr.size;
        if (!nid) {
            /*
             * zero nodeid is the same as "not found",
             * but it's also cacheable (which we keep
             * keep on doing not as of writing this)
             */
            lookup_err = ENOENT;
        } else if (nid == FUSE_ROOT_ID) {
            lookup_err = EINVAL;
        }
    }

    if (lookup_err &&
        (!fdi.answ_stat || lookup_err != ENOENT || op != FUSE_LOOKUP)) {
        return lookup_err;
    }

    /* lookup_err, if non-zero, must be ENOENT at this point */

    if (lookup_err) {

        if ((nameiop == CREATE || nameiop == RENAME) && islastcn
            /* && directory dvp has not been removed */) {

            if (vfs_isrdonly(mp)) {
                err = EROFS;
                goto out;
            }

#if 0 // THINK_ABOUT_THIS
            if ((err = fuse_internal_access(dvp, VWRITE, cred, td, &facp))) {
                goto out;
            }
#endif

            /*
             * Possibly record the position of a slot in the
             * directory large enough for the new component name.
             * This can be recorded in the vnode private data for
             * dvp. Set the SAVENAME flag to hold onto the
             * pathname for use later in VOP_CREATE or VOP_RENAME.
             */
            cnp->cn_flags |= SAVENAME;

            err = EJUSTRETURN;
            goto out;
        }

        /* Consider inserting name into cache. */

        /*
         * No we can't use negative caching, as the fs
         * changes are out of our control.
         * False positives' falseness turns out just as things
         * go by, but false negatives' falseness doesn't.
         * (and aiding the caching mechanism with extra control
         * mechanisms comes quite close to beating the whole purpose
         * caching...)
         */
#if 0
        if ((cnp->cn_flags & MAKEENTRY) && nameiop != CREATE) {
            DEBUG("inserting NULL into cache\n");
            cache_enter(dvp, NULL, cnp);
        }
#endif
        err = ENOENT;
        goto out;

    } else {

        /* !lookup_err */

        struct fuse_entry_out *feo   = NULL;
        struct fuse_attr      *fattr = NULL;

        if (op == FUSE_GETATTR) {
            fattr = &((struct fuse_attr_out *)fdi.answ)->attr;
        } else {
            feo = (struct fuse_entry_out *)fdi.answ;
            fattr = &(feo->attr);
        }

        /*
         * If deleting, and at end of pathname, return parameters
         * which can be used to remove file.  If the wantparent flag
         * isn't set, we return only the directory, otherwise we go on
         * and lock the inode, being careful with ".".
         */
        if (nameiop == DELETE && islastcn) {
            /*
             * Check for write access on directory.
             */
            facp.xuid = fattr->uid;
            facp.facc_flags |= FACCESS_STICKY;
            err = fuse_internal_access(dvp, VWRITE, &facp, td, cred);
            facp.facc_flags &= ~FACCESS_XQUERIES;

            if (err) {
                goto out;
            }

            if (nid == VTOI(dvp)) {
                vref(dvp);
                *vpp = dvp;
                goto out;
            }

            err = fuse_vnode_get(dvp->v_mount,
                                 nid,
                                 dvp,
                                 &vp,
                                 cnp,
                                 IFTOVT(fattr->mode),
                                 size);
            if (err) {
                goto out;
            }

            *vpp = vp;
        
            goto out;

        }

        /*
         * If rewriting (RENAME), return the inode and the
         * information required to rewrite the present directory
         * Must get inode of directory entry to verify it's a
         * regular file, or empty directory.
         */
        if (nameiop == RENAME && wantparent && islastcn) {

#if 0 // THINK_ABOUT_THIS
            if ((err = fuse_internal_access(dvp, VWRITE, cred, td, &facp))) {
                goto out;
            }
#endif

            /*
             * Check for "."
             */
            if (nid == VTOI(dvp)) {
                err = EISDIR;
                goto out;
            }

            err = fuse_vnode_get(vnode_mount(dvp),
                                 nid,
                                 dvp,
                                 &vp,
                                 cnp,
                                 IFTOVT(fattr->mode),
                                 size);
            if (err) {
                goto out;
            }

            *vpp = vp;
            /*
             * Save the name for use in VOP_RENAME later.
             */
            cnp->cn_flags |= SAVENAME;

            goto out;
        }

        if (flags & ISDOTDOT) {
            int ltype;

            ltype = VOP_ISLOCKED(dvp);
            VOP_UNLOCK(dvp, 0);
            err = fuse_vnode_get(vnode_mount(dvp),
                                 nid,
                                 NULL,
                                 &vp,
                                 cnp,
                                 IFTOVT(fattr->mode),
                                 0);
            vn_lock(dvp, ltype | LK_RETRY);
            vref(vp);
            *vpp = vp;
        } else if (nid == VTOI(dvp)) {
            vref(dvp);
            *vpp = dvp;
        } else {
            err = fuse_vnode_get(vnode_mount(dvp),
                                 nid,
                                 dvp,
                                 &vp,
                                 cnp,
                                 IFTOVT(fattr->mode),
                                 size);
            if (err) {
                goto out;
            }
            if (vnode_vtype(vp) == VDIR) {
                VTOFUD(vp)->parent_nid = VTOI(dvp);
                //SETPARENT(vp, dvp);
            }
            *vpp = vp;
        }

        if (op == FUSE_GETATTR) {
            cache_attrs(*vpp, (struct fuse_attr_out *)fdi.answ);
        } else {
            cache_attrs(*vpp, (struct fuse_entry_out *)fdi.answ);
        }

        /* Insert name into cache if appropriate. */

        /*
         * Nooo, caching is evil. With caching, we can't avoid stale
         * information taking over the playground (cached info is not
         * just positive/negative, it does have qualitative aspects,
         * too). And a (VOP/FUSE)_GETATTR is always thrown anyway, when
         * walking down along cached path components, and that's not
         * any cheaper than FUSE_LOOKUP. This might change with
         * implementing kernel side attr caching, but... In Linux,
         * lookup results are not cached, and the daemon is bombarded
         * with FUSE_LOOKUPS on and on. This shows that by design, the
         * daemon is expected to handle frequent lookup queries
         * efficiently, do its caching in userspace, and so on.
         *
         * So just leave the name cache alone.
         */

        /*
         * Well, now I know, Linux caches lookups, but with a
         * timeout... So it's the same thing as attribute caching:
         * we can deal with it when implement timeouts.
         */    
#if 0
        if (cnp->cn_flags & MAKEENTRY) {
            cache_enter(dvp, *vpp, cnp);
        }
#endif
    }
out:
    if (!lookup_err) {

        /* No lookup error; need to clean up. */

        if (err) { /* Found inode; exit with no vnode. */
            if (op == FUSE_LOOKUP) {
                fuse_internal_forget_send(vnode_mount(dvp), td, cred,
                                          nid, 1, &fdi);
            }
            return err;
        } else {
#ifndef NO_EARLY_PERM_CHECK_HACK
            if (!islastcn) {
                /* We have the attributes of the next item
                 * *now*, and it's a fact, and we do not have
                 * to do extra work for it (ie, beg the
                 * daemon), and it neither depends on such
                 * accidental things like attr caching. So the
                 * big idea: check credentials *now*, not at
                 * the beginning of the next call to lookup.
                 *
                 * The first item of the lookup chain (fs root)
                 * won't be checked then here, of course, as
                 * its never "the next". But go and see that
                 * the root is taken care about at the very
                 * beginning of this function.
                 *
                 * Now, given we want to do the access check
                 * this way, one might ask: so then why not do
                 * the access check just after fetching the
                 * inode and its attributes from the daemon?
                 * Why bother with producing the corresponding
                 * vnode at all if something is not OK? We know
                 * what's the deal as soon as we get those
                 * attrs... There is one bit of info though not
                 * given us by the daemon: whether his response
                 * is authorative or not... His response should
                 * be ignored if something is mounted over the
                 * dir in question. But that can be known only
                 * by having the vnode...
                 */
                int tmpvtype = vnode_vtype(*vpp);

                bzero(&facp, sizeof(facp));
                // the early perm check hack
                facp.facc_flags |= FACCESS_VA_VALID;

                if ((tmpvtype != VDIR) && (tmpvtype != VLNK)) {
                    err = ENOTDIR;
                }

                if (!err && !vnode_mountedhere(*vpp)) {
                    err = fuse_internal_access(*vpp, VEXEC, &facp, td, cred);
                }

                if (err) {
                    if (tmpvtype == VLNK)
                        DEBUG("weird, permission error with a symlink?\n");
                    vput(*vpp);
                    *vpp = NULL;
                }
            }
#endif
        }
            
        fuse_ticket_drop(fdi.tick);
    }

    return err;
}

/*
    struct vnop_mkdir_args {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
    };
*/
static int
fuse_vnop_mkdir(struct vop_mkdir_args *ap)
{
    struct vnode         *dvp     = ap->a_dvp;
    struct vnode        **vpp     = ap->a_vpp;
    struct componentname *cnp     = ap->a_cnp;
    struct vattr         *vap     = ap->a_vap;

    int err = 0;

    struct fuse_mkdir_in fmdi;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(dvp)) {
        panic("FUSE: fuse_vnop_mkdir(): called on a dead file system");
    }

    fmdi.mode = MAKEIMODE(vap->va_type, vap->va_mode);

    err = fuse_internal_newentry(dvp, vpp, cnp, FUSE_MKDIR, &fmdi,
                                 sizeof(fmdi), VDIR);

    return err;
}

/*
    struct vnop_mknod_args {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
    };
*/
static int
fuse_vnop_mknod(struct vop_mknod_args *ap)
{
    struct vnode         *dvp     = ap->a_dvp;
    struct vnode        **vpp     = ap->a_vpp;
    struct componentname *cnp     = ap->a_cnp;
    struct vattr         *vap     = ap->a_vap;

    struct fuse_mknod_in fmni;

    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(dvp)) {
        panic("fuse_vnop_mknod(): called on a dead file system");
    }

    fmni.mode = MAKEIMODE(vap->va_type, vap->va_mode);
    fmni.rdev = vap->va_rdev;

    err = fuse_internal_newentry(dvp, vpp, cnp, FUSE_MKNOD, &fmni,
                                 sizeof(fmni), vap->va_type);

    return err;
}


/*
    struct vnop_open_args {
	struct vnode *a_vp;
	int  a_mode;
	struct ucred *a_cred;
	struct thread *a_td;
	int a_fdidx; / struct file *a_fp;
    };
*/
static int
fuse_vnop_open(struct vop_open_args *ap)
{
    struct vnode *vp      = ap->a_vp;
    int           mode    = ap->a_mode;
    struct thread *td     = ap->a_td;
    struct ucred *cred    = ap->a_cred;

    fufh_type_t             fufh_type;
    struct fuse_vnode_data *fvdat;
    struct fuse_filehandle *fufh = NULL;
    struct fuse_filehandle *fufh_rw = NULL;

    int error, isdir = 0, oflags;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    fvdat = VTOFUD(vp);

    if (vnode_isdir(vp)) {
        isdir = 1;
    }

    if (isdir) {
        fufh_type = FUFH_RDONLY;
    } else {
        fufh_type = fuse_filehandle_xlate_from_fflags(mode);
    }

    oflags = fuse_filehandle_xlate_to_oflags(fufh_type);

    fufh = &(fvdat->fufh[fufh_type]);

    if (!isdir && (fvdat->flag & FN_CREATING)) {

        mtx_lock(&fvdat->createlock);

        if (fvdat->flag & FN_CREATING) { // check again
            if (fvdat->creator == curthread->td_tid) {

                /*
                 * For testing the race condition we want to prevent here,
                 * try something like the following:
                 *
                 *     int dummyctr = 0;
                 *
                 *     for (; dummyctr < 2048000000; dummyctr++);
                 */

                fufh_rw = &(fvdat->fufh[FUFH_RDWR]);

                fufh->fufh_flags |= FUFH_VALID;
                fufh->fufh_flags &= ~FUFH_MAPPED;
                fufh->open_count = 1;
                fufh->open_flags = oflags;
                fufh->type = fufh_type;

                fufh->fh_id = fufh_rw->fh_id;
                fufh->open_flags = fufh_rw->open_flags;
                debug_printf("creator picked up stashed handle, moved to %d\n",
                             fufh_type);
                
                fvdat->flag &= ~FN_CREATING;

                mtx_unlock(&fvdat->createlock);
                wakeup((caddr_t)&fvdat->creator); // wake up all
                goto ok; /* return 0 */
            } else {
                debug_printf("contender going to sleep\n");
                error = msleep(&fvdat->creator, &fvdat->createlock,
                               PDROP | PINOD | PCATCH, "fuse_open", 0);
                /*
                 * msleep will drop the mutex. since we have PDROP specified,
                 * it will NOT regrab the mutex when it returns.
                 */
                debug_printf("contender awake (error = %d)\n", error);

                if (error) {
                    /*
                     * Since we specified PCATCH above, we'll be woken up in
                     * case a signal arrives. The value of error could be
                     * EINTR or ERESTART.
                     */
                    return error;
                }
            }
        } else {
            mtx_unlock(&fvdat->createlock);
            /* Can proceed from here. */
        }
    }

    if (fufh->fufh_flags & FUFH_VALID) {
        fufh->open_count++;
        goto ok; /* return 0 */
    }

    error = fuse_filehandle_get(vp, td, cred, fufh_type);
    if (error) {
        return error;
    }

ok:
    if (vnode_vtype(vp) == VREG) {
        /* XXXIP prevent getattr, by using cached node size */
        vnode_create_vobject(vp, 0, td);
    }

    /*
     * Doing this here because when a vnode goes inactive, things like
     * no-cache and no-readahead are cleared by the kernel.
     */

    {
#ifdef XXXIP
        int dataflags = fusefs_get_data(vnode_mount(vp))->dataflags;
        if (dataflags & FSESS_NO_READAHEAD) {
            vnode_setnoreadahead(vp);
        }
        if (dataflags & FSESS_NO_UBC) {
            vnode_setnocache(vp);
        }
#endif
    }

    return 0;
}

/*
    struct vnop_read_args {
	struct vnode *a_vp;
	struct uio *a_uio;
	int  a_ioflag;
	struct ucred *a_cred;
    };
*/
static int
fuse_vnop_read(struct vop_read_args *ap)
{
    struct vnode *vp      = ap->a_vp;
    struct uio   *uio     = ap->a_uio;
    int           ioflag  = ap->a_ioflag;
    struct ucred *cred    = ap->a_cred;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        return EIO;
    }

    return fuse_io_vnode(vp, uio, ioflag, cred);
}

/*
    struct vnop_readdir_args {
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
	int *a_eofflag;
	int *ncookies;
	u_long **a_cookies;
    };
*/
static int
fuse_vnop_readdir(struct vop_readdir_args *ap)
{
    struct vnode  *vp           = ap->a_vp;
    struct uio   *uio           = ap->a_uio;
    struct ucred *cred          = ap->a_cred;

    struct fuse_filehandle *fufh = NULL;
    struct fuse_vnode_data *fvdat;
    struct fuse_iov         cookediov;

    int err = 0;
    int freefufh = 0;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        return EBADF;
    }

    if ( /* XXXIP ((uio_iovcnt(uio) > 1)) || */
        (uio_resid(uio) < sizeof(struct dirent))) {
        return EINVAL;
    }

    fvdat = VTOFUD(vp);

    fufh = &(fvdat->fufh[FUFH_RDONLY]);

    if (!(fufh->fufh_flags & FUFH_VALID)) {
        err = fuse_filehandle_get(vp, NULL, cred, FUFH_RDONLY);
        if (err) {
            return err;
        }
        freefufh = 1;
    }

#define DIRCOOKEDSIZE FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + MAXNAMLEN + 1)
    fiov_init(&cookediov, DIRCOOKEDSIZE);

    err = fuse_internal_readdir(vp, uio, fufh, &cookediov);

    fiov_teardown(&cookediov);
    if (freefufh) {
        fufh->open_count--;
        (void)fuse_filehandle_put(vp, NULL, NULL, FUFH_RDONLY, 0);
    }

    fuse_invalidate_attr(vp);

    return err;
}

/*
    struct vnop_readlink_args {
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
    };
*/
static int
fuse_vnop_readlink(struct vop_readlink_args *ap)
{
    struct vnode *vp      = ap->a_vp;
    struct uio   *uio     = ap->a_uio;
    struct ucred *cred    = ap->a_cred;

    struct fuse_dispatcher fdi;
    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        return EBADF;
    }

    if (!vnode_islnk(vp)) {
        return EINVAL;
    }

    if ((err = fdisp_simple_putget_vp(&fdi, FUSE_READLINK, vp, curthread, cred))) {
        return err;
    }

    if (((char *)fdi.answ)[0] == '/' &&
        fusefs_get_data(vnode_mount(vp))->dataflags & FSESS_PUSH_SYMLINKS_IN) {
            char *mpth = vnode_mount(vp)->mnt_stat.f_mntonname;
            err = uiomove(mpth, strlen(mpth), uio);
    }

    if (!err) {
        err = uiomove(fdi.answ, fdi.iosize, uio);
    }

    fuse_ticket_drop(fdi.tick);
    fuse_invalidate_attr(vp);

    return err;
}

/*
    struct vnop_reclaim_args {
	struct vnode *a_vp;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_reclaim(struct vop_reclaim_args *ap)
{
    struct vnode *vp      = ap->a_vp;
    struct thread *td     = ap->a_td;

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh = NULL;

    int type;

    fuse_trace_printf_vnop();

    if (!fvdat) {
        panic("FUSE: no vnode data during recycling");
    }

    for (type = 0; type < FUFH_MAXTYPE; type++) {
        fufh = &(fvdat->fufh[type]);
        if (fufh->fufh_flags & FUFH_VALID) {
            if (fufh->fufh_flags & FUFH_STRATEGY) {
                fufh->fufh_flags &= ~FUFH_MAPPED;
                fufh->open_count = 0;
                (void)fuse_filehandle_put(vp, td, NULL, type, 0);
            } else {
                panic("vnode being reclaimed but fufh (type=%d) is valid",
                      type);
            }
        }
    }

    if ((!fuse_isdeadfs(vp)) && (fvdat->nlookup)) {
        struct fuse_dispatcher fdi;
        fdi.tick = NULL;
        fuse_internal_forget_send(vnode_mount(vp), td, NULL, VTOI(vp),
                                  fvdat->nlookup, &fdi);
    }

    cache_purge(vp);
    vfs_hash_remove(vp);
    vnode_destroy_vobject(vp);
    fuse_vnode_destroy(vp);

    return 0;
}

/*
    struct vnop_remove_args {
	struct vnode *a_dvp;
	struct vnode *a_vp;
	struct componentname *a_cnp;
    };
*/
static int
fuse_vnop_remove(struct vop_remove_args *ap)
{
    struct vnode         *dvp     = ap->a_dvp;
    struct vnode         *vp      = ap->a_vp;
    struct componentname *cnp     = ap->a_cnp;

    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        panic("FUSE: fuse_vnop_remove(): called on a dead file system");
    }

    if (vnode_isdir(vp)) {
        return EPERM;
    }

    cache_purge(vp);

    err = fuse_internal_remove(dvp, vp, cnp, FUSE_UNLINK);

    return err;
}

/*
    struct vnop_rename_args {
	struct vnode *a_fdvp;
	struct vnode *a_fvp;
	struct componentname *a_fcnp;
	struct vnode *a_tdvp;
	struct vnode *a_tvp;
	struct componentname *a_tcnp;
    };
*/
static int
fuse_vnop_rename(struct vop_rename_args *ap)
{
    struct vnode *fdvp         = ap->a_fdvp;
    struct vnode *fvp          = ap->a_fvp;
    struct componentname *fcnp = ap->a_fcnp;
    struct vnode *tdvp         = ap->a_tdvp;
    struct vnode *tvp          = ap->a_tvp;
    struct componentname *tcnp = ap->a_tcnp;

    int err = 0;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(fdvp)) {
        panic("fuse_vnop_rename(): called on a dead file system");
    }

    if (fvp->v_mount != tdvp->v_mount ||
        (tvp && fvp->v_mount != tvp->v_mount)) {
        DEBUG("cross-device rename: %s -> %s\n",
	    fcnp->cn_nameptr, (tcnp != NULL ? tcnp->cn_nameptr : "(NULL)"));
        err = EXDEV;
        goto out;
    }

    cache_purge(fvp);

    /*
     * FUSE library is expected to check if target directory is not
     * under the source directory in the file system tree.
     * Linux performs this check at VFS level.
     */
    err = fuse_internal_rename(fdvp, fcnp, tdvp, tcnp);

    if (tvp != NULL && tvp != fvp) {
        cache_purge(tvp);
    }

out:
    if (tdvp == tvp) {
        vrele(tdvp);
    } else {
        vput(tdvp);
    }
    if (tvp != NULL) {
        vput(tvp);
    }
    vrele(fdvp);
    vrele(fvp);

    return err;
}

/*
    struct vnop_rmdir_args {
	    struct vnode *a_dvp;
	    struct vnode *a_vp;
	    struct componentname *a_cnp;
    } *ap;
*/
static int
fuse_vnop_rmdir(struct vop_rmdir_args *ap)
{
    struct vnode         *dvp     = ap->a_dvp;
    struct vnode         *vp      = ap->a_vp;

    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(ap->a_vp)) {
        panic("fuse_vnop_rmdir(): called on a dead file system");
    }

    if (VTOFUD(vp) == VTOFUD(dvp)) {
        return EINVAL;
    }

    cache_purge(ap->a_vp);

    err = fuse_internal_remove(ap->a_dvp, ap->a_vp, ap->a_cnp, FUSE_RMDIR);

    return err;
}

/*
    struct vnop_setattr_args {
	struct vnode *a_vp;
	struct vattr *a_vap;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_setattr(struct vop_setattr_args *ap)
{
    struct vnode      *vp      = ap->a_vp;
    struct vattr      *vap     = ap->a_vap;
    struct ucred      *cred    = ap->a_cred;
    struct thread     *td      = curthread;

    struct fuse_dispatcher  fdi;
    struct fuse_setattr_in *fsai;
    struct fuse_access_param facp;

    int err = 0;
    enum vtype vtyp;
    int sizechanged = 0;
    uint64_t newsize = 0;

    fuse_trace_printf_vnop();

    /*
     * XXX: Locking
     *
     * We need to worry about the file size changing in setattr. If the call
     * is indeed altering the size, then:
     *
     * lock_exclusive(truncatelock)
     *   lock(nodelock)
     *     set the new size
     *   unlock(nodelock)
     *   adjust ubc
     *   lock(nodelock)
     *     do cleanup
     *   unlock(nodelock)
     * unlock(truncatelock)
     * ...
     */

    if (fuse_isdeadfs_nop(vp)) {
        return EBADF;
    }

    fdisp_init(&fdi, sizeof(*fsai));
    fdisp_make_vp(&fdi, FUSE_SETATTR, vp, td, cred);
    fsai = fdi.indata;
    fsai->valid = 0;

    bzero(&facp, sizeof(facp));

#define FUSEATTR(x) x

    facp.xuid = vap->va_uid;
    facp.xgid = vap->va_gid;

    if (vap->va_uid != (uid_t)VNOVAL) {
        facp.facc_flags |= FACCESS_CHOWN;
        fsai->FUSEATTR(uid) = vap->va_uid;
        fsai->valid |= FATTR_UID;
    }

    if (vap->va_gid != (gid_t)VNOVAL) {
        facp.facc_flags |= FACCESS_CHOWN;
        fsai->FUSEATTR(gid) = vap->va_gid;
        fsai->valid |= FATTR_GID;
    }

    if (vap->va_size != VNOVAL) {

        struct fuse_filehandle *fufh = NULL;
        fufh_type_t fufh_type = FUFH_WRONLY;
        struct fuse_vnode_data *fvdat = VTOFUD(vp);

        // Truncate to a new value.
        fsai->FUSEATTR(size) = vap->va_size;
        sizechanged = 1;
        newsize = vap->va_size;
        fsai->valid |= FATTR_SIZE;      

        fufh = &(fvdat->fufh[fufh_type]);
        if (!(fufh->fufh_flags & FUFH_VALID)) {
            fufh_type = FUFH_RDWR;
            fufh = &(fvdat->fufh[fufh_type]);
            if (!(fufh->fufh_flags & FUFH_VALID)) {
                fufh = NULL;
            }
        }

        if (fufh) {
            fsai->fh = fufh->fh_id;
            fsai->valid |= FATTR_FH;
        }
    }

    if (vap->va_atime.tv_sec != VNOVAL) {
        fsai->FUSEATTR(atime) = vap->va_atime.tv_sec;
        fsai->FUSEATTR(atimensec) = vap->va_atime.tv_nsec;
        fsai->valid |=  FATTR_ATIME;
    }

    if (vap->va_mtime.tv_sec != VNOVAL) {
        fsai->FUSEATTR(mtime) = vap->va_mtime.tv_sec;
        fsai->FUSEATTR(mtimensec) = vap->va_mtime.tv_nsec;
        fsai->valid |=  FATTR_MTIME;
    }

    if (vap->va_mode != (mode_t)VNOVAL) {
        fsai->FUSEATTR(mode) = vap->va_mode & ALLPERMS;
        fsai->valid |= FATTR_MODE;
    }

#undef FUSEATTR

    if (!fsai->valid) {
        goto out;
    }

    vtyp = vnode_vtype(vp);

    if (fsai->valid & FATTR_SIZE && vtyp == VDIR) {
        err = EISDIR;
        goto out;
    }

    if (vfs_isrdonly(vnode_mount(vp)) && (fsai->valid & ~FATTR_SIZE || vtyp == VREG)) {
        err = EROFS;
        goto out;
    }

    if (fsai->valid & ~FATTR_SIZE) {
        // err = fuse_internal_access(vp, VADMIN, context, &facp); // XXX
        err = 0;
    }

    facp.facc_flags &= ~FACCESS_XQUERIES;

    if (err && !(fsai->valid & ~(FATTR_ATIME | FATTR_MTIME)) &&
        vap->va_vaflags & VA_UTIMES_NULL) {
        err = fuse_internal_access(vp, VWRITE, &facp, td, cred);
    }

    if (err) {
        fuse_invalidate_attr(vp);
        goto out;
    }

    if ((err = fdisp_wait_answ(&fdi))) {
        fuse_invalidate_attr(vp);
        return err;
    }

    vtyp = IFTOVT(((struct fuse_attr_out *)fdi.answ)->attr.mode);

    if (vnode_vtype(vp) != vtyp) {
        if (vnode_vtype(vp) == VNON && vtyp != VNON) {
            debug_printf("FUSE: Dang! vnode_vtype is VNON and vtype isn't.\n");
        } else {
            // XXX: should ditch vnode.
            err = ENOTCONN;
        }
    }

    if (!err && !sizechanged) {
        cache_attrs(vp, (struct fuse_attr_out *)fdi.answ);
    }

out:
    fuse_ticket_drop(fdi.tick);
    if (!err && sizechanged) {
        fuse_invalidate_attr(vp);
        VTOFUD(vp)->filesize = newsize;
        vnode_pager_setsize(vp, newsize);
    }

    return err;
}

/*
    struct vnop_strategy_args {
	struct vnode *a_vp;
	struct buf *a_bp;
    };
*/
static int
fuse_vnop_strategy(struct vop_strategy_args *ap)
{
    struct vnode *vp = ap->a_vp;
    struct buf *bp = ap->a_bp;

    fuse_trace_printf_vnop();

    if (!vp || fuse_isdeadfs(vp)) {
        bp->b_ioflags |= BIO_ERROR;
        bp->b_error = EIO;
        bufdone(bp);
        return EIO;
    }

    (void)fuse_io_strategy(vp, bp, NULL, 0);

    /* 
     * This is a dangerous function. If returns error, that might mean a
     * panic. We prefer pretty much anything over being forced to panic by
     * a malicious daemon (a demon?). So we just return 0 anyway. You
     * should never mind this: this function has its own error propagation
     * mechanism via the argument buffer, so not-that-melodramatic
     * residents of the call chain still will be able to know what to do.
     */
    return 0;
}


/*
    struct vnop_symlink_args {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
	char *a_target;
    };
*/
static int
fuse_vnop_symlink(struct vop_symlink_args *ap)
{
    struct vnode         *dvp     = ap->a_dvp;
    struct vnode        **vpp     = ap->a_vpp;
    struct componentname *cnp     = ap->a_cnp;
    char                 *target  = ap->a_target;

    struct fuse_dispatcher fdi;

    int err;
    size_t len;

    /*
     * Unlike the other creator type calls, here we have to create a message
     * where the name of the new entry comes first, and the data describing
     * the entry comes second.
     * Hence we can't rely on our handy fuse_internal_newentry() routine,
     * but put together the message manually and just call the core part.
     */

    len = strlen(target) + 1;
    fdisp_init(&fdi, len + cnp->cn_namelen + 1);
    fdisp_make_vp(&fdi, FUSE_SYMLINK, dvp, curthread, NULL);

    memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
    ((char *)fdi.indata)[cnp->cn_namelen] = '\0';
    memcpy((char *)fdi.indata + cnp->cn_namelen + 1, target, len);

    err = fuse_internal_newentry_core(dvp, vpp, cnp, VLNK, &fdi);
    fuse_invalidate_attr(dvp);

    return err;
}

/*
    struct vnop_write_args {
	struct vnode *a_vp;
	struct uio *a_uio;
	int  a_ioflag;
	struct ucred *a_cred;
    };
*/
static int
fuse_vnop_write(struct vop_write_args *ap)
{
    struct vnode *vp      = ap->a_vp;
    struct uio   *uio     = ap->a_uio;
    int           ioflag  = ap->a_ioflag;
    struct ucred *cred    = ap->a_cred;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        return EIO;
    }

    return fuse_io_vnode(vp, uio, ioflag, cred);
}

/*
 * [gs]etpages taken & stripped off from nfsclient
 */

#ifndef PAGEOP_TRANSLATE_UIO
#define PAGEOP_TRANSLATE_UIO 1
#endif
#if PAGEOP_TRANSLATE_UIO
#define FUSE_PAGEOPS_RESID uio.uio_resid
#else
#define FUSE_PAGEOPS_RESID bp->b_resid
#endif

/*
    struct vnop_getpages_args {
        struct vnode *a_vp;
        vm_page_t *a_m;
        int a_count;
        int a_reqpage;
        vm_ooffset_t a_offset;
    };
*/
static int
fuse_vnop_getpages(struct vop_getpages_args *ap)
{
	int i, error, nextoff, size, toff, count, npages;
#if PAGEOP_TRANSLATE_UIO
	struct uio uio;
	struct iovec iov;
#endif
	vm_offset_t kva;
	struct buf *bp;
	struct vnode *vp;
	struct thread *td;
	struct ucred *cred;
	vm_page_t *pages;

	DEBUG2G("heh\n");

	vp = ap->a_vp;
	KASSERT(vp->v_object, ("objectless vp passed to getpages"));
	td = curthread;				/* XXX */
	cred = curthread->td_ucred;		/* XXX */
	pages = ap->a_m;
	count = ap->a_count;

	npages = btoc(count);

	/*
	 * If the requested page is partially valid, just return it and
	 * allow the pager to zero-out the blanks.  Partially valid pages
	 * can only occur at the file EOF.
	 */

	{
		vm_page_t m = pages[ap->a_reqpage];

		VM_OBJECT_LOCK(vp->v_object);
		vm_page_lock_queues();
		if (m->valid != 0) {
			/* handled by vm_fault now	  */
			/* vm_page_zero_invalid(m, TRUE); */
			for (i = 0; i < npages; ++i) {
				if (i != ap->a_reqpage)
					vm_page_free(pages[i]);
			}
			vm_page_unlock_queues();
			VM_OBJECT_UNLOCK(vp->v_object);
			return(0);
		}
		vm_page_unlock_queues();
		VM_OBJECT_UNLOCK(vp->v_object);
	}

	/*
	 * We use only the kva address for the buffer, but this is extremely
	 * convienient and fast.
	 */
	bp = getpbuf(&fuse_pbuf_freecnt);

	kva = (vm_offset_t) bp->b_data;
	pmap_qenter(kva, pages, npages);
	cnt.v_vnodein++;
	cnt.v_vnodepgsin += npages;

#if PAGEOP_TRANSLATE_UIO
	iov.iov_base = (caddr_t) kva;
	iov.iov_len = count;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = IDX_TO_OFF(pages[0]->pindex);
	uio.uio_resid = count;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = td;

	error = fuse_io_dispatch(vp, &uio, FREAD | O_DIRECT, cred);
#else
	error = fuse_io_strategy(vp, bp);
#endif
	pmap_qremove(kva, npages);

	relpbuf(bp, &fuse_pbuf_freecnt);

	if (error && (FUSE_PAGEOPS_RESID == count)) {
		DEBUG2G("error %d\n", error);
		VM_OBJECT_LOCK(vp->v_object);
		vm_page_lock_queues();
		for (i = 0; i < npages; ++i) {
			if (i != ap->a_reqpage)
				vm_page_free(pages[i]);
		}
		vm_page_unlock_queues();
		VM_OBJECT_UNLOCK(vp->v_object);
		return VM_PAGER_ERROR;
	}

	/*
	 * Calculate the number of bytes read and validate only that number
	 * of bytes.  Note that due to pending writes, size may be 0.  This
	 * does not mean that the remaining data is invalid!
	 */

	size = count - FUSE_PAGEOPS_RESID;
	VM_OBJECT_LOCK(vp->v_object);
	vm_page_lock_queues();
	for (i = 0, toff = 0; i < npages; i++, toff = nextoff) {
		vm_page_t m;
		nextoff = toff + PAGE_SIZE;
		m = pages[i];

		if (nextoff <= size) {
			/*
			 * Read operation filled an entire page
			 */
			m->valid = VM_PAGE_BITS_ALL;
			vm_page_undirty(m);
		} else if (size > toff) {
			/*
			 * Read operation filled a partial page.
			 */
			m->valid = 0;
			vm_page_set_validclean(m, 0, size - toff);
			/* handled by vm_fault now	  */
			/* vm_page_zero_invalid(m, TRUE); */
		} else {
			/*
			 * Read operation was short.  If no error occured
			 * we may have hit a zero-fill section.   We simply
			 * leave valid set to 0.
			 */
			;
		}
		if (i != ap->a_reqpage) {
			/*
			 * Whether or not to leave the page activated is up in
			 * the air, but we should put the page on a page queue
			 * somewhere (it already is in the object).  Result:
			 * It appears that emperical results show that
			 * deactivating pages is best.
			 */

			/*
			 * Just in case someone was asking for this page we
			 * now tell them that it is ok to use.
			 */
			if (!error) {
#ifdef VPO_WANTED
				if (m->oflags & VPO_WANTED)
#else
				if (m->flags & PG_WANTED)
#endif
					vm_page_activate(m);
				else
					vm_page_deactivate(m);
				vm_page_wakeup(m);
			} else {
				vm_page_free(m);
			}
		}
	}
	vm_page_unlock_queues();
	VM_OBJECT_UNLOCK(vp->v_object);
	return 0;
}

/*
    struct vnop_putpages_args {
        struct vnode *a_vp;
        vm_page_t *a_m;
        int a_count;
        int a_sync;
        int *a_rtvals;
        vm_ooffset_t a_offset;
    };
*/
static int
fuse_vnop_putpages(struct vop_putpages_args *ap)
{
#if PAGEOP_TRANSLATE_UIO
	struct uio uio;
	struct iovec iov;
#endif
	vm_offset_t kva;
	struct buf *bp;
	int i, error, npages, count;
	off_t offset;
	int *rtvals;
	struct vnode *vp;
	struct thread *td;
	struct ucred *cred;
	vm_page_t *pages;
	vm_ooffset_t fsize;

	DEBUG2G("heh\n");

	vp = ap->a_vp;
	KASSERT(vp->v_object, ("objectless vp passed to putpages"));
	fsize = vp->v_object->un_pager.vnp.vnp_size;
	td = curthread;				/* XXX */
	cred = curthread->td_ucred;		/* XXX */
	pages = ap->a_m;
	count = ap->a_count;
	rtvals = ap->a_rtvals;
	npages = btoc(count);
	offset = IDX_TO_OFF(pages[0]->pindex);

	for (i = 0; i < npages; i++)
		rtvals[i] = VM_PAGER_AGAIN;

	/*
	 * When putting pages, do not extend file past EOF.
	 */

	if (offset + count > fsize) {
		count = fsize - offset;
		if (count < 0)
			count = 0;
	}

	/*
	 * We use only the kva address for the buffer, but this is extremely
	 * convienient and fast.
	 */
	bp = getpbuf(&fuse_pbuf_freecnt);

	kva = (vm_offset_t) bp->b_data;
	pmap_qenter(kva, pages, npages);
	cnt.v_vnodeout++;
	cnt.v_vnodepgsout += count;

#if PAGEOP_TRANSLATE_UIO
	iov.iov_base = (caddr_t) kva;
	iov.iov_len = count;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = offset;
	uio.uio_resid = count;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_td = td;

	error = fuse_io_dispatch(vp, &uio, FWRITE | O_DIRECT, cred);
#else
	error = fuse_io_strategy(vp, bp);
#endif

	pmap_qremove(kva, npages);
	relpbuf(bp, &fuse_pbuf_freecnt);

	if (!error) {
		int nwritten = round_page(count - FUSE_PAGEOPS_RESID) / PAGE_SIZE;
		for (i = 0; i < nwritten; i++) {
			rtvals[i] = VM_PAGER_OK;
			vm_page_undirty(pages[i]);
		}
	}
	return rtvals[0];
}
#undef FUSE_PAGEOPS_RESID

/*
    struct vnop_print_args {
        struct vnode *a_vp;
    };
*/
static int
fuse_vnop_print(struct vop_print_args *ap)
{
	struct fuse_vnode_data *fvdat = VTOFUD(ap->a_vp);

	printf("nodeid: %ju, parent_nid: %ju, "
	       "nlookup: %ju, flags: %#x\n",
	       VTOILLU(ap->a_vp), (uintmax_t) fvdat->parent_nid,
	       (uintmax_t)fvdat->nlookup,
	       fvdat->flags);

	return 0;
}

/*
    struct vnop_unlock_args {
        struct vnode *a_vp;
        int a_flags;
        struct thread *a_td;
    };
*/
static int
fuse_vnop_unlock(struct vop_unlock_args *ap)
{
	struct vnode *vp = ap->a_vp;

	if (VTOFUD(vp))
		VTOFUD(vp)->flags &= ~FVP_ACCESS_NOOP;

	return vop_stdunlock(ap);
}
