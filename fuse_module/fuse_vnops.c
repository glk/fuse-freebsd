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

static struct vop_vector fuse_vnops = {
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

MALLOC_DEFINE(M_FUSEVN, "fuse_vnode", "fuse vnode private data");
MALLOC_DEFINE(M_FUSEFH, "fuse_filehandles", "buffer for fuse filehandles");

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
    struct vnode *vp = ap->a_vp;
    struct fuse_access_param facp;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        if (vnode_isvroot(vp)) {
            return 0;
        }
        return EBADF;
    }

    bzero(&facp, sizeof(facp));

    if (fvdat->flags & FVP_ACCESS_NOOP) {
        fvdat->flags &= ~FVP_ACCESS_NOOP;
    } else {
        facp.facc_flags |= FACCESS_DO_ACCESS;
    }   

    return fuse_internal_access(vp, ap->a_accmode, ap->a_cred, ap->a_td, &facp);
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
    struct vnode *vp = ap->a_vp;
    fufh_type_t             fufh_type;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh = NULL;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        return 0;
    }

    if (vnode_vtype(vp) == VDIR) {
        fufh_type = FUFH_RDONLY;
    } else {
        fufh_type = fuse_filehandle_xlate_from_fflags(ap->a_fflag);
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
    struct vnode *dvp = ap->a_dvp;
    struct vnode **vpp = ap->a_vpp;
    struct componentname *cnp = ap->a_cnp;
    struct vattr *vap = ap->a_vap;
    struct thread *td = cnp->cn_thread;
    struct ucred *cred = cnp->cn_cred;

    struct fuse_dispatcher  fdi;
    struct fuse_dispatcher *fdip = &fdi;
    struct fuse_entry_out  *feo;
    struct fuse_mknod_in    fmni;
    struct fuse_open_in    *foi;

    int err;
    int gone_good_old = 0;

    struct mount *mp = vnode_mount(dvp);
    uint64_t parentnid = VTOFUD(dvp)->nid;
    mode_t mode = MAKEIMODE(vap->va_type, vap->va_mode);

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(dvp)) {
        panic("fuse_vnop_create(): called on a dead file system");
    }

    bzero(&fdi, sizeof(fdi));

    // XXX: Will we ever want devices?
    if ((vap->va_type != VREG) ||
        fusefs_get_data(mp)->dataflag & FSESS_NOCREATE) {
        goto good_old;
    }

    debug_printf("parent nid = %llu, mode = %x\n", parentnid, mode);

    fdisp_init(fdip, sizeof(*foi) + cnp->cn_namelen + 1);
    if (fusefs_get_data(vnode_mount(dvp))->dataflag & FSESS_NOCREATE) {
        debug_printf("eh, daemon doesn't implement create?\n");
        goto good_old;
    }

    fdisp_make(fdip, vnode_mount(dvp), FUSE_CREATE, parentnid, td, cred);

    foi = fdip->indata;
    foi->mode = mode;
    foi->flags = O_RDWR; // XXX: We /always/ creat() like this.

    memcpy((char *)fdip->indata + sizeof(*foi), cnp->cn_nameptr,
           cnp->cn_namelen);
    ((char *)fdip->indata)[sizeof(*foi) + cnp->cn_namelen] = '\0';

    err = fdisp_wait_answ(fdip);

    if (err == ENOSYS) {
        debug_printf("create: got ENOSYS from daemon\n");
        fusefs_get_data(vnode_mount(dvp))->dataflag |= FSESS_NOCREATE;
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

    err = FSNodeGetOrCreateFileVNodeByID(mp,
                                         feo->nodeid,
                                         dvp,
                                         VREG, /*size*/0,
                                         vpp,
                                         (gone_good_old) ? 0 : FN_CREATING);
    if (err) {
       if (gone_good_old) {
           fuse_internal_forget_send(mp, td, cred, feo->nodeid, 1, fdip);
       } else {
           struct fuse_release_in *fri;
           uint64_t nodeid = feo->nodeid;
           uint64_t fh_id = ((struct fuse_open_out *)(feo + 1))->fh;

           fdisp_init(fdip, sizeof(*fri));
           fdisp_make(fdip, mp, FUSE_RELEASE, nodeid, td, cred);
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

    cache_enter(dvp, *vpp, cnp);

    return (0);

undo:
    return (err);
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
    struct vnode *vp = ap->a_vp;
    struct thread *td = ap->a_td;
    struct fuse_dispatcher fdi;
    struct fuse_filehandle *fufh;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    int type;
#if 0
    int err = 0;
    int waitfor = ap->a_waitfor;
    struct timeval tv;
    int wait = (waitfor == MNT_WAIT);
#endif
    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        return 0;
    }

    cluster_push(vp, 0);

#if 0
    buf_flushdirtyblks(vp, wait, 0, (char *)"fuse_fsync");
    microtime(&tv);
#endif

    // vnode and ubc are in lock-step.
    // can call vnode_isinuse().
    // can call ubc_sync_range().

    if (!(fusefs_get_data(vnode_mount(vp))->dataflag &
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

#ifdef XXXVP
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
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct ucred *cred = ap->a_cred;
	struct thread *td = curthread;
	struct fuse_dispatcher fdi;
	struct timespec uptsp;
	int err = 0;

	/* look for cached attributes */
	nanouptime(&uptsp);
	if (timespeccmp(&uptsp, &VTOFUD(vp)->cached_attrs_valid, <=)) {
		DEBUG("found valid cached attrs for vp #%llu\n", VTOILLU(vp));

		if (vap != VTOVA(vp))
			memcpy(vap, VTOVA(vp), sizeof(*vap));

		return (0);
	}

	if (! (fusefs_get_data(vp->v_mount)->dataflag & FSESS_INITED)) {
		if (! (vp->v_vflag & VV_ROOT)) {
			fdata_kick_set(fusefs_get_data(vp->v_mount));
			err = ENOTCONN;

			return (err);
		} else
			goto fake;
	}

	if ((err = fdisp_simple_putget(&fdi, FUSE_GETATTR, vp, td, cred))) {
		if (err == ENOTCONN && vp->v_vflag & VV_ROOT)
			/* see comment at similar place in fuse_statfs() */
			goto fake;

		return (err);
	}

	cache_attrs(vp, (struct fuse_attr_out *)fdi.answ);
	if (vap != VTOVA(vp))
		memcpy(vap, VTOVA(vp), sizeof(*vap));

	fuse_ticket_drop(fdi.tick);

	if (vp->v_type != vap->va_type) {
		if (vp->v_type == VNON && vap->va_type != VNON) {
			DEBUG2G("vnode #%llu with no type\n", VTOILLU(vp));
			vp->v_type = vap->va_type;
		} else {
			/* stale vnode */
			DEBUG2G("node #%lu got stale (old type %#x, new type %#x), kicking...\n",
		                vap->va_fileid, vp->v_type, vap->va_type);
			fuse_vnode_ditch(vp, td);
			return (ENOTCONN);
		}
	}

	DEBUG("node #%llu, type %d\n", VTOILLU(vp), vap->va_type);
#if _DEBUG
	DEBUG2G("\n");	
	vn_printf(vp, " * ");
#endif
	return (0);

fake:
    bzero(vap, sizeof(*vap));
    vap->va_type = vnode_vtype(vp);

    return (0);
}
#endif

/*
    struct vnop_inactive_args {
	struct vnode *a_vp;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_inactive(struct vop_inactive_args *ap)
{
    struct vnode *vp = ap->a_vp;	
    struct thread *td = ap->a_td;
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
    struct vnode *vp = ap->a_vp;
    struct vnode *tdvp = ap->a_tdvp;
    struct componentname *cnp = ap->a_cnp;

    int err = 0;
    struct fuse_dispatcher fdi;
    struct fuse_entry_out *feo;
    struct fuse_link_in    fli;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(vp)) {
        panic("fuse_vnop_link(): called on a dead file system");
    }

    if (vnode_mount(tdvp) != vnode_mount(vp)) {
        return (EXDEV);
    }

    fli.oldnodeid = VTOI(vp);

    fdisp_init(&fdi, 0);
    fuse_internal_newentry_makerequest(vnode_mount(tdvp), VTOI(tdvp), cnp,
                                       FUSE_LINK, &fli, sizeof(fli), &fdi);
    if ((err = fdisp_wait_answ(&fdi))) {
        return (err);
    }

    feo = fdi.answ;

    err = fuse_internal_checkentry(feo, vnode_vtype(vp));
    fuse_ticket_drop(fdi.tick);
    fuse_invalidate_attr(tdvp);
    fuse_invalidate_attr(vp);

    return (err);
}

/*
    struct vnop_lookup_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
    };
*/
#ifdef XXXIP
int
fuse_vnop_lookup(struct vop_lookup_args *ap)
{
    struct componentname *cnp = ap->a_cnp;
    int nameiop               = cnp->cn_nameiop;
    int flags                 = cnp->cn_flags;
    int wantparent            = flags & WANTPARENT;
    int islastcn              = flags & ISLASTCN;
    struct vnode *dvp         = ap->a_dvp;
    struct vnode **vpp        = ap->a_vpp;
    struct thread *td         = cnp->cn_thread;
    struct ucred *cred        = cnp->cn_cred;

    fuse_trace_printf_vnop();

    int err                   = 0;
    int lookup_err            = 0;
    struct vnode *vp          = NULL;
    struct fuse_attr *fattr   = NULL;
    struct fuse_dispatcher fdi;
    enum fuse_opcode op;
    uint64_t nid, parentid;
    struct fuse_access_param facp;
#ifdef INVARIANTS
    int cache_attrs_hit = 0;
#endif

    /* general stuff, based on vfs_cache_lookup */

#if _DEBUG
    DEBUG2G("root node:\n");
    vn_printf(fusefs_get_data(dvp->v_mount)->rvp, " * ");
#endif

    if (dvp->v_type != VDIR) {
        return ENOTDIR;
    }

    if (islastcn && (dvp->v_mount->mnt_flag & MNT_RDONLY) &&
        (nameiop == DELETE || nameiop == RENAME)) {
        return (EROFS);
    }

    /*
     * We do access check prior to doing anything else only in the case
     * when we are at fs root (we'd like to say, "we are at the first
     * component", but that's not exactly the same... nevermind).
     * See further comments at further access checks.
     */

    bzero(&facp, sizeof(facp));
    if (
#ifdef NO_EARLY_PERM_CHECK_HACK
        1
#else
        dvp->v_vflag & VV_ROOT
#endif
       ) {
            if ((err = fuse_internal_access(dvp, VEXEC, cred, td, &facp)))
                return err;
    }

    DEBUG2G("lookup in #%llu, nameiop %lu, with flags %#x\n",
            VTOILLU(dvp), cnp->cn_nameiop, flags);

    /* fetching data from "storage" */

    if (flags & ISDOTDOT) {
        DEBUG2G("dotdot lookup!\n");
        nid = VTOFUD(dvp)->parent_nid;
        parentid = FUSE_NULL_ID;
        fdisp_init(&fdi, 0);
        op = FUSE_GETATTR;
    } else if (cnp->cn_namelen == 1 && *(cnp->cn_nameptr) == '.') {
        DEBUG2G("dot lookup!\n");
        nid = VTOI(dvp);
        parentid = VTOFUD(dvp)->parent_nid; /* irrelevant */
        fdisp_init(&fdi, 0);
        op = FUSE_GETATTR;
    } else {
        nid = VTOI(dvp);
        parentid = VTOI(dvp);
        fdisp_init(&fdi, cnp->cn_namelen + 1);
        op = FUSE_LOOKUP;
    }

    fdisp_make(&fdi, dvp->v_mount, op, nid, td, cred);

    if (op == FUSE_LOOKUP) {
        memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
        ((char *)fdi.indata)[cnp->cn_namelen] = '\0';
        DEBUG2G("standard lookup, looking up %s\n", (char *)fdi.indata);
    }

    lookup_err = fdisp_wait_answ(&fdi);

    if (op == FUSE_LOOKUP && !lookup_err) {
        nid = ((struct fuse_entry_out *)fdi.answ)->nodeid;
        if (!nid) {
            /*
             * zero nodeid is the same as "not found",
             * but it's also cacheable (which we keep
             * keep on doing not as of writing this)
             */
            DEBUG2G("zero nid, ie ENOENT\n");
            lookup_err = ENOENT;
        } else if (nid == FUSE_ROOT_ID) {
            DEBUG2G("root inode found on lookup?!!\n");
            lookup_err = EINVAL;
        }
    }

    if (lookup_err && (
         (!fdi.answ_stat) || /* this means messaging error */
         lookup_err != ENOENT || /* daemon reported other error than "legal" ENOENT */
         op != FUSE_LOOKUP /* we tolerate ENOENT only when we sent a LOOKUP */  
        )) {
        /*
         * There is error but not lookup related actually
         * (messaging error)
         */
        DEBUG("lookup failed b/c messaging crap\n");
        return (lookup_err);
    }

    /* analyzing answer */

    /*
     * Now we got the answer and filtered out the crap, too, so we know that
     * "found" iff lookup_err == 0
     */

    if (lookup_err) {
        DEBUG("looked up thingy not found\n");
        if ((nameiop == CREATE || nameiop == RENAME)
         && islastcn
         /* && directory dvp has not been removed */) {

                if (dvp->v_mount->mnt_flag & MNT_RDONLY) {
                        err = EROFS;
                        goto out;
                }

                DEBUG("create/rename -- we have to make it\n");
                /*
                 * Check for write access on directory.
                 */
                
                if ((err = fuse_internal_access(dvp, VWRITE, cred, td, &facp)))
                        goto out;

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

        /*
         * Consider inserting name into cache.
         */

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
        if (op == FUSE_GETATTR) {
            fattr = &((struct fuse_attr_out *)fdi.answ)->attr;
        } else {
            fattr = &((struct fuse_entry_out *)fdi.answ)->attr;
        }

        DEBUG("we found something...\n");
        /*
         * If deleting, and at end of pathname, return parameters
         * which can be used to remove file.  If the wantparent flag
         * isn't set, we return only the directory, otherwise we go on
         * and lock the inode, being careful with ".".
         */
        if (nameiop == DELETE && islastcn) {
            DEBUG("something to delete\n");
            /*
             * Check for write access on directory.
             */

            facp.xuid = fattr->uid;
            facp.facc_flags |= FACCESS_STICKY;
            err = fuse_internal_access(dvp, VWRITE, cred, td, &facp);
            facp.facc_flags &= ~FACCESS_XQUERIES;

            if (err) {
                goto out;
            }

            if (nid == VTOI(dvp)) {
                VREF(dvp);
                *vpp = dvp;
                goto out;
            }

            if ((err = fuse_vget_i(dvp->v_mount, td,
                                   nid,
                                   IFTOVT(fattr->mode),
                                   &vp,
                                   VG_NORMAL,
                                   parentid))) {
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
                    DEBUG("something to rename...\n");

                    facp.xuid = fattr->uid;
                    facp.facc_flags |= FACCESS_STICKY;
                    err = fuse_internal_access(dvp, VWRITE, cred, td, &facp);
                    facp.facc_flags &= ~FACCESS_XQUERIES;

                    if (err)
                            goto out;

                    /*
                     * Check for "."
                     */
                    if (nid == VTOI(dvp)) {
                            err = EISDIR;
                            goto out;
                    }

                    err = fuse_vget_i(dvp->v_mount, td, nid,
                                      IFTOVT(fattr->mode), &vp, VG_NORMAL,
                                      parentid);
                    if (err)
                            goto out;
                    *vpp = vp;
                    /*
                     * Save the name for use in VOP_RENAME later.
                     */
                    cnp->cn_flags |= SAVENAME;

                    goto out;
            }

            DEBUG("we peacefully found that file\n");

            if (nid == VTOI(dvp)) {
                    VREF(dvp); /* We want ourself, ie "." */
                    *vpp = dvp;
            } else {
                    if (flags & ISDOTDOT)
                            /*
                             * If doing dotdot, we unlock dvp for vget time
                             * to conform lock order regulations.
                             */
                            VOP_UNLOCK(dvp, 0);
                    err = fuse_vget_i(dvp->v_mount, td, nid,
                                      IFTOVT(fattr->mode), &vp, VG_NORMAL,
                                      parentid);
                    if (flags & ISDOTDOT)
                            vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY);
                    if (err)
                            goto out;
                    *vpp = vp;
            }

        if (op == FUSE_GETATTR)
            cache_attrs(*vpp, (struct fuse_attr_out *)fdi.answ);
        else
            cache_attrs(*vpp, (struct fuse_entry_out *)fdi.answ);

#ifdef INVARIANTS
            cache_attrs_hit = 1;
#endif

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
            DEBUG("...caching\n");
            cache_enter(dvp, *vpp, cnp);
        }
#endif
    }
out:
    if (!lookup_err) {
        DEBUG("as the looked up thing was simply found, the cleanup is left for us\n");

        if (err) {
            DEBUG("though inode found, err exit with no vnode\n");
            if (op == FUSE_LOOKUP)
                fuse_internal_forget_send(dvp->v_mount, td, cred, nid, 1, &fdi);
            return (err);
        } else {
            if (op == FUSE_LOOKUP)
                VTOFUD(*vpp)->nlookup++;

            if (islastcn && flags & ISOPEN)
                VTOFUD(*vpp)->flags |= FVP_ACCESS_NOOP;

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
                bzero(&facp, sizeof(facp));
                DEBUG("the early perm check hack\n");
                facp.facc_flags |= FACCESS_VA_VALID;

                KASSERT(cache_attrs_hit,
                        (("invalid reference to cached attrs")));
                if ((*vpp)->v_type != VDIR && (*vpp)->v_type != VLNK)
                    err = ENOTDIR;
                if (!err && !(*vpp)->v_mountedhere)
                    err = fuse_internal_access(*vpp, VEXEC, cred, td, &facp);
                if (err) {
                    if ((*vpp)->v_type == VLNK)
                        DEBUG("weird, permission error with a symlink?\n");
                    vput(*vpp);
                    *vpp = NULL;
                }
            }
#endif
        }
            
        fuse_ticket_drop(fdi.tick);
    }

    return (err);
}
#endif


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
    struct vnode *dvp = ap->a_dvp;
    struct vnode **vpp = ap->a_vpp;
    struct componentname *cnp = ap->a_cnp;
    struct vattr *vap = ap->a_vap;

    struct fuse_mkdir_in fmdi; 

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(dvp)) {
        panic("fuse_vnop_mkdir(): called on a dead file system");
    }

    fmdi.mode = MAKEIMODE(vap->va_type, vap->va_mode);

    return fuse_internal_newentry(dvp, vpp, cnp, FUSE_MKDIR, &fmdi,
                                 sizeof(fmdi), VDIR);
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
    struct vnode *dvp = ap->a_dvp;
    struct vnode **vpp = ap->a_vpp;
    struct componentname *cnp = ap->a_cnp;
    struct vattr *vap = ap->a_vap;

    struct fuse_mknod_in fmni; 

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_nop(dvp)) {
        panic("fuse_vnop_mknod(): called on a dead file system");
    }

    fmni.mode = MAKEIMODE(vap->va_type, vap->va_mode);
    fmni.rdev = vap->va_rdev;

    return fuse_internal_newentry(dvp, vpp, cnp, FUSE_MKNOD, &fmni,
                                 sizeof(fmni), vap->va_type);
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
    struct vnode *vp = ap->a_vp;
    struct thread *td = ap->a_td;
    struct ucred *cred = ap->a_cred;
    fufh_type_t             fufh_type;
    struct fuse_vnode_data *fvdat;
    struct fuse_filehandle *fufh = NULL;
    struct fuse_filehandle *fufh_rw = NULL;

    int error, isdir = 0, mode, oflags;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    mode    = ap->a_mode;
    fvdat   = VTOFUD(vp);
    if (vnode_vtype(vp) == VDIR) {
        isdir = 1;
    }

    if (isdir) {
        fufh_type = FUFH_RDONLY;
    } else {
        debug_printf("fuse_open(VREG)\n");
        fufh_type = fuse_filehandle_xlate_from_fflags(mode);
    }

    oflags = fuse_filehandle_xlate_to_oflags(fufh_type);

    fufh = &(fvdat->fufh[fufh_type]);

    if (!isdir && (fvdat->flag & FN_CREATING)) {

        mtx_lock(&fvdat->createlock);

        if (fvdat->flag & FN_CREATING) { // check again
            if (fvdat->creator == curthread) {

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
                wakeup((caddr_t)fvdat->creator); // wake up all
                goto ok; /* return 0 */
            } else {
                printf("contender going to sleep\n");
                error = msleep(fvdat->creator, &fvdat->createlock,
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
    {
        /*
         * Doing this here because when a vnode goes inactive, no-cache and
         * no-readahead are cleared by the kernel.
         */
        int dataflag = fusefs_get_data(vnode_mount(vp))->dataflag;
        if (dataflag & FSESS_NO_READAHEAD) {
            vnode_setnoreadahead(vp);
        }
        if (dataflag & FSESS_NO_UBC) {
            vnode_setnocache(vp);
        }
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
    struct vnode *vp = ap->a_vp;
    struct ucred *cred = ap->a_cred;
    struct uio *uio = ap->a_uio;
    int ioflag = ap->a_ioflag;

    DEBUG2G("vnode #%llu\n", VTOILLU(vp));
    return fuse_io_vnode(vp, cred, uio, ioflag);
}

#define DIRCOOKEDSIZE FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + MAXNAMLEN + 1)

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
    struct vnode *vp = ap->a_vp;
    struct ucred *cred = ap->a_cred;
    struct uio *uio = ap->a_uio;

    struct thread *td = curthread;
    int err = 0;
    struct fuse_iov cookediov;
    struct fuse_filehandle *fufh;
    struct fuse_io_data fioda;
    struct get_filehandle_param gefhp;

    bzero(&gefhp, sizeof(gefhp));
    gefhp.opcode = FUSE_OPENDIR;
    if ((err = fuse_get_filehandle(vp, td, cred, FREAD, &fufh, &gefhp))) {
            DEBUG2G("fetching filehandle failed\n");
            return (err);
    }

    /*
     * In "most cases" this will do and won't have to resize the buffer
     * (that is, if the daemon has a "tight" view of the dir entries,
     * which is the case if userspace uses the old API or the new one
     * in the analogous way; by our terminology, this means
     * freclen == bytesavail)
     * (See fuse_internal_readdir_processdata).
     */
    fiov_init(&cookediov, DIRCOOKEDSIZE);

    bzero(&fioda, sizeof(fioda));
    fioda.vp = vp;
    fioda.fufh = fufh;
    fioda.uio = uio;
    fioda.cred = cred;
    fioda.opcode = FUSE_READDIR;
    fioda.buffeater = fuse_internal_readdir_processdata;
    fioda.param = &cookediov;
    /*
     * We tried hard to use bio, but offsety readdir can't be handled
     * properly that way -- the offset field of fuse_dirents can't be
     * mapped to an offset of a bio buffer
     */
    err = fuse_read_directbackend(&fioda);

    fiov_teardown(&cookediov);
    fufh->useco--;
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
    int err;
    struct vnode *vp = ap->a_vp;
    struct uio *uio = ap->a_uio;
    struct fuse_dispatcher fdi;

    fuse_trace_printf_vnop();

    if ((err = fdisp_simple_putget(&fdi, FUSE_READLINK, vp, curthread,
        ap->a_cred)))
            return (err);

    if (((char *)fdi.answ)[0] == '/' &&
        fusefs_get_data(vp->v_mount)->dataflag & FSESS_PUSH_SYMLINKS_IN) {
        char *mpth = vp->v_mount->mnt_stat.f_mntonname;

        err = uiomove(mpth, strlen(mpth), uio);
    }

    if (!err) {
        err = uiomove(fdi.answ, fdi.iosize, uio);
    }

    fuse_ticket_drop(fdi.tick);
    fuse_invalidate_attr(vp);

    return (err);
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
    struct vnode *vp = ap->a_vp;
    struct thread *td = ap->a_td;

    DEBUG("pfft...\n");
#if _DEBUG
    DEBUG2G("=============>\n");
    kdb_backtrace();
    vn_printf(vp, " ");
    DEBUG2G("<=============\n");
#endif
    vnode_destroy_vobject(vp);
    return (fuse_recyc_backend(vp, td));
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
    struct vnode *dvp = ap->a_dvp;
    struct vnode *vp = ap->a_vp;
    struct componentname *cnp = ap->a_cnp;

    return (fuse_internal_remove(dvp, vp, cnp, FUSE_UNLINK));
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
	struct vnode *tvp = ap->a_tvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *fdvp = ap->a_fdvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;

	int doingdirectory = 0;
	int err = 0;
	struct thread *td;
	struct fuse_access_param facp;
	uint64_t fnid, tdnid;
	struct fuse_data *data = NULL;
	struct parentmanager_param pmp;
	struct vnode *xvp;

	td = curthread;
	bzero(&facp, sizeof(facp));

	/*
	 * Check for cross-device rename.
	 */
	if (fvp->v_mount != tdvp->v_mount ||
	    (tvp && fvp->v_mount != tvp->v_mount)) {
		DEBUG("cross-device move. Why am I expected to deal with it?!\n");
		err = EXDEV;
		goto out;
	}

	/*
	 * To ensure consistent view upon walking the vnode tree,
	 * we let only one rename op at a time.
	 * (FYI: Linux does this at the VFS level, BSDs usually
	 * go for more fine grained solutions. Now it's good enough
	 * for us.)
	 *
	 * Although we want to guarantee exclusive access for the lock holder,
	 * we use an sx lock instead of a mutex, because it lets us sleep
	 * while we are holding the lock.
	 */
	data = fusefs_get_data(tdvp->v_mount);
	sx_xlock(&data->rename_lock);

	/*
	 * Check if just deleting a link name.
	 */
	if (fvp == tvp) {
		if (fvp->v_type == VDIR) {
			err = EINVAL;
			goto out;
		}

		sx_unlock(&data->rename_lock);

		/*
		 * Release destination.
		 */
		vput(tdvp);
		vput(tvp);

		/*
		 * Delete source. Pretty bizarre stuff.
		 */
		vrele(fdvp);
		vrele(fvp);
		fcnp->cn_flags &= ~MODMASK;
		fcnp->cn_flags |= LOCKPARENT | LOCKLEAF;
		fcnp->cn_nameiop = DELETE;
		VREF(fdvp);
		err = relookup(fdvp, &fvp, fcnp);
		if (err == 0)
			vrele(fdvp);

		return VOP_REMOVE(fdvp, fvp, fcnp);
	}

	/*
	 * No LK_RETRY. See discussion in thread
	 * http://thread.gmane.org/gmane.os.dragonfly-bsd.kernel/8952/focus=8964
	 */
	err = vn_lock(fvp, LK_EXCLUSIVE);
	if (err)
		goto out;

	if (fvp->v_type == VDIR) {
		/*
		 * Avoid ".", "..", and aliases of "." for obvious reasons.
		 */
		if ((fcnp->cn_namelen == 1 && fcnp->cn_nameptr[0] == '.')
			|| fdvp == fvp
			|| ((fcnp->cn_flags | tcnp->cn_flags) & ISDOTDOT)) {
			VOP_UNLOCK(fvp, 0);
			err = EINVAL;
			goto out;
		}
		doingdirectory = 1;
	}
	/* vrele(fdvp);  ???? */

	/*
	 * If ".." must be changed (ie the directory gets a new
	 * parent) then the source directory must not be in the
	 * directory hierarchy above the target, as this would
	 * orphan everything below the source directory. Also
	 * the user must have write permission in the source so
	 * as to be able to change "..".
	 */
	err = fuse_internal_access(fvp, VWRITE, tcnp->cn_cred, tcnp->cn_thread, &facp);
	fnid = VTOI(fvp);
	VOP_UNLOCK(fvp, 0
	           );
	if (err)
		goto out;

	if (doingdirectory && fdvp != tdvp) {
		/*
		 * Check for pathname conflict.
		 *
		 * That is, moved vnode should not be over target and
		 * if target is in an isolated subtree, target and source
		 * should be in the same subtree.
		 */

		int isolated = 0;
		uint64_t trootid = 0;

		pmp.nodeid = VTOI(tdvp);
climbup:
		if (isolated)
			/* Climbing up again, this time from fvp */
			pmp.nodeid = fnid;
	
		for (;;) {
			if (! isolated && pmp.nodeid == fnid) {
				/* target is above source, bail out */
				err = EINVAL;
				goto out;
			}

			if (pmp.nodeid == FUSE_ROOT_ID)
				/*
				 * we successfully arrived to the top,
				 * life can go on
				 */
				break;

			/* fetching parent info via abusing vfs_hash_get */
			pmp.valid = 0;
			err = vfs_hash_get(fvp->v_mount, pmp.nodeid, 0, td, &xvp,
			                   fuse_vnode_findparent_cmp, &pmp);
			KASSERT(xvp == NULL, ("findparent routine has fetched a vnode"));
			if (err)
				goto out;

			if (! pmp.valid)
				/*
				 * No valid parent found, we are in an isolated
				 * subtree.
				 */
				break;

			pmp.nodeid = pmp.parent_nid;
		}

		if (isolated) {
			/*
			 * Second climbup completed,
			 * let's see if local roots match...
			 */
			if (trootid != pmp.nodeid) {
				err = EINVAL;
				goto out;
			}
		} else if (! pmp.valid) {
			/*
			 * ... we are isolated: in this case we require that
			 * target and source lives in the same subtree.
			 * To see that, we'll have to climb up also from fvp.
			 */

			isolated = 1;
			trootid = pmp.nodeid;

			goto climbup;
		}
	}

	/*
	 * If the target doesn't exist, link the target to the source and
	 * unlink the source. Otherwise, rewrite the target directory to
	 * reference the source and remove the original entry.
	 */
	if (tvp) {
		/*
		 * Target must be empty if a directory and have no links
		 * to it. Also, ensure source and target are compatible
		 * (both directories, or both not directories).
		 */
		if (tvp->v_type == VDIR) {
			/*
			 * "not empty" misery is handled by the fine daemon
			 * (in nulix too)
			 */
			if (!doingdirectory) {
				err = ENOTDIR;
				goto out;
			}
			/*
			 * Update name cache since directory is going away.
			 */
			/* cache_purge(tdvp); */
		} else if (doingdirectory) {
			err = ENOTDIR;
			goto out;
		}

	}

/* Fuse-specific code */

	if ((err = fuse_internal_rename(fdvp, fcnp, tdvp, tcnp)))
		goto out;

	
out:
	tdnid = VTOI(tdvp);
	if (tdvp == tvp)
		vrele(tdvp);
	else
		vput(tdvp);
	if (tvp)
		vput(tvp);
	vrele(fdvp);
	if (! err) {
		/* Adjusting parent field via VFS hash API */
		pmp.nodeid = VTOI(fvp);
		pmp.parent_nid = tdnid;
		pmp.valid = 0;
		err = vfs_hash_get(fvp->v_mount, pmp.nodeid, 0, td, &xvp,
			           fuse_vnode_setparent_cmp, &pmp);
		KASSERT(xvp == NULL, ("findparent routine has fetched a vnode"));
	}
	vrele(fvp);
	if (data)
		sx_xunlock(&data->rename_lock);
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
	struct vnode *vp = ap->a_vp;

	int err;
	struct vnode *xvp;
	struct parentmanager_param pmp;

	err = fuse_internal_remove(ap->a_dvp, vp, ap->a_cnp, FUSE_RMDIR);
	if (err)
		return (err);

	/*
	 * Resetting parent field via VFS hash API so
	 * that the nodeid of this directory can be
	 * reused
	 */
	pmp.nodeid = VTOI(vp);
	pmp.parent_nid = 0;
	pmp.valid = 0;
	err = vfs_hash_get(vp->v_mount, pmp.nodeid, 0, curthread, &xvp,
		           fuse_vnode_setparent_cmp, &pmp);
	KASSERT(xvp == NULL, ("findparent routine has fetched a vnode"));

	return err;
}

static int
fuse_recyc_backend(struct vnode *vp, struct thread *td)
{
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	struct fuse_release_param frp;

	if (! fvdat) {
		DEBUG("got a dataless node\n");
		return (0);
	}

	DEBUG("getting at vnode of ino %llu\n", VTOILLU(vp));
	ASSERT_VOP_ELOCKED(vp, "recycling unlocked vnode");

	ASSERT_VOP_ELOCKED__FH(vp);
	iterate_filehandles(vp, td, NULL, fuse_file_ditch, NULL);
	/*
	 * Sometimes the FORGET message sent below used to hit the target
	 * _sooner_ than the RELEASE-s sent here, and the daemon wasn't
	 * particularly happy about that.
	 *
	 * So now we just peacefully sit here and wait for the answer before
	 * goin' on.
	 */
	frp.fg = 1;
	frp.flush = 0;
	iterate_filehandles(vp, td, NULL, release_filehandle, &frp);

	if (! (vp->v_vflag & VV_ROOT)) {
		if (fvdat->nid != FUSE_NULL_ID)
			vfs_hash_remove(vp);

		if (fvdat->nlookup) {
			struct fuse_dispatcher fdi;

			fdi.tick = NULL;
			/*
			 * sending a FORGET is just courtesy toward the daemon
			 * (who might as well be as dead as a stone at this
			 * point), so we don't care a damned shit about it if
			 * something woes during this action.
			 */
			fuse_internal_forget_send(vp->v_mount, td, NULL, VTOI(vp),
			                 fvdat->nlookup, &fdi);
		}
	}
	vp->v_data = NULL;

	/*
	 * Taking down fuse_vnode_data structures is just hooked in here...
	 * no separate destructor.
	 */
	free(fvdat, M_FUSEVN);

	/* XXX what does it mean exactly to return a non-zero value from here? */
	return (0);
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
    struct vattr *vap = ap->a_vap;
    struct vnode *vp = ap->a_vp;
    struct ucred *cred = ap->a_cred;
    struct thread *td = curthread;
    int err = 0;
    struct fuse_dispatcher fdi;
    struct fuse_setattr_in *fsai;
    enum vtype vtyp;
    struct fuse_access_param facp;
    
    /*
     * Check for unsettable attributes.
     */
    if ((vap->va_type != VNON) || (vap->va_nlink != VNOVAL) ||
        (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
        (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
        ((int)vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL))
        return (EINVAL);
    if (vap->va_flags != VNOVAL)
        return (EOPNOTSUPP);

    fdisp_init(&fdi, sizeof(*fsai));
    fdisp_make_vp(&fdi, FUSE_SETATTR, vp, td, cred);
    fsai = fdi.indata;
    KASSERT(isbzero(fsai, sizeof(*fsai)), ("non-clean buffer passed to setattr"));
    bzero(&facp, sizeof(facp));

#if FUSE_KERNELABI_GEQ(7, 3)
#define FUSEATTR(x) x
#else
#define FUSEATTR(x) attr.x
#endif 

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
        fsai->FUSEATTR(size) = vap->va_size;
        fsai->valid |= FATTR_SIZE;	
    }

    if (vap->va_mode != (mode_t)VNOVAL) {
#if _DEBUG
        if (vap->va_mode & S_IFMT)
                DEBUG("fuse_setattr -- weird: "
                      "format bits in mode field, 0%o\n",
                      vap->va_mode);
#endif
        if (vap->va_mode & S_ISGID)
                facp.facc_flags |= FACCESS_SETGID;
        fsai->FUSEATTR(mode) = vap->va_mode & ALLPERMS;
        fsai->valid |= FATTR_MODE;
    }

    /* XXX: fuse code says, the (atime, mtime) pair should be set
     * atomically. On the contrary, BSD code doesn't seem to care
     * about such a constraint. Is this a fuseism or a linuxism?
     * Should we enforce the constraint?
     */
    if (vap->va_atime.tv_sec != VNOVAL) {
        /* XXX on some platforms 32 -> bits cast ? */
        fsai->FUSEATTR(atime) = vap->va_atime.tv_sec;
        fsai->FUSEATTR(atimensec) = vap->va_atime.tv_nsec;
        fsai->valid |=  FATTR_ATIME;
    }

    if (vap->va_mtime.tv_sec != VNOVAL) {
        fsai->FUSEATTR(mtime) = vap->va_mtime.tv_sec;
        fsai->FUSEATTR(mtimensec) = vap->va_mtime.tv_nsec;
        fsai->valid |=  FATTR_MTIME;
    }

#undef FUSEATTR

    if (!fsai->valid)
        goto out;

    if (fsai->valid & FATTR_SIZE && vp->v_type == VDIR) {
        err = EISDIR;
        goto out;
    }

    if (vp->v_mount->mnt_flag & MNT_RDONLY &&
        (fsai->valid & ~FATTR_SIZE || vp->v_type == VREG)) {
            err = EROFS;
            goto out;
    }

    if (fsai->valid & ~FATTR_SIZE) {
            err = fuse_internal_access(vp, VADMIN, cred, td, &facp);
    }

    facp.facc_flags &= ~FACCESS_XQUERIES;

    /*
     * If we set the times and nothing else, we get one more choice,
     * as the quoted ufs_setattr comment explains...
     */

    /*
     * From utimes(2):
     * If times is NULL, ... The caller must be the owner of
     * the file, have permission to write the file, or be the
     * super-user.
     * If times is non-NULL, ... The caller must be the owner of
     * the file or be the super-user.
     */
    if (err && ! (fsai->valid & ~(FATTR_ATIME | FATTR_MTIME)) &&
        vap->va_vaflags & VA_UTIMES_NULL)
            err = fuse_internal_access(vp, VWRITE, cred, td, &facp);

    if (err) {
        fuse_invalidate_attr(vp);
        goto out;
    }

    if ((err = fdisp_wait_answ(&fdi))) {
        fuse_invalidate_attr(vp);
        return (err);
    }

    vtyp = IFTOVT(((struct fuse_attr_out *)fdi.answ)->attr.mode);

    if (vp->v_type != vtyp) {
        if (vp->v_type == VNON && vtyp != VNON) {
            DEBUG2G("vnode #%llu with no type\n", VTOILLU(vp));
            vp->v_type = vtyp;
        } else {
            fuse_vnode_ditch(vp, td);
            err = ENOTCONN;
            goto out;
        }
    }

    cache_attrs(vp, (struct fuse_attr_out *)fdi.answ);

out:
    fuse_ticket_drop(fdi.tick);

    return (err);
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
	(void)fuse_strategy_i(ap->a_vp, ap->a_bp, NULL, 0);

	/* 
	 * This is a dangerous function. If returns error, that might mean a
	 * panic. We prefer pretty much anything over being forced to panic by
	 * a malicious daemon (a demon?). So we just return 0 anyway. You
	 * should never mind this: this function has its own error propagation
	 * mechanism via the argument buffer, so not-that-melodramatic
	 * residents of the call chain still will be able to know what to do.
	 */
	return (0);
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
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	char *target = ap->a_target;

	struct fuse_dispatcher fdi;
	size_t len;
	int err;

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
	return (err);
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
	struct vnode *vp = ap->a_vp;
	struct ucred *cred = ap->a_cred;
	struct uio *uio = ap->a_uio;
	int ioflag = ap->a_ioflag;

	DEBUG2G("vnode #%llu\n", VTOILLU(vp));
	return fuse_io_vnode(vp, cred, uio, ioflag);
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

	error = fuse_io_dispatch(vp, NULL, &uio, cred, FREAD | O_DIRECT, td);
#else
	error = fuse_strategy_i(vp, bp, NULL, 0);
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

	error = fuse_io_dispatch(vp, NULL, &uio, cred, FWRITE | O_DIRECT, td);
#else
	error = fuse_strategy_i(vp, bp, NULL, 0);
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

	printf("nodeid: %llu, parent_nid: %llu, fh_counter: %d, "
	       "nlookup: %llu, flags: %#x\n",
	       VTOILLU(ap->a_vp), (unsigned long long) fvdat->parent_nid,
	       fvdat->fh_counter, (unsigned long long)fvdat->nlookup,
	       fvdat->flags);

	return (0);
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
