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

/* function prototype for iterators over filehandles (of a vp) */
typedef int fuse_metrics_t(struct fuse_filehandle *fufh, struct thread *td,
                           struct ucred *cred, void *param);


/* parameter struct for fuse_standard_metrics() */
struct standard_metrics_param {
	int mode;
	enum fuse_opcode op;
	struct fuse_filehandle *fufh;
};

struct fuse_release_param {
	int err;
	uint8_t fg:1;
	uint8_t flush:1;
};

#if FUSE_HAS_CREATE
struct fuse_pidcred {
	pid_t pid;
	struct ucred cred;
};
#endif

static void             fuse_send_forget_pid(struct mount *mp, pid_t pid,
                                             struct ucred *cred, uint64_t nodeid,
                                             uint64_t nlookup,
                                             struct fuse_dispatcher *fdip);
static void             fuse_send_forget(struct mount *mp, struct thread *td,
                                         struct ucred *cred, uint64_t nodeid,
                                         uint64_t nlookup,
                                         struct fuse_dispatcher *fdip);
static __inline void    fuse_vnode_init_data(struct vnode *vp, struct fuse_vnode_data *fvdat,
                                             uint64_t nodeid);
static __inline void    fuse_vnode_init_misc(struct vnode *vp, enum vtype vtyp,
                                             uint64_t parentid);
static __inline void    fat2vat(struct mount *mp, struct fuse_attr *fat,
                                struct vattr *vap);
static __inline int     fuse_match_cred(struct ucred *daemoncred,
                                        struct ucred *usercred);
static __inline int     fuse_check_spyable(struct fuse_dispatcher *fdip,
                                           struct mount *mp, struct thread *td,
                                           struct ucred *cred);
static int              fuse_recyc_backend(struct vnode *vp, struct thread *td);
static void             fuse_filehandle_gc(struct vnode *vp, struct thread *td,
                                           struct ucred *cred,
                                           struct fuse_release_param *frp);
static int              fuse_access_i(struct vnode *vp, mode_t mode,
                                      struct ucred *cred, struct thread *td,
                                      struct fuse_access_param *facp);
static int              iterate_filehandles(struct vnode *vp, struct thread *td,
                                            struct ucred *cred,
                                            fuse_metrics_t fmetr, void *param);
#if FUSE_HAS_CREATE
static __inline int     create_filehandle(struct vnode *vp, struct thread *td,
                                          struct ucred *cred, int mode,
                                          struct fuse_dispatcher *fdip);
#endif
static void             fuse_send_release(struct fuse_filehandle *fufh,
                                          struct thread *td, struct ucred *cred,
                                          int flags,
                                          struct fuse_release_param *frp);
static int              fuse_newentry_backend(struct vnode *dvp,
                                              struct vnode **vpp,
                                              struct componentname *cnp,
                                              enum fuse_opcode op, void *buf,
                                              size_t bufsize, enum vtype vtyp);
static __inline void    fuse_make_entry_req(struct mount *mp, uint64_t dnid,
                                            struct componentname *cnp,
                                            enum fuse_opcode op, void *buf,
                                            size_t bufsize,
                                            struct fuse_dispatcher *fdip);
static __inline int     checkentry(struct fuse_entry_out *feo, enum vtype vtyp);
static __inline int     fuse_newentry_core(struct vnode *dvp, struct vnode **vpp,
                                           enum vtype vtyp,
                                           struct fuse_dispatcher *fdip);
static __inline int     fuse_remove_backend(struct vnode *dvp,
                                            struct vnode *vp,
                                            struct componentname *cnp,
                                            enum fuse_opcode op);
static __inline int     fuse_rename_core(struct vnode *fdvp,
                                         struct componentname *fcnp,
                                         struct vnode *tdvp,
                                         struct componentname *tcnp);

extern int              fuse_read_directbackend(struct fuse_io_data *fioda);

static fuse_buffeater_t fuse_dir_buffeater;

static fuse_handler_t		 fuse_fsync_handler;
#if FUSE_HAS_CREATE
static fuse_handler_t		 fuse_forgetful_handler;
#endif

static fuse_metrics_t fuse_file_ditch;
static fuse_metrics_t fuse_standard_metrics;
static fuse_metrics_t fuse_fsync_filehandle;
static fuse_metrics_t release_filehandle;

#if FUSE_HAS_CREATE
static vfs_hash_cmp_t fuse_vnode_fgdrop_cmp;
#endif
static vfs_hash_cmp_t fuse_vnode_findparent_cmp;

/* file ops */
static fo_close_t fuse_close_f;

/* vnode ops */
static vop_getattr_t  fuse_getattr;
static vop_reclaim_t  fuse_reclaim;
static vop_inactive_t fuse_inactive;
static vop_access_t   fuse_access;
static vop_lookup_t   fuse_lookup;
static vop_open_t     fuse_open;
static vop_close_t    fuse_close;
static vop_read_t     fuse_read;
static vop_readdir_t  fuse_readdir;
static vop_readlink_t fuse_readlink;
static vop_mknod_t    fuse_mknod;
static vop_create_t   fuse_create;
static vop_mkdir_t    fuse_mkdir;
static vop_link_t     fuse_link;
static vop_symlink_t  fuse_symlink;
static vop_remove_t   fuse_remove;
static vop_rmdir_t    fuse_rmdir;
static vop_rename_t   fuse_rename;
static vop_setattr_t  fuse_setattr;
static vop_fsync_t    fuse_fsync;
static vop_write_t    fuse_write;
static vop_strategy_t fuse_strategy;
static vop_getpages_t fuse_getpages;
static vop_putpages_t fuse_putpages;
static vop_print_t    fuse_print;
static vop_unlock_t   fuse_unlock;

#if FUSE_HAS_CREATE
vop_access_t fuse_germ_access;
#endif

struct fileops fuse_fileops = {
	.fo_read     = fuse_io_file,
	.fo_write    = fuse_io_file,
	/*
         * following fields are filled from vnops, but "vnops.foo" is not
         * legitimate in a definition, so we set them at module load time
	 */
	.fo_ioctl    = NULL,
	.fo_poll     = NULL,
	.fo_kqfilter = NULL,
	.fo_stat     = NULL,
	.fo_close    = fuse_close_f,
	.fo_flags    = DFLAG_PASSABLE | DFLAG_SEEKABLE
};

struct vop_vector fuse_vnops = {
	.vop_default       = &default_vnodeops,
	.vop_inactive      = fuse_inactive,
	.vop_reclaim       = fuse_reclaim,
	.vop_getattr       = fuse_getattr,
	.vop_access        = fuse_access,
	.vop_lookup        = fuse_lookup,
	.vop_pathconf      = vop_stdpathconf,
	.vop_open          = fuse_open,
	.vop_close         = fuse_close,
	.vop_read          = fuse_read,
	.vop_write         = fuse_write,
	.vop_readdir       = fuse_readdir,
	.vop_readlink      = fuse_readlink,
	.vop_mknod         = fuse_mknod,
	.vop_create        = fuse_create,
	.vop_mkdir         = fuse_mkdir,
	.vop_link          = fuse_link,
	.vop_symlink       = fuse_symlink,
	.vop_remove        = fuse_remove,
	.vop_rmdir         = fuse_rmdir,
	.vop_rename        = fuse_rename,
	.vop_setattr       = fuse_setattr,
	.vop_fsync         = fuse_fsync,
	.vop_strategy      = fuse_strategy,
	.vop_getpages      = fuse_getpages,
	.vop_putpages      = fuse_putpages,
	.vop_print         = fuse_print,
	.vop_unlock        = fuse_unlock,
};

#if FUSE_HAS_CREATE
struct vop_vector fuse_germ_vnops;
#endif

MALLOC_DEFINE(M_FUSEVN, "fuse_vnode", "fuse vnode private data");
MALLOC_DEFINE(M_FUSEFH, "fuse_filehandles", "buffer for fuse filehandles");

int fuse_pbuf_freecnt = -1;

/********************
 *
 * >>> Vnode related callback handlers
 *
 ********************/

static int
fuse_fsync_handler(struct fuse_ticket *tick, struct uio *uio)
{
	if (tick->tk_aw_ohead.error == ENOSYS)
		tick->tk_data->dataflag |=
	         fticket_opcode(tick) == FUSE_FSYNC ?
		 FSESS_NOFSYNC : FSESS_NOFSYNCDIR;

	fuse_ticket_drop(tick);
	return (0);
}

#if FUSE_HAS_CREATE
static int
fuse_forgetful_handler(struct fuse_ticket *tick, struct uio *uio)
{
	struct fuse_dispatcher fdi;
	struct fuse_pidcred *pidcred;

	/*
	 * XXX I think I'm right to send a forget regardless of possible
	 * errors, but...
	 */

	fdi.tick = tick;
	pidcred = tick->tk_aw_handler_parm.base;

	fuse_send_forget_pid(tick->tk_data->mp, pidcred->pid, &pidcred->cred,
	           ((struct fuse_in_header *)tick->tk_ms_fiov.base)->nodeid,
	           1, &fdi);

	return (0);
}
#endif

/******************
 *
 * >>> VFS hash comparators
 *
 ******************/

#if FUSE_HAS_CREATE
/*
 * Vnode comparison function with which the given vnode always
 * gets inserted, but got marked invalid upon a clash. Caller
 * is free (and expected to) deal with clashes.
 */

int
fuse_vnode_fgdrop_cmp(struct vnode *vp, void *param)
{
	struct fuse_vnode_data *fvdat = param;

	if (VTOI(vp) == fvdat->nid)
		fvdat->nid = FUSE_NULL_ID;

	return (1);
}
#endif

/*
 * A skewed use of the vfs hash subsystem for finding out parent
 * nodeid. This comparator never matches, just collects data during
 * scanning through the nodes (without vnode locking).
 */

static int
fuse_vnode_findparent_cmp(struct vnode *vp, void *param)
{
	struct parentmanager_param *pmp = param;

	/*
	 * In general, we'd need a (nodeid, vtyp) pair to match
	 * but we may assume that the type is directory, because
	 * that's what users of this function will want.
	 */

	if (VTOI(vp) == pmp->nodeid && vp->v_type == VDIR) {
		KASSERT(! pmp->valid,
		        ("more than one vnode seems to match #%llu",
			 (unsigned long long)pmp->nodeid));
		pmp->parent_nid = VTOFUD(vp)->parent_nid;
		pmp->valid = 1;
	}

	return (1);
}

/******************
 *
 * >>> Vnode related aux routines
 *
 ******************/

static __inline void
__fuse_send_forget_pid(struct mount *mp, pid_t pid, struct ucred *cred,
                       uint64_t nodeid, uint64_t nlookup,
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

static void
fuse_send_forget_pid(struct mount *mp, pid_t pid, struct ucred *cred,
                     uint64_t nodeid, uint64_t nlookup,
                     struct fuse_dispatcher *fdip)
{
	return (__fuse_send_forget_pid(mp, pid, cred, nodeid, nlookup, fdip));
}

static void
fuse_send_forget(struct mount *mp, struct thread *td, struct ucred *cred,
                 uint64_t nodeid, uint64_t nlookup,
                 struct fuse_dispatcher *fdip)
{
	RECTIFY_TDCR(td, cred);
	return (__fuse_send_forget_pid(mp, td->td_proc->p_pid, cred, nodeid,
	                               nlookup, fdip));
}

static __inline void
fuse_vnode_init_data(struct vnode *vp, struct fuse_vnode_data *fvdat,
                     uint64_t nodeid)
{
	fvdat->nid = nodeid;
	vp->v_data = fvdat;
}

static __inline void
fuse_vnode_init_misc(struct vnode *vp, enum vtype vtyp, uint64_t parentid)
{
	struct fuse_vnode_data *fvdat = VTOFUD(vp);

	VNASSERT(fvdat, vp, (("init_misc on virgin vnode"))); 

	fvdat->parent_nid = parentid;
	vp->v_type = vtyp;

	LIST_INIT(&fvdat->fh_head);

	vp->v_bufobj.bo_private = vp;
}	

void
fuse_vnode_init(struct vnode *vp, struct fuse_vnode_data *fvdat,
                uint64_t nodeid, enum vtype vtyp, uint64_t parentid)
{
	fuse_vnode_init_data(vp, fvdat, nodeid);
	fuse_vnode_init_misc(vp, vtyp, parentid);
}	

void
fuse_vnode_ditch(struct vnode *vp, struct thread *td)
{
	if (! td)
		td = curthread;

	if (vp->v_vflag & VV_ROOT) {
		fdata_kick_set(fusefs_get_data(vp->v_mount));
		return;
	}
	DEBUG2G("vp %p, #%llu\n", vp, VTOILLU(vp));
	vnode_destroy_vobject(vp);
	/*
	 * this implies we won't get feedback on recycling
	 * (other than panicking, or the lack of that)
	 * but creating a customized set of bad vnode ops
	 * would be too much hassle...
	 */
	vp->v_op = &dead_vnodeops;
	fuse_recyc_backend(vp, td);
}

void
fuse_vnode_teardown(struct vnode *vp, struct thread *td, struct ucred *cred,
                 enum vtype vtyp)
{
	struct fuse_dispatcher fdi;
	struct fuse_vnode_data *fvdat = VTOFUD(vp);

	if (vp->v_type == vtyp) {
		bzero(&fdi, sizeof(fdi));
		vfs_hash_remove(vp);
		fuse_send_forget(vp->v_mount, td, cred, fvdat->nid,
		                 fvdat->nlookup, &fdi);
		fvdat->nid = FUSE_NULL_ID;
	} else
		fuse_vnode_ditch(vp, td);

	vput(vp);
}

static int
fuse_file_ditch(struct fuse_filehandle *fufh, struct thread *td,
                struct ucred *cred, void *param)
{
	if (fufh->fp) {
		fufh->fp->f_ops = &vnops;
		fufh->fp->f_data = NULL;
		fufh->fp = NULL;
	}
	fufh->useco = 0;

	return (0);
}

/******************
 *
 * >>> Vnode ops and their helpers
 *
 ******************/

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
			fuse_send_forget(vp->v_mount, td, NULL, VTOI(vp),
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

static int
release_filehandle(struct fuse_filehandle *fufh, struct thread *td,
                   struct ucred *cred, void *param)
{
	KASSERT(fufh->useco >= 0,
	        ("negative use count for fuse filehandle #%llu@#%llu",
	         (long long unsigned)fufh->fh_id, VTOILLU(fufh->fh_vp)));
	KASSERT(! fufh->fp || fufh->useco > 0,
	        ("filehandle bound with 0 use counter"));
	DEBUG2G("vnode #%llu, fufh %p #%llu, owner file %p, useco %d\n",
	        VTOILLU(fufh->fh_vp), fufh, (long long unsigned) fufh->fh_id,
	        fufh->fp, fufh->useco);
	if (! fufh->fp && fufh->useco == 0) {
		LIST_REMOVE(fufh, fh_link);
		fuse_send_release(fufh, td, cred, fufh->mode, param);
	}

	return (0);		
}

static void
fuse_filehandle_gc(struct vnode *vp, struct thread *td, struct ucred *cred,
                   struct fuse_release_param *frp)
{
	ASSERT_VOP_ELOCKED__FH(vp);
	iterate_filehandles(vp, td, cred, release_filehandle, frp);
}

static int
fuse_reclaim(ap)
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
		struct thread *a_td;
	} */ *ap;
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

static int
fuse_inactive(ap)
	struct vop_inactive_args /* {
		struct vnode *a_vp;
		struct thread *a_td;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;	
	struct thread *td = ap->a_td;

	int err;

	DEBUG("getting at vnode of ino %llu\n", VTOILLU(vp));
#if _DEBUG
	DEBUG2G("=============>\n");
	kdb_backtrace();
	vn_printf(vp, " ");
	DEBUG2G("<=============\n");
#endif

	{
		struct fuse_release_param frp;

		frp.fg = 0;
		frp.flush = 0;
		fuse_filehandle_gc(vp, td, NULL, &frp);
	}

#ifndef DONT_STORE_FS_MAP
	/*
	 * Dropping vnodes when they are not in use would mean that
	 * the respective inode must be freed on the daemon's side
	 * (this is ia necessity according to the protocol: if
	 * we drop the vnode, then we lose the associated nlookup
	 * value, which is required to be kept during the lifetime of
	 * the inode, as at the end of the inode's lifetime this info
	 * is required for properly killing it (cf. forget_node() of 
	 * lib/fuse.c and the assertion in it), that is, the inode
	 * can't be kept alive further than the vnode).
	 *
	 * So either we aggressively kill both kind of beasts and don't
	 * store permanently a "map" of the fs (thus, eg, same files
	 * pop up with different inode numbers upon different lookups, 
	 * which is weird), or we keep them both and don't do anything when 
	 * the vnode usecount falls to zero (ie. use a peaceful vop_inactive
	 * which throws away only rotten vegetables).
	 *
	 * The latter approach seems to be the better, partly because of
	 * the above mentioned weirdness, but mostly because fs ops done
	 * by the daemon are considered expensive.
	 * 
	 * [To add, all this reasoning doesn't imply I understand the 
	 * reason for the enforcement of the thigt synchronization
	 * between in-kernel vnodes and userspace inodes.]
	 */
	if (VTOFUD(vp))
		return (0);
#endif

	if ((err = fuse_recyc_backend(vp, td)))
		return err;

	vrecycle(vp, td);

	return (0);
}

/*
 *  It's by-and-large reversing vn_stat() of kern/vfs_vnops.c
 */

static __inline void
fat2vat(struct mount *mp, struct fuse_attr *fat, struct vattr *vap)
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

#define cache_attrs(vp, fuse_out) do {					      \
	struct timespec uptsp_ ## __func__;				      \
									      \
	VTOFUD(vp)->cached_attrs_valid.tv_sec = (fuse_out)->attr_valid;	      \
	VTOFUD(vp)->cached_attrs_valid.tv_nsec = (fuse_out)->attr_valid_nsec; \
	nanouptime(&uptsp_ ## __func__);				      \
									      \
	DEBUG("cached attrs for vp #%llu: timo s %d ns %ld\n", VTOILLU(vp), \
              VTOFUD(vp)->cached_attrs_valid.tv_sec,			      \
              VTOFUD(vp)->cached_attrs_valid.tv_nsec);		      \
	timespecadd(&VTOFUD(vp)->cached_attrs_valid, &uptsp_ ## __func__);    \
									      \
	fat2vat((vp)->v_mount, &(fuse_out)->attr, VTOVA(vp));		      \
} while (0)

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

static int
fuse_getattr(ap)
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
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
	vap->va_type = vp->v_type;

	return (0);
}

static int
fuse_access(ap)
	struct vop_access_args /* {
		struct vnode *a_vp;
#if VOP_ACCESS_TAKES_ACCMODE_T
		accmode_t a_accmode;
#else
		int a_mode;
#endif
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct fuse_access_param facp;
	struct fuse_vnode_data *fvdat = VTOFUD(vp);

	bzero(&facp, sizeof(facp));
	if (fvdat->flags & FVP_ACCESS_NOOP)
		fvdat->flags &= ~FVP_ACCESS_NOOP;
	else
		facp.facc_flags |= FACCESS_DO_ACCESS;

	return fuse_access_i(vp, ap->a_accmode,
	    ap->a_cred, ap->a_td, &facp);
}

/*
 * Attribute caching hasn't yet been implemented.
 * [... Update: it _has been_ implemented.]
 * However, within one function we don't wanna query attributes
 * several times. Now it's enough pull the attributes once, and throw
 * it into the following routine with various modes.
 */

static int
fuse_access_i(struct vnode *vp, mode_t mode, struct ucred *cred, struct thread *td,
              struct fuse_access_param *facp)
{
	struct fuse_dispatcher fdi;
	int err = 0;

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
 * Based on sample code of VOP_LOOKUP(9), reiserfs_lookup()
 * of gnu/fs/reiserfs/reiserfs_namei.c  and vfs_cache_lookup()
 */

int
fuse_lookup(ap)
	struct vop_lookup_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{
        struct vnode *dvp         = ap->a_dvp;
        struct vnode **vpp        = ap->a_vpp;
        struct componentname *cnp = ap->a_cnp;
	int nameiop = cnp->cn_nameiop;
	struct thread *td = cnp->cn_thread;
	struct ucred *cred = cnp->cn_cred;
	int flags = cnp->cn_flags;
	int wantparent = flags & WANTPARENT;
	int islastcn = flags & ISLASTCN;

	int err = 0;
	int lookup_err = 0;
	struct vnode *vp = NULL;
	struct fuse_dispatcher fdi;
	struct fuse_attr *fattr = NULL;
	enum fuse_opcode op;
	uint64_t nid;
	uint64_t parentid;
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
		DEBUG("vnode #%llu of vtype %d is not a dir\n", VTOILLU(dvp),
		      dvp->v_type); 
		return (ENOTDIR);
	}

	if (islastcn && (dvp->v_mount->mnt_flag & MNT_RDONLY) &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME))
		return (EROFS);

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
		if ((err = fuse_access_i(dvp, VEXEC, cred, td, &facp)))
			return (err);
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

	if (op == FUSE_LOOKUP && ! lookup_err) {
		nid = ((struct fuse_entry_out *)fdi.answ)->nodeid;
		if (! nid) {
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
	     (! fdi.answ_stat) || /* this means messaging error */
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
			
			if ((err = fuse_access_i(dvp, VWRITE, cred, td, &facp)))
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
		if (op == FUSE_GETATTR)
			fattr = &((struct fuse_attr_out *)fdi.answ)->attr;
		else
			fattr = &((struct fuse_entry_out *)fdi.answ)->attr;

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
			err = fuse_access_i(dvp, VWRITE, cred, td, &facp);
			facp.facc_flags &= ~FACCESS_XQUERIES;

			if (err)
				goto out;

			if (nid == VTOI(dvp)) {
				VREF(dvp);
				*vpp = dvp;
				goto out;
			}

			err = fuse_vget_i(dvp->v_mount, td, nid,
			                  IFTOVT(fattr->mode), &vp, VG_NORMAL,
                                          parentid);
			if (err)
				goto out;
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
			err = fuse_access_i(dvp, VWRITE, cred, td, &facp);
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
	if (! lookup_err) {
		DEBUG("as the looked up thing was simply found, the cleanup is left for us\n");

		if (err) {
			DEBUG("though inode found, err exit with no vnode\n");
			if (op == FUSE_LOOKUP)
				fuse_send_forget(dvp->v_mount, td, cred, nid, 1,
				                 &fdi);
			return (err);
		} else {
			if (op == FUSE_LOOKUP)
				VTOFUD(*vpp)->nlookup++;

			if (islastcn && flags & ISOPEN)
				VTOFUD(*vpp)->flags |= FVP_ACCESS_NOOP;

#ifndef NO_EARLY_PERM_CHECK_HACK
			if (! islastcn) {
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
				if (! err && ! (*vpp)->v_mountedhere)
					err = fuse_access_i(*vpp, VEXEC, cred, td, &facp);
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

	DEBUG("returning with %d\n", err);
#if _DEBUG2G
	if (!err) {
		DEBUG2G("looked up node:\n");
		vn_printf(*vpp, " * ");
	}
#endif
#if _DEBUG
	DEBUG2G("root node:\n");
	vn_printf(fusefs_get_data(dvp->v_mount)->rvp, " * ");
#endif
	return (err);
}

static int
iterate_filehandles(struct vnode *vp, struct thread *td, struct ucred *cred,
		    fuse_metrics_t fmetr, void *param)
{
	struct fuse_filehandle *fufh, *fufhxxx;
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	int rv = 0;

	RECTIFY_TDCR(td, cred);

	LIST_FOREACH_SAFE(fufh, &fvdat->fh_head, fh_link, fufhxxx) {
		KASSERT(fufh->fh_vp == vp,
		        ("vnode mismatch for fuse_filehandle %p\n", fufh));
		if ((rv = fmetr(fufh, td, cred, param)))
			return (rv); 
	}

	return (0);
}

static int
fuse_standard_metrics(struct fuse_filehandle *fufh, struct thread *td,
                      struct ucred *cred, void *param)
{
	struct standard_metrics_param *stmp = param;

	DEBUG2G("fufh->mode %#x, mode %#x\n", fufh->mode, stmp->mode);
	if (fufh->cred->cr_uid == cred->cr_uid &&
	    fufh->cred->cr_rgid == cred->cr_rgid &&
	    fufh->pid == td->td_proc->p_pid &&
	    ((fufh->mode ^ stmp->mode) & ~(O_CREAT | O_EXCL | O_TRUNC)) == 0 &&
	    fufh->op == stmp->op) {
		stmp->fufh = fufh;
		fufh->useco++;
		return (-1);
	}

	return (0);
}

static __inline void
fuse_make_entry_req(struct mount *mp, uint64_t dnid, struct componentname *cnp,
                    enum fuse_opcode op, void *buf, size_t bufsize,
                    struct fuse_dispatcher *fdip)
{
	fdip->iosize = bufsize + cnp->cn_namelen + 1;
	fdisp_make(fdip, mp, op, dnid, curthread, NULL);

	memcpy(fdip->indata, buf, bufsize);

	memcpy((char *)fdip->indata + bufsize, cnp->cn_nameptr, cnp->cn_namelen);
	((char *)fdip->indata)[bufsize + cnp->cn_namelen] = '\0';
}

static __inline int
checkentry(struct fuse_entry_out *feo, enum vtype vtyp)
{
	if (vtyp != IFTOVT(feo->attr.mode) ||
	    feo->nodeid == FUSE_NULL_ID ||
	    feo->nodeid == FUSE_ROOT_ID) {
		DEBUG2G("messy new entry, shall be dropped\n");
		return (EINVAL);
	}

	return (0);
}

#if FUSE_HAS_CREATE
static __inline int
create_filehandle(struct vnode *vp, struct thread *td, struct ucred *cred,
                  int mode, struct fuse_dispatcher *fdip)
{
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	uint64_t parentid = fvdat->parent_nid;
	struct componentname *cnp = fvdat->germcnp;
	struct fuse_open_in *foi;
	struct fuse_entry_out *feo;
	struct fuse_mknod_in fmni;
	int err;
	int gone_good_old = 0;
	struct vnode *clashvp;

	vp->v_data = NULL;
	mode &= ~O_NOCTTY;

	fdisp_init(fdip, sizeof(*foi) + cnp->cn_namelen + 1);

	if (fusefs_get_data(vp->v_mount)->dataflag & FSESS_NOCREATE)
		goto good_old;
	fdisp_make(fdip, vp->v_mount, FUSE_CREATE, parentid, td, cred);

	/*
	 * Looks stupid, but this is how we could smuggle in these
	 * values from fuse_create...
	 */
	foi = fdip->indata;
	foi->flags = OFLAGS(mode);
	foi->mode = fvdat->flags;

	memcpy((char *)fdip->indata + sizeof(*foi), cnp->cn_nameptr,
	       cnp->cn_namelen);
	((char *)fdip->indata)[sizeof(*foi) + cnp->cn_namelen] = '\0';

	err = fdisp_wait_answ(fdip);

	if (err == ENOSYS) {
		fusefs_get_data(vp->v_mount)->dataflag |= FSESS_NOCREATE;
		fdip->tick = NULL;
		goto good_old;
	} else if (err)
		goto undo;

	goto bringup;

good_old:
	gone_good_old = 1;
	fmni.mode = fvdat->flags;
	fmni.rdev = 0;
	fuse_make_entry_req(vp->v_mount, parentid, cnp, FUSE_MKNOD,
	                    &fmni, sizeof(fmni), fdip);
	err = fdisp_wait_answ(fdip);
	if (err)
		goto undo;

bringup:
	feo = fdip->answ;
	
	if ((err = checkentry(feo, VREG))) {
		fuse_ticket_drop(fdip->tick);
		goto undo;
	}

	bzero(fvdat, sizeof(*fvdat));
	fuse_vnode_init(vp, fvdat, feo->nodeid, VREG, parentid);
	fvdat->nlookup++;
	vp->v_op = &fuse_vnops;
	cache_attrs(vp, feo);

try_insert:
	VOP_UNLOCK(vp, 0);
	/*
	 * We can't let the vnode being vput() here, the caller wants
	 * that do by herself.
	 * That means hash collisions must be relaxed. With a funky
	 * comparison function insertion will succeed, but we get a clear
	 * sign of the collision and we can handle it by ourselves.
	 */
	err = vfs_hash_get(vp->v_mount, feo->nodeid, LK_EXCLUSIVE, td,
	                   &clashvp, fuse_vnode_cmp, &feo->nodeid);
	if (! err && clashvp)
		fuse_vnode_teardown(clashvp, td, cred, VREG);

	if (! err) {
		err = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		if (err)
			printf("fuse4bsd: leaking vnode %p\n", vp);
		else {
			struct mount *mp = vp->v_mount;

			vp->v_mount = NULL;
			err = insmntque(vp, mp);
		}
	}

	if (! err)
		err = vfs_hash_insert(vp, feo->nodeid, LK_EXCLUSIVE, td,
		                      &clashvp, fuse_vnode_fgdrop_cmp, fvdat);
	if (! err && fvdat->nid == FUSE_NULL_ID) {
		vfs_hash_remove(vp);
		fvdat->nid = feo->nodeid;
		goto try_insert;
	}

	if (err) {
		if (gone_good_old)
			fuse_send_forget(vp->v_mount, td, cred, feo->nodeid, 1,
			                 fdip);
		else {
			struct fuse_release_in *fri;
			uint64_t nodeid = feo->nodeid;
			uint64_t fh_id = ((struct fuse_open_out *)(feo + 1))->fh;
			struct fuse_pidcred *pidcred;

			fdisp_init(fdip, sizeof(*fri));
			fdisp_make(fdip, vp->v_mount, FUSE_RELEASE, nodeid, td,
			           cred);
			fri = fdip->indata;
			fri->fh = fh_id;
			fri->flags = OFLAGS(mode);
			/*
			 * The node must be forgotten after the release.
			 * Release is sent in the background as usual (that's not
			 * necessary, but anyway...), so we do the forgetting
			 * by a dedicated callback handler.
			 *
			 * Current pid/cred is attached to the ticket as a parameter
			 * as the FORGET must be sent with current pid/cred but
			 * it will be sent from another context.
			 */
			fiov_adjust(&fdip->tick->tk_aw_handler_parm,
			            sizeof(*pidcred));
			pidcred = fdip->tick->tk_aw_handler_parm.base;
			pidcred->pid = td->td_proc->p_pid;
			memcpy(&pidcred->cred, cred, sizeof(*cred));
			fuse_insert_callback(fdip->tick, fuse_forgetful_handler);
			fuse_insert_message(fdip->tick);
		}

		return (err);
	}

	fdip->answ = gone_good_old ? NULL : feo + 1;

	return (0);

undo:
	free(fvdat, M_FUSEVN);
	vp->v_data = NULL;
	return (err);
}
#endif

int
fuse_get_filehandle(struct vnode *vp, struct thread *td, struct ucred *cred,
               int mode, struct fuse_filehandle **fufhp,
               struct get_filehandle_param *gefhp)
{
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	struct fuse_dispatcher fdi;
	struct fuse_open_in *foi;
	struct fuse_open_out *foo;
	int err = 0;
	struct fuse_filehandle *fufh = NULL;
	enum fuse_opcode op;
	int gone_create = 0;

	RECTIFY_TDCR(td, cred);

	/*
	 * "create" messaging is almost transparent for get_filehandle. There are
	 * some gotos and status variables though.
	 * And it's totally transparent for fuse_open.
	 * (By transparent I mean that they don't see the special "germic" state of
	 * the vnode... if the vnode is a germ, it will be tried to be initialized
	 * via a dedicated method, but from that on we go on as usual.)
	 */
#if FUSE_HAS_CREATE
	if (vp->v_op == &fuse_germ_vnops) {
		KASSERT(gefhp, ("create_filehandle called without get_filehandle_param"));
		gone_create = 1;
		if (gefhp)
			gefhp->do_gc = 0;
		op = FUSE_OPEN;
		fdi.answ = NULL;
		if ((err = create_filehandle(vp, td, cred, mode, &fdi)))
			goto out;
		else if (fdi.answ)
			goto setup_filehandle;
	}
#endif

	if (gefhp && gefhp->opcode)
		op = gefhp->opcode;
	else
        	op = FUSE_OPEN;

	if (op == FUSE_OPENDIR)
		mode = FREAD;
	else
		mode &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

	if (! (gefhp && gefhp->do_new)) {
		struct standard_metrics_param stmp;
		stmp.mode = mode;
		stmp.op = op;

		ASSERT_VOP_LOCKED__FH(vp);
		err = iterate_filehandles(vp, td, cred, fuse_standard_metrics,
		                          &stmp);

		if (err) {
			if (err == -1) {
				DEBUG2G("suitable fh of vnode #%llu found\n",
				        VTOILLU(vp));
				fufh = stmp.fufh;
				err = 0;
			}
			goto out;
		}
	}

	DEBUG2G("we need to fetch a new filehandle for vnode #%llu\n", VTOILLU(vp));

	fdisp_init(&fdi, sizeof(*foi));
	fdisp_make_vp(&fdi, op, vp, td, cred);

	foi = fdi.indata;
	foi->flags = OFLAGS(mode);

	if ((err = fdisp_wait_answ(&fdi)))
		goto out;

#if FUSE_HAS_CREATE
setup_filehandle:
#endif
	foo = fdi.answ;

	fufh = malloc(sizeof(*fufh), M_FUSEFH, M_WAITOK | M_ZERO);

	/*
	 * We need to reference the vnode from fuse private file data
	 * as files' f_vnode field might point to another vnode (eg.,
	 * if we are accessed through a nullfs overlay).
	 */
	fufh->fh_vp = vp;
	fufh->fh_id = foo->fh;
	fufh->flags = foo->open_flags;

	fuse_ticket_drop(fdi.tick);

	fufh->mode = mode;
	fufh->cred = crhold(cred);
	fufh->pid = td->td_proc->p_pid;
	fufh->useco = 1;
	fufh->op = op;

	ASSERT_VOP_ELOCKED__FH(vp);
	LIST_INSERT_HEAD(&fvdat->fh_head, fufh, fh_link);
	if (gefhp && gefhp->do_gc) {
		/*
		 * The neat idea is that a cache cleanup is the best time for
		 * a gc -- gc'ing unbound filehandles at inactive/reclaim time
		 * is not enough, they can just accumulate while something
		 * happens with the file, given the cache is flushed frequently
		 * (otherwise there is no reason for the system to spawn them,
		 * as the data can be read from core).
		 * So then, let's just tie their gc to cache flush...
		 * Luckily, this won't break the POSIX semantics that an
		 * unlinked file is get kept until there is reference to it,
		 * because that's done via the lookup/forget mechanism, and not
		 * via filehandles.
		 */
		/*
		 * Now we use unbound filehandles pretty rarely (as read/write
		 * of regular files doesn't rely on them anymore), only during
		 * exec and reading directories. It's pretty much unlikely that
		 * one can be reused in any way, so we drop them
		 * unconditionally.
		 */
		struct fuse_release_param frp;

		DEBUG2G("gc'ing...\n");
		frp.fg = 0;
		frp.flush = 0;
		iterate_filehandles(vp, td, cred, release_filehandle, &frp);
	}
	fvdat->fh_counter++;

#if _DEBUG2G
	if (gefhp && gefhp->do_gc) {
		DEBUG2G("after gc...\n");
		vn_printf(vp, " ");
	}
#endif

out:
	if (gone_create && ! err)
		fufh->flags |= FOPEN_KEEP_CACHE;

	*fufhp = fufh;

	return (err);
}

static int
fuse_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct thread *a_td;
		int a_fdidx; / struct file *a_fp;
	} */ *ap;
{
	struct thread *td = ap->a_td;
	struct vnode *vp = ap->a_vp;
	struct ucred *cred = ap->a_cred;
	int mode = ap->a_mode;

	struct fuse_filehandle *fufh = NULL;
	int err = 0;
	struct file *fp = ap->a_fp;
	struct get_filehandle_param gefhp;

	/*
	 * Contrary to that how it used to be, now we go on even if it's an
	 * internal (fileless) open: to match the "specs", we must get the
	 * keep_cache information (and act according to it).
	 */

#if _DEBUG2G
	if (fp)
		DEBUG2G("fp->f_flag %#x, open mode %d\n", fp->f_flag, mode);
#endif

	bzero(&gefhp, sizeof(gefhp));
	gefhp.do_gc = 1;
	gefhp.do_new = 1;
        gefhp.opcode = (vp->v_type == VDIR) ? FUSE_OPENDIR : FUSE_OPEN;
	if ((err = fuse_get_filehandle(vp, td, cred, mode, &fufh, &gefhp)))
		goto out;

	/*
	 * Types: VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD 
	 * XXX: should we let the fs take over spec files or let the OS
	 *  directly handle their IO?
	 */
	/* This is neither got right, nor settled */
#if 0
		if (! (vp->v_type == VFIFO || vp->v_type == VSOCK))
			fp->f_ops = &fuse_fileops;
#endif

	if (! (fufh->flags & FOPEN_KEEP_CACHE)) {
		DEBUG2G("flushing cache\n");
		/*
		 * This is a bit more heavyweight than the analogous function
		 * used in Linux at this point (in their sys/mm/truncate.c,
		 * the description says:
		 * "invalidate_mapping_pages() will not block on IO activity.
		 * It will not invalidate pages which are dirty, locked, under
		 * writeback or mapped into pagetables.") 
		 */
		err = vinvalbuf(vp, 0, PCATCH, 0);
		fufh->flags |= FOPEN_KEEP_CACHE;
	}

	if (! vp->v_object && /* just to avoid needless getattr'ing */
	    ! (err = vnode_create_vobject(vp, 0, td)) &&
	    /*
	     * Duh, we have to check the result by ourselfves,
	     * vnode_create_vobject swallows errors
	     */
	    ! vp->v_object)
		err = ENODEV;

	if (fp && ! err) {
		fp->f_ops = &fuse_fileops;
		fufh->fp = fp;
		fp->f_data = fufh;
	} else
		fufh->useco--;

out:
	if (VTOFUD(vp))
		/*
		 * If vnode was to be created, but FUSE_CREATE/FUSE_MKNOD
		 * has failed, vp will have no private data.
		 * It seems to be fine to handle that here.
		 */
		VTOFUD(vp)->flags &= ~FVP_ACCESS_NOOP;
	return (err);
}

static void
fuse_send_release(struct fuse_filehandle *fufh, struct thread *td,
                  struct ucred *cred, int flags, struct fuse_release_param *frp)
{
	struct vnode *vp = fufh->fh_vp;
	struct fuse_dispatcher fdi;
	struct fuse_release_in *fri;
	int err = 0;

	KASSERT(! fufh->fp && fufh->useco == 0, ("active-looking fuse filehandle was attempted to release"));

	VTOFUD(vp)->fh_counter--;
	DEBUG2G("filehandle of vnode #%llu being released, fh counter now is %d\n",
	         VTOILLU(vp), VTOFUD(vp)->fh_counter);

	if (vp->v_type == VBAD)
		goto out;

	fdisp_init(&fdi, sizeof(*fri));
	fdisp_make_vp(&fdi,
	              fufh->op == FUSE_OPENDIR ? FUSE_RELEASEDIR : FUSE_RELEASE,
	              vp, td, cred);
	fri = fdi.indata;
	fri->fh = fufh->fh_id;
	fri->flags = OFLAGS(flags);
#if FUSE_HAS_FLUSH_RELEASE
	if (frp->flush)
		fri->release_flags = FUSE_RELEASE_FLUSH;
#endif

	if (frp->fg) {
		err = fdisp_wait_answ(&fdi);
		if (err)
			goto out;
		else
			fuse_ticket_drop(fdi.tick);
	} else {
		fuse_insert_callback(fdi.tick, NULL);
		fuse_insert_message(fdi.tick);
	}

out:
	crfree(fufh->cred);
	free(fufh, M_FUSEFH);
	if (err && frp->err == 0)
		frp->err = err;
}

static int
fuse_close_f(struct file *fp, struct thread *td)
{
	struct fuse_filehandle *fufh;
	struct vnode *vp = NULL, *ovl_vp = fp->f_vnode;
	struct fuse_release_param frp;

	if (! _file_is_fat(fp))
		panic("non-fat file passed to close routine");

	vn_lock(ovl_vp, LK_EXCLUSIVE | LK_RETRY);

	if (_file_is_bad(fp)) {
		DEBUG2G("fp %p, (overlay) vnode %p: went bad, giving up\n",
		        fp, ovl_vp);
		goto out;
	}
	fufh = FTOFH(fp);
	vp = fufh->fh_vp;
	KASSERT(fufh->fp == fp, ("file's filehandle is stolen"));
	DEBUG2G("vnode #%llu, fufh owner %p, useco %d\n",
	        VTOILLU(vp), fp, fufh->useco);

	fufh->useco--;
	ASSERT_VOP_ELOCKED__FH(vp);
	fufh->fp = NULL;
	if (fufh->useco == 0)
		LIST_REMOVE(fufh, fh_link);
	fp->f_data = NULL;

	if (fufh->useco == 0) {
		frp.err = 0;
#if FUSE_HAS_FLUSH_RELEASE
		frp.fg = 1;
		frp.flush = 1;
#else
		frp.fg = 0;
		frp.flush = 0;
#endif
		fuse_send_release(fufh, td, NULL, fp->f_flag & ~O_EXCL, &frp);
	}

out:
	if (fp->f_flag & FWRITE && vp)
                vp->v_writecount--;
	vput(ovl_vp);
	return (frp.err);
}

static int
fuse_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	struct fuse_release_param frp;

	DEBUG2G("vnode #%llu\n", VTOILLU(ap->a_vp));
	frp.err = 0;
#if FUSE_HAS_FLUSH_RELEASE
	frp.fg = 1;
	frp.flush = 1;
#else
	frp.fg = 0;
	frp.flush = 0;
#endif
	fuse_filehandle_gc(ap->a_vp, ap->a_td, ap->a_cred, &frp);

	return (frp.err);
}

static int
fuse_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct ucred *cred = ap->a_cred;
	struct uio *uio = ap->a_uio;
	int ioflag = ap->a_ioflag;

	DEBUG2G("vnode #%llu\n", VTOILLU(vp));
	return fuse_io_vnode(vp, cred, uio, ioflag);
}

#define DIRCOOKEDSIZE FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + MAXNAMLEN + 1)

static int
fuse_readdir(ap)
	struct vop_readdir_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
		int *a_eofflag;
		int *ncookies;
		u_long **a_cookies;
	} */ *ap;
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
	 * (See fuse_dir_buffeater).
	 */
	fiov_init(&cookediov, DIRCOOKEDSIZE);

	bzero(&fioda, sizeof(fioda));
	fioda.vp = vp;
	fioda.fufh = fufh;
	fioda.uio = uio;
	fioda.cred = cred;
	fioda.opcode = FUSE_READDIR;
	fioda.buffeater = fuse_dir_buffeater;
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

	return (err);
}

/* A hack for being able to please the GENERIC_DIRSIZ macro */

struct pseudo_dirent {
	uint32_t d_namlen;
};

static int
fuse_dir_buffeater(struct uio *uio, size_t reqsize, void *buf, size_t bufsize, void *param)
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
	struct dirent *de;
	struct fuse_dirent *fudge;
	int err = 0;
	size_t freclen;
	int cou = 0;
	int bytesavail;
	struct fuse_iov *cookediov;
	
	KASSERT(bufsize <= reqsize, ("read more than asked for?"));

	DEBUG2G("starting\n");

	/*
	 * Sanity check: if this fails, we would overrun the allocated space
	 * upon entering the loop below, so we'd better leave right now.
	 * If so, we return -1 to terminate reading.
	 */
	if (bufsize < FUSE_NAME_OFFSET)
		return (-1);

	cookediov = param;

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
		de = (struct dirent *) cookediov->base;
		de->d_fileno = fudge->ino; /* XXX cast from 64 to 32 bytes */
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

		if (err)
			break;

		buf = (char*)buf + freclen;
		bufsize -= freclen;
		uio->uio_offset = fudge->off;
	}

	return (err);
}

static int
fuse_readlink(ap)
	struct vop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;

	struct fuse_dispatcher fdi;
	int err;

	if ((err = fdisp_simple_putget(&fdi, FUSE_READLINK, vp, curthread,
	    ap->a_cred)))
		return (err);

	if (((char *)fdi.answ)[0] == '/' &&
	    fusefs_get_data(vp->v_mount)->dataflag & FSESS_PUSH_SYMLINKS_IN) {
		char *mpth = vp->v_mount->mnt_stat.f_mntonname;

		err = uiomove(mpth, strlen(mpth), uio);
	}

	if (! err)
		err = uiomove(fdi.answ, fdi.iosize, uio);

	fuse_ticket_drop(fdi.tick);
	fuse_invalidate_attr(vp);

	return (err);
}

static __inline int
fuse_newentry_core(struct vnode *dvp, struct vnode **vpp, enum vtype vtyp,
                   struct fuse_dispatcher *fdip)
{
	struct mount *mp = dvp->v_mount;
	struct fuse_entry_out *feo;
	int err = 0;

	KASSERT(! (mp->mnt_flag & MNT_RDONLY),
	        ("request for new entry in a read-only mount"));

	if ((err = fdisp_wait_answ(fdip)))
		return (err);
	
	feo = fdip->answ;

	if ((err = checkentry(feo, vtyp)))
		goto out;

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
		fuse_send_forget(mp, curthread, NULL, feo->nodeid, 1, fdip);
		return (err);
	}

	VTOFUD(*vpp)->nlookup++;
	cache_attrs(*vpp, feo);

out:
	fuse_ticket_drop(fdip->tick);

	return (err);
}

static int
fuse_newentry_backend(struct vnode *dvp, struct vnode **vpp,
                      struct componentname *cnp, enum fuse_opcode op,
                      void *buf, size_t bufsize, enum vtype vtyp)
{
	struct fuse_dispatcher fdi;
	int err;

	fdisp_init(&fdi, 0);
	fuse_make_entry_req(dvp->v_mount, VTOI(dvp), cnp, op, buf, bufsize,
	                    &fdi);

	err = fuse_newentry_core(dvp, vpp, vtyp, &fdi);
	fuse_invalidate_attr(dvp);
	return (err);
}

static int
fuse_mknod(ap)
	struct vop_mknod_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vattr *vap = ap->a_vap;
	struct fuse_mknod_in fmni; 

	fmni.mode = MAKEIMODE(vap->va_type, vap->va_mode);
	fmni.rdev = vap->va_rdev;

	return fuse_newentry_backend(dvp, vpp, cnp, FUSE_MKNOD, &fmni,
	                             sizeof(fmni), vap->va_type);
}

static int
fuse_create(ap)
	struct vop_create_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct vattr *vap = ap->a_vap;
#if FUSE_HAS_CREATE
	struct fuse_vnode_data *fvdat;
	int err;

	if (vap->va_type != VREG ||
	    fusefs_get_data(dvp->v_mount)->dataflag & FSESS_NOCREATE)
		goto good_old;

	/*
	 * We cobble together here a new vnode as the caller expects that,
	 * but we don't yet fully initialize it (that will happen when it
	 * will be opened). We keep it in a "germic" state.
	 */
	if ((err = getnewvnode("fuse", dvp->v_mount, &fuse_vnops, vpp)))
		return (err);

	if ((err = vn_lock(*vpp, LK_EXCLUSIVE | LK_RETRY))) {
		printf("fuse4bsd: leaking vnode %p\n", *vpp);
		return (err);
	}

	fvdat = malloc(sizeof(*fvdat), M_FUSEVN, M_WAITOK | M_ZERO);

	fvdat->parent_nid = VTOI(dvp);
	/*
	 * We overload some fields of the vnode data to carry the information
	 * which will be needed to make the proper CREATE query in open.
	 * germcnp is a dedicated field for this purpose though.
	 */
	fvdat->flags = MAKEIMODE(vap->va_type, vap->va_mode);
	fvdat->germcnp = ap->a_cnp;

	/*
	 * Stub vnops, almost the same as "dead", with the exception of the
	 * critical ones which will let the vnode get fully emerged.
	 */
	(*vpp)->v_op = &fuse_germ_vnops;
	(*vpp)->v_data = fvdat;
	(*vpp)->v_mount = dvp->v_mount;

	fuse_invalidate_attr(dvp);

	return (0);

good_old:
#endif
	vap->va_rdev = 0;
	return (VOP_MKNOD(dvp, vpp, ap->a_cnp, vap));
}

static int
fuse_mkdir(ap)
	struct vop_mkdir_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vattr *vap = ap->a_vap;
	struct fuse_mkdir_in fmdi; 

	fmdi.mode = MAKEIMODE(vap->va_type, vap->va_mode);

	return fuse_newentry_backend(dvp, vpp, cnp, FUSE_MKDIR, &fmdi,
	                             sizeof(fmdi), VDIR);
}

static int
fuse_link(ap)
	struct vop_link_args /* {
		struct vnode *a_tdvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap;
{
	struct vnode *dvp = ap->a_tdvp;
	struct vnode *vp = ap->a_vp;
	struct componentname *cnp = ap->a_cnp;

	struct fuse_dispatcher fdi;
	struct fuse_link_in fli; 
	struct fuse_entry_out *feo;
	int err = 0;

	if (dvp->v_mount != vp->v_mount)
		return (EXDEV);

	fli.oldnodeid = VTOI(vp);

	/*
	 * Unlike Linux, we proceed here lazily: here we do nothing on
	 * the kernel side for registering the new, hardlinked entry.
	 * (That will just happen when the hardlinked entry is looked up
	 * first time). We just send the request to the daemon.
	 * This suits better for the BSD VFS.
	 */

	fdisp_init(&fdi, 0);
	fuse_make_entry_req(dvp->v_mount, VTOI(dvp), cnp, FUSE_LINK, &fli,
	                    sizeof(fli), &fdi);
	if ((err = fdisp_wait_answ(&fdi)))
		return (err);
	
	feo = fdi.answ;

	err = checkentry(feo, vp->v_type);

	fuse_ticket_drop(fdi.tick);
	fuse_invalidate_attr(dvp);
	/*
	 * It depends on userspace if the hardlinked entry is really the
	 * same vnode or not. Sort of unconventionally, the latter happens
	 * if linking is managed by the hi-level FUSE library (in which case
	 * syncing between the two nodes is up to the actual fs code).
	 * Therefore we can't just cache the attrs we got for the hardlink node,
	 * -- that regards to the hardlinked node and not the original.
	 * What we do instead is invalidating cached attrs of the original so
	 * the fs gets a chance to pass on updated attributes also for the
	 * original node.
	 *
	 * See also remark at the similar place in the Linux kernel code.
	 */
	fuse_invalidate_attr(vp);

	VTOFUD(vp)->nlookup++;

	return (err);
}

static int
fuse_symlink(ap)
	struct vop_symlink_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
		char *a_target;
	} */ *ap;
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
	 * Hence we can't rely on our handy fuse_newentry_backend() routine,
	 * but put together the message manually and just call the core part.
	 */

	len = strlen(target) + 1;
	fdisp_init(&fdi, len + cnp->cn_namelen + 1);
	fdisp_make_vp(&fdi, FUSE_SYMLINK, dvp, curthread, NULL);

	memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
	((char *)fdi.indata)[cnp->cn_namelen] = '\0';
	memcpy((char *)fdi.indata + cnp->cn_namelen + 1, target, len);

	err = fuse_newentry_core(dvp, vpp, VLNK, &fdi);
	fuse_invalidate_attr(dvp);
	return (err);
}

static __inline int
fuse_remove_backend(struct vnode *dvp, struct vnode *vp,
                    struct componentname *cnp, enum fuse_opcode op)
{
	struct fuse_dispatcher fdi;
	int err = 0;

	fdisp_init(&fdi, cnp->cn_namelen + 1);
	fdisp_make_vp(&fdi, op, dvp, curthread, NULL);

	memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
	((char *)fdi.indata)[cnp->cn_namelen] = '\0';

	if (! (err = fdisp_wait_answ(&fdi)))
		fuse_ticket_drop(fdi.tick);
	fuse_invalidate_attr(dvp);
	fuse_invalidate_attr(vp);

	return (err);
}

static int
fuse_remove(ap)
	struct vop_remove_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap;
{
	return (fuse_remove_backend(ap->a_dvp, ap->a_vp, ap->a_cnp,
	        FUSE_UNLINK));
}

static int
fuse_rmdir(ap)
	struct vop_rmdir_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	int err;
	struct vnode *xvp;
	struct parentmanager_param pmp;

	err = fuse_remove_backend(ap->a_dvp, vp, ap->a_cnp, FUSE_RMDIR);
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

static __inline int
fuse_rename_core(struct vnode *fdvp, struct componentname *fcnp,
                 struct vnode *tdvp, struct componentname *tcnp)
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
	((char *)fdi.indata)[sizeof(*fri) + fcnp->cn_namelen + tcnp->cn_namelen + 1] = '\0';
	
	if (! (err = fdisp_wait_answ(&fdi)))
		fuse_ticket_drop(fdi.tick);

	fuse_invalidate_attr(fdvp);
	if (tdvp != fdvp)
		fuse_invalidate_attr(tdvp);

	return (err);
}

static int
fuse_rename(ap)
	struct vop_rename_args /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
	} */ *ap;
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
	err = fuse_access_i(fvp, VWRITE, tcnp->cn_cred, tcnp->cn_thread, &facp);
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

	if ((err = fuse_rename_core(fdvp, fcnp, tdvp, tcnp)))
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

static int
fuse_setattr(ap)
	struct vop_setattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
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

	if (! fsai->valid)
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

	if (fsai->valid & ~FATTR_SIZE)
		err = fuse_access_i(vp, VADMIN, cred, td, &facp);
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
		err = fuse_access_i(vp, VWRITE, cred, td, &facp);

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

static int 
fuse_fsync_filehandle(struct fuse_filehandle *fufh, struct thread *td,
                      struct ucred *cred, void *param)
{
	struct fuse_fsync_in *ffsi;
	struct fuse_dispatcher *fdip = param;

	fdip->iosize = sizeof(*ffsi);
	fdip->tick = NULL;
	fdisp_make_vp(fdip,
	              (fufh->op == FUSE_OPENDIR) ? FUSE_FSYNCDIR : FUSE_FSYNC,
	              fufh->fh_vp, td, cred);

	ffsi = fdip->indata;
	ffsi->fh = fufh->fh_id;
	/*
	 * this sets that we wanna sync file data,
	 * not just metadata; a 0 value would have no
	 * counterpart in BSD semantics
	 */
	ffsi->fsync_flags = 1;
  
	fuse_insert_callback(fdip->tick, fuse_fsync_handler);
	fuse_insert_message(fdip->tick);

	return (0);
}

static int
fuse_fsync(ap)
	struct vop_fsync_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode * a_vp;
		struct ucred * a_cred;
		int  a_waitfor;
		struct thread * a_td;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct thread *td = ap->a_td;

	int err = 0;
	struct fuse_dispatcher fdi;

	DEBUG("got flag %d\n", ap->a_waitfor);

	/*
	 * Usually, the call to vop_stdfsync is expected to do nothing, as we
	 * tend to leave no dirty buffers behind. However, they might show up,
	 * eg., after an interrupted write.
	 * To be able to release the kernel's cleanup-dirty-buffers machinery
	 * this is advised to be inserted here.
	 */

	if ((err = vop_stdfsync(ap)))
		return (err); 

	/*	
	 * In Linux, the fsync syscall handler is file based.
	 * Hence in fuse too -- and this approach does make sense,
	 * for exapmle, when it comes to implementing things like
	 * sshfs: the sshfs userspace fsync handler flushes data
	 * associated with the given filehandle, ie. sftp
	 * messaging thread.
	 * 
	 * On the other hand, BSD fsync is inherently not file
	 * but vnode based: even fsync(2), to which one passes
	 * a file descriptor, the corresponding file is used for 
	 * nothing but looking up the vnode behind (see fsync() 
	 * in kern/vfs_syscalls.c).
	 *
	 * We have thus two choices here: either grab the first
	 * open file and use that for the fsync message or run
	 * through all files (at least, the ones we have acces to,
	 * ie., those belonging to the current process). The first
	 * is bad: as we mentioned concerning sshfs, dirty data can belong
	 * to each ssh messaging thread, being associated to file
	 * handles independently. 
	 *
	 * So we wanna sync all our open files. "Nowait" sync is easy,
	 * just walk over all the files, and send FUSE_FSYNC(DIR) with
	 * a null callback, and leave. "Wait" sync is harder: syncing
	 * the files linearly, one after the other would be very easy
	 * indeed but would be far more than a lethal dose of the KISS
	 * principle. So sending of the messages and waiting for them
	 * should be done synchronously. The messaging backend is flexible
	 * enough for making the implementation of this not too hard, 
	 * but now I don't wanna go mucking with the proper handling of
	 * interrupts, and other issues; and I don't wanna break the nice
	 * hi-level messaging API which serves us well otherwise. So
	 * currently I just say no here...
	 *
	 * Just to note: even the "nowait" type fsync could be optimized
	 * if we went beyond the api, and lock/unlock all mutexes (tickets',
	 * messages', callbacks') only once, and take out/put in stuff for all
	 * files together, with one big breath. But doing not so is not as much
	 * overhead as it would be worth for the trouble.
	 */

	/*
	 * It seemed to be a good idea to lock the filehandle lock only before
	 * doing iterate_filehandle but that configuration is suspected to cause
	 * LOR alerts, so now we get the filehandle lock before the fuse_data
	 * lock.
	 */
	ASSERT_VOP_LOCKED__FH(vp);

	if (fusefs_get_data(vp->v_mount)->dataflag &
            (vp->v_type == VDIR ? FSESS_NOFSYNCDIR : FSESS_NOFSYNC))
		goto out;

	fdisp_init(&fdi, 0);
	iterate_filehandles(vp, td, NULL, fuse_fsync_filehandle, &fdi);

out:
	return (err);
}

static int
fuse_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct ucred *cred = ap->a_cred;
	struct uio *uio = ap->a_uio;
	int ioflag = ap->a_ioflag;

	DEBUG2G("vnode #%llu\n", VTOILLU(vp));
	return fuse_io_vnode(vp, cred, uio, ioflag);
}

/*
 * Do an I/O operation to/from a cache block. This may be called
 * synchronously or from an nfsiod.
 */
static int
fuse_strategy(ap)
	struct vop_strategy_args /* {
		struct vnode *a_vp;
		struct buf *a_bp;
	} */ *ap;
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

int
fuse_getpages(ap)
	struct vop_getpages_args /* {
		struct vnode *a_vp;
		vm_page_t *a_m;
		int a_count;
		int a_reqpage;
		vm_ooffset_t a_offset;
	} */ *ap;
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
 * Vnode op for VM putpages.
 */
int
fuse_putpages(ap)
	struct vop_putpages_args /* {
		struct vnode *a_vp;
		vm_page_t *a_m;
		int a_count;
		int a_sync;
		int *a_rtvals;
		vm_ooffset_t a_offset;
	} */ *ap;
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

int
fuse_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct fuse_vnode_data *fvdat = VTOFUD(ap->a_vp);

	printf("nodeid: %llu, parent_nid: %llu, fh_counter: %d, "
	       "nlookup: %llu, flags: %#x\n",
	       VTOILLU(ap->a_vp), (unsigned long long) fvdat->parent_nid,
	       fvdat->fh_counter, (unsigned long long)fvdat->nlookup,
	       fvdat->flags);

	return (0);
}

static int
fuse_unlock(ap)
	struct vop_unlock_args /* {
		struct vnode *a_vp;
		int a_flags;
		struct thread *a_td;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	if (VTOFUD(vp))
		VTOFUD(vp)->flags &= ~FVP_ACCESS_NOOP;

	return vop_stdunlock(ap);
}

#if FUSE_HAS_CREATE
int
fuse_germ_access(struct vop_access_args *ap)
{
	return (0);
}
#endif
