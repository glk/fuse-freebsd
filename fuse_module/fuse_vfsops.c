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
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/fcntl.h>

#include "fuse.h"
#include "fuse_session.h"
#include "fuse_vnode.h"

#include <sys/priv.h>
#include <security/mac/mac_framework.h>


/* This will do for privilege types for now */
#ifndef PRIV_VFS_FUSE_ALLOWOTHER
#define PRIV_VFS_FUSE_ALLOWOTHER PRIV_VFS_MOUNT_NONUSER
#endif
#ifndef PRIV_VFS_FUSE_MOUNT_NONUSER
#define PRIV_VFS_FUSE_MOUNT_NONUSER PRIV_VFS_MOUNT_NONUSER
#endif
#ifndef PRIV_VFS_FUSE_SYNC_UNMOUNT
#define PRIV_VFS_FUSE_SYNC_UNMOUNT PRIV_VFS_MOUNT_NONUSER
#endif


static int fuse_init_handler(struct fuse_ticket *tick, struct uio *uio);
static void fuse_send_init(struct fuse_data *data, struct thread *td);
static vfs_hash_cmp_t fuse_vnode_bgdrop_cmp;

static vfs_mount_t fuse_mount;
static vfs_unmount_t fuse_unmount;
static vfs_root_t fuse_root;
static vfs_statfs_t fuse_statfs;

struct vfsops fuse_vfsops = {
	.vfs_mount   = fuse_mount,
	.vfs_unmount = fuse_unmount,
	.vfs_root    = fuse_root,
	.vfs_statfs  = fuse_statfs,
};

SYSCTL_INT(_vfs_fuse, OID_AUTO, init_backgrounded, CTLFLAG_RD,
           0, 1, "indicate async handshake");
static int fuse_enforce_dev_perms = 0;
SYSCTL_LONG(_vfs_fuse, OID_AUTO, enforce_dev_perms, CTLFLAG_RW,
            &fuse_enforce_dev_perms, 0,
            "enforce fuse device permissions for secondary mounts");
static unsigned sync_unmount = 1;
SYSCTL_UINT(_vfs_fuse, OID_AUTO, sync_unmount, CTLFLAG_RW,
            &sync_unmount, 0, "specify when to use synchronous unmount");

MALLOC_DEFINE(M_FUSEVFS, "fuse_filesystem", "buffer for fuse vfs layer");

extern struct vop_vector fuse_vnops;


/********************
 *
 * >>> callback handlers for VFS ops
 *
 ********************/

static int
fuse_init_handler(struct fuse_ticket *tick, struct uio *uio)
{
	struct fuse_data *data = tick->tk_data;
#if FUSE_KERNELABI_GEQ(7, 5)
	struct fuse_init_out *fiio;
#else
	struct fuse_init_in_out *fiio;
#endif
	int err = 0;

	if ((err = tick->tk_aw_ohead.error))
		goto out;
	if ((err = fticket_pull(tick, uio)))
		goto out;

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
		if (fticket_resp(tick)->len == sizeof(struct fuse_init_out))
			data->max_write = fiio->max_write;
		else
			err = EINVAL;
#endif
	} else
		/* Old fix values */
		data->max_write = 4096;

out:
	fuse_ticket_drop(tick);
	if (err)
		fdata_kick_set(data);

	mtx_lock(&data->ticket_mtx);
	data->dataflag |= FSESS_INITED;
	wakeup(&data->ticketer);
	mtx_unlock(&data->ticket_mtx);

	return (0);
}

/******************
 *
 * >>> VFS hash comparators
 *
 ******************/

int
fuse_vnode_cmp(struct vnode *vp, void *nidp)
{
	return (VTOI(vp) != *((uint64_t *)nidp));
}

/*
 * This comparator is used for safely setting the parent_nid.
 */

int
fuse_vnode_setparent_cmp(struct vnode *vp, void *param)
{
	struct parentmanager_param *pmp = param;

	if (VTOI(vp) == pmp->nodeid) {
		KASSERT(! pmp->valid,
		        ("more than one vnode seems to match #%llu",
			 (unsigned long long)pmp->nodeid));
		VTOFUD(vp)->parent_nid = pmp->parent_nid;
		pmp->valid = 1;
	}

	return (1);
}

/*
 * Vnode comparison function which expicitly marks
 * clashing vnodes as unhashed (via setting id to 0)
 * before dropping them. So at gc time we'll know if
 * we have to remove the node from the hash.
 */

static int
fuse_vnode_bgdrop_cmp(struct vnode *vp, void *param)
{
	struct fuse_vnode_data *fvdat = param;

	if (VTOI(vp) != fvdat->nid)
		return (1);

	fvdat->nid = FUSE_NULL_ID;
	return (0);
}

/*************
 *
 * >>> VFS ops
 *
 *************/

static __inline void
fuse_send_init(struct fuse_data *data, struct thread *td)
{
#if FUSE_KERNELABI_GEQ(7, 5)
	struct fuse_init_in *fiii;
#else
	struct fuse_init_in_out *fiii;
#endif
	struct fuse_dispatcher fdi;

	fdisp_init(&fdi, sizeof(*fiii));
	fdisp_make(&fdi, data->mp, FUSE_INIT, 0, td, NULL);
	fiii = fdi.indata;
	fiii->major = FUSE_KERNEL_VERSION;
	fiii->minor = FUSE_KERNEL_MINOR_VERSION;

	fuse_insert_callback(fdi.tick, fuse_init_handler);
	fuse_insert_message(fdi.tick);
}

/*
 * Mount system call
 */
static int
fuse_mount(struct mount *mp)
{
	struct thread *td = curthread;
	int err = 0;
	size_t len;
	char *fspec, *subtype = NULL;
	struct vnode *devvp;
	struct vfsoptlist *opts;
	struct nameidata nd, *ndp = &nd;
	struct cdev *fdev;
	struct sx *slock;
	struct fuse_data *data;
	int mntopts = 0, __mntopts = 0, max_read_set = 0, secondary = 0;
	unsigned max_read = ~0;
	struct vnode *rvp;
	struct fuse_vnode_data *fvdat;

	GIANT_REQUIRED;
	KASSERT(fuse_useco >= 0,
	        ("negative fuse usecount despite Giant"));

	if (mp->mnt_flag & MNT_UPDATE)
		return (EOPNOTSUPP);

	mp->mnt_flag |= MNT_SYNCHRONOUS; 
	/* Get the new options passed to mount */
	opts = mp->mnt_optnew;

	if (!opts)
		return (EINVAL);

	/* `fspath' contains the mount point (eg. /mnt/fuse/sshfs); REQUIRED */
	if (!vfs_getopts(opts, "fspath", &err))
		return (err);

	/* `from' contains the device name (eg. /dev/fuse0); REQUIRED */
	fspec = vfs_getopts(opts, "from", &err);
	if (!fspec)
		return (err);

	mp->mnt_data = NULL;

	/*
	 * Not an update, or updating the name: look up the name
	 * and verify that it refers to a sensible disk device.
	 */ 

	NDINIT(ndp, LOOKUP, FOLLOW, UIO_SYSSPACE, fspec, td);
	if ((err = namei(ndp)) != 0)
		return (err);
	NDFREE(ndp, NDF_ONLY_PNBUF);
	devvp = ndp->ni_vp;

	if (devvp->v_type != VCHR) {
		vrele(devvp);
		return (ENXIO);
	}

	fdev = devvp->v_rdev;
	dev_ref(fdev);

	if (fuse_enforce_dev_perms) {
		/*
		 * Check if mounter can open the fuse device.
		 *
		 * This has significance only if we are doing a secondary mount
		 * which doesn't involve actually opening fuse devices, but we
		 * still want to enforce the permissions of the device (in
		 * order to keep control over the circle of fuse users).
		 *
		 * (In case of primary mounts, we are either the superuser so
		 * we can do anything anyway, or we can mount only if the
		 * device is already opened by us, ie. we are permitted to open
		 * the device.)
		 */
#ifdef MAC
		err = mac_check_vnode_open(td->td_ucred, devvp, VREAD|VWRITE);
		if (! err)
#endif
			err = VOP_ACCESS(devvp, VREAD|VWRITE, td->td_ucred, td);
		if (err) {
			vrele(devvp);
			return (err);
		}
	}

	/*
	 * according to coda code, no extra lock is needed --
	 * although in sys/vnode.h this field is marked "v"
	 */
	vrele(devvp);

	FUSE_LOCK;
	if (! fdev->si_devsw ||
	    strcmp("fuse", fdev->si_devsw->d_name)) {
		FUSE_UNLOCK;
		return (ENXIO);
	}

	if ((data = fusedev_get_data(fdev)) &&
	    data->dataflag & FSESS_OPENED)
		data->mntco++;
	else {
		FUSE_UNLOCK;
		dev_rel(fdev);
		return (ENXIO);
	}	
	FUSE_UNLOCK;

	/* 
	 * With the help of underscored options the mount program
	 * can inform us from the flags it sets by default
	 */
#define FUSE_FLAGOPT(fnam, fval) do {				\
	vfs_flagopt(opts, #fnam, &mntopts, fval);		\
	vfs_flagopt(opts, "__" #fnam, &__mntopts, fval);	\
} while (0)
	FUSE_FLAGOPT(private, FSESS_PRIVATE);
	FUSE_FLAGOPT(neglect_shares, FSESS_NEGLECT_SHARES);
	FUSE_FLAGOPT(allow_other, FSESS_DAEMON_CAN_SPY);
	FUSE_FLAGOPT(push_symlinks_in, FSESS_PUSH_SYMLINKS_IN);
	FUSE_FLAGOPT(default_permissions, FSESS_DEFAULT_PERMISSIONS);
#if FUSE_HAS_DESTROY
	FUSE_FLAGOPT(sync_unmount, FSESS_SYNC_UNMOUNT);
#endif
#undef FUSE_FLAGOPT

	if (vfs_scanopt(opts, "max_read=", "%u", &max_read) == 1)
		max_read_set = 1;
	subtype = vfs_getopts(opts, "subtype=", &err);
	err = 0;

	if (fdata_kick_get(data))
		err = ENOTCONN;
	if (mntopts & FSESS_DAEMON_CAN_SPY)
	    err = priv_check(td, PRIV_VFS_FUSE_ALLOWOTHER);

	slock = &data->mhierlock;
	/* Note that sx_try_xlock returns 0 on _failure_ */
	if (! err && sx_try_xlock(slock) == 0) {
		err = EBUSY;
		DEBUG2G("lock contested\n");
	}

	if (err)
		goto out;

	DEBUG2G("mntopts 0x%x\n", mntopts);

	/* Sanity + permission checks */ 

	if (! data->daemoncred)
		panic("fuse daemon found, but identity unknown");

	if (data->mpri == FM_PRIMARY) {
		secondary = 1;
		if (data->dataflag & FSESS_PRIVATE)
			/*
			 * device is owned and owner doesn't
			 * wanna share it with us 
			 */
			err = EPERM;
		if (/* actual option set differs from default */
		    mntopts != __mntopts ||
		    max_read_set || subtype)
			/*
			 * Secondary mounts not allowed to have
			 * options (basicly, that would be
			 * useless though harmless, just let's
			 * be explicit about it)
			 */
			err = EINVAL;
	} else {
		if (td->td_ucred->cr_uid != data->daemoncred->cr_uid)
			/* are we allowed to do the first mount? */
			err = priv_check(td, PRIV_VFS_FUSE_MOUNT_NONUSER);
	}

	if (err) {
		sx_xunlock(slock);
		goto out;
	}

	/* We need this here as this slot is used by getnewvnode() */
	mp->mnt_stat.f_iosize = MAXBSIZE;

	if (secondary) {
		struct fuse_secondary_data *fsdat;

		fsdat = malloc(sizeof(*fsdat), M_FUSEVFS, M_WAITOK| M_ZERO);
		fsdat->mpri = FM_SECONDARY;
		mp->mnt_data = fsdat;
		fsdat->mp = mp;
		fsdat->master = data;

		LIST_INSERT_HEAD(&data->slaves_head, fsdat, slaves_link);

		goto rootdone;
	}

	mp->mnt_data = data;

	/* code stolen from portalfs */

	fvdat = malloc(sizeof(*fvdat), M_FUSEVN, M_WAITOK | M_ZERO);

	err = getnewvnode("fuse", mp, &fuse_vnops, &rvp);
	if (! err) {
		err = vn_lock(rvp, LK_EXCLUSIVE | LK_RETRY);
		if (err)
			printf("fuse4bsd: leaking vnode %p\n", rvp);
	}

	if (! err) {
		/*
		 * FUSE_ROOT_ID as an inode number will be resolved directly.
		 * without resorting to the vfs hashing mechanism, thus it also
		 * can be inserted directly to the v_hash slot.
		 */
		rvp->v_hash = FUSE_ROOT_ID;
		data->rvp = rvp;
		fuse_vnode_init(rvp, fvdat, FUSE_ROOT_ID, VNON, 0);
		rvp->v_vflag |= VV_ROOT;
		err = insmntque(rvp, mp);
	}

	if (err) {
		fdata_kick_set(data);
		sx_xunlock(slock);
		free(fvdat, M_FUSEVN);
	        goto out;
	} else
		VOP_UNLOCK(rvp, 0);
	data->mp = mp;
	data->mpri = FM_PRIMARY;
	data->dataflag |= mntopts;
	data->max_read = max_read;
	if (! priv_check(td, PRIV_VFS_FUSE_SYNC_UNMOUNT))
		data->dataflag |= FSESS_CAN_SYNC_UNMOUNT;

rootdone:

	sx_xunlock(slock);

	vfs_getnewfsid(mp);	
	mp->mnt_flag |= MNT_LOCAL;
#ifdef MNTK_MPSAFE
	mp->mnt_kern_flag |= MNTK_MPSAFE;
#endif
	if (subtype) {
		strlcat(mp->mnt_stat.f_fstypename, ".", MFSNAMELEN);
		strlcat(mp->mnt_stat.f_fstypename, subtype, MFSNAMELEN);
	}
	copystr(fspec, mp->mnt_stat.f_mntfromname, MNAMELEN - 1, &len);
	if (secondary && len >= 1) {
		/*
		 * I've considered using s1, s2,... for shares, instead
		 * #1, #2,... as s* is more conventional...
		 * Finally I chose #* as I feel it's more expressive
		 * and s* can be misleading (slices are strung up
		 * serially, shares exist in parallell)
		 */
		mp->mnt_stat.f_mntfromname[len-1] = '#';
		if (len < MNAMELEN - 1) {
			/* Duhh, ain't there a better way of doing this? */
			int log = 0, lim = 1;
			while (data->mntco > lim) {
				lim *= 10;
				log++;
			}
			if (log >= MNAMELEN - len) {
				mp->mnt_stat.f_mntfromname[len] = '?';
				len++;
			} else {
				sprintf(mp->mnt_stat.f_mntfromname + len, "%d",
				        data->mntco - 1);
				len += log;
			}
		}
	}
	bzero(mp->mnt_stat.f_mntfromname + len, MNAMELEN - len);
	DEBUG2G("mp %p: %s\n", mp, mp->mnt_stat.f_mntfromname);

	if (! secondary)
		/* Now handshaking with daemon */
		fuse_send_init(data, td);

out:
	if (err ) {
		data->mntco--;
		FUSE_LOCK;
		if (data->mntco == 0 && ! (data->dataflag & FSESS_OPENED)) {
			fdev->si_drv1 = NULL;
			fdata_destroy(data);
		}
		FUSE_UNLOCK;
		dev_rel(fdev);
	}
	return (err);
}

/*
 * Unmount system call
 */
static int
fuse_unmount(struct mount *mp, int mntflags)
{
	struct thread *td = curthread;
	int flags = 0, err = 0;
	struct fuse_data *data;
	struct fuse_secondary_data *fsdat = NULL;
	struct cdev *fdev;

	GIANT_REQUIRED;

	DEBUG2G("mp %p: %s\n", mp, mp->mnt_stat.f_mntfromname);
	/* Flag handling */
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	data = fusefs_get_data(mp);
	if (! data) {
		fsdat = fusefs_get_secdata(mp);
		data = fsdat->master;
	}

	if (sx_try_xlock(&data->mhierlock) == 0) {
		DEBUG2G("lock contested\n");
		return (EBUSY);
	}
	if (! fsdat) {
#if _DEBUG
		struct vnode *vp, *nvp;
#endif

		if (! (mntflags & MNT_FORCE ||
		    data->dataflag & FSESS_NEGLECT_SHARES ||
		    LIST_EMPTY(&data->slaves_head))) {
			err = EBUSY;
			goto unlock;
		}

#if _DEBUG
		MNT_ILOCK(mp);
		DEBUG2G("vnodes:\n");
		MNT_VNODE_FOREACH(vp, mp, nvp) {
			DEBUG2G("\n");
			vn_printf(vp, "...");
		}
		MNT_IUNLOCK(mp);
#endif

		/* Flush files -> vflush */
		/* There is 1 extra root vnode reference (mp->mnt_data). */
		if ((err = vflush(mp, 1, flags, td))) {
			DEBUG2G("err %d\n", err);
			goto unlock;
		}
	}

	if (fsdat) {
		LIST_REMOVE(fsdat, slaves_link);
		free(fsdat, M_FUSEVFS);
	} else {
#if FUSE_HAS_DESTROY
		if (data->dataflag & FSESS_SYNC_UNMOUNT &&
		    ((sync_unmount == 1 &&
	              data->dataflag & FSESS_CAN_SYNC_UNMOUNT) ||
		     sync_unmount == 2) &&
		    !(mntflags & MNT_FORCE)) {
			struct fuse_dispatcher fdi;

			fdisp_init(&fdi, 0);
			fdisp_make(&fdi, mp, FUSE_DESTROY, FUSE_ROOT_ID, td,
			           NULL);
			fdisp_wait_answ(&fdi);
			/* ignore return value */
		}
#endif
		fdata_kick_set(data);

		data->mpri = FM_NOMOUNTED;
	}

unlock:
	sx_xunlock(&data->mhierlock);
	if (err)
		return (err);

	data->mntco--;
	FUSE_LOCK;
	fdev = data->fdev;
	DEBUG2G("mntco %d, opened 0x%x\n",
	        data->mntco, data->dataflag & FSESS_OPENED);
	if (data->mntco == 0 && ! (data->dataflag & FSESS_OPENED)) {
		data->fdev->si_drv1 = NULL;
		fdata_destroy(data);
	}
	FUSE_UNLOCK;
	dev_rel(fdev);
	mp->mnt_data = NULL;

	/* Other guys do this, I don't know what it is good for... */
	mp->mnt_flag &= ~MNT_LOCAL;

	return (0);
}		

/* stolen from portalfs */
static int
fuse_root(struct mount *mp, int flags, struct vnode **vpp)
{
	/*
	 * Return locked reference to root.
	 */
	struct thread *td = curthread;
	struct fuse_data *data = fusefs_get_data(mp);
	struct vnode *vp;

	DEBUG2G("mp %p: %s\n", mp, mp->mnt_stat.f_mntfromname);

	if (! data) {
		struct fuse_secondary_data *fsdat = fusefs_get_secdata(mp);
		int err;

		data = fsdat->master;
		sx_slock(&data->mhierlock);
		if (data->mpri == FM_PRIMARY)
			err = fuse_root(data->mp, flags, vpp);
		else
			err = ENXIO;
		sx_sunlock(&data->mhierlock);
		return (err);
	}

	vp = data->rvp;
	vref(vp);
	vn_lock(vp, flags | LK_RETRY);
	if (vp->v_type == VNON) {
		struct vattr va;

		(void)VOP_GETATTR(vp, &va, td->td_ucred);
	}
	*vpp = vp;
#if _DEBUG2G
	DEBUG2G("root node:\n");
	vn_printf(vp, " * ");
#endif
	return (0);
}

static int
fuse_statfs(struct mount *mp, struct statfs *sbp)
{
	struct thread *td = curthread;
	struct fuse_dispatcher fdi;
	struct fuse_statfs_out *fsfo;
	struct fuse_data *data;
	int err = 0;	

	DEBUG2G("mp %p: %s\n", mp, mp->mnt_stat.f_mntfromname);
	data = fusefs_get_data(mp);

	if (! data) {
		struct fuse_secondary_data *fsdat;

		fsdat = fusefs_get_secdata(mp);
		data = fsdat->master;

		sx_slock(&data->mhierlock);
		if (data->mpri == FM_PRIMARY)
			err = fuse_statfs(data->mp, sbp);
		else
			err = ENXIO;
		sx_sunlock(&data->mhierlock);
		return (err);
	}

	if (! (data->dataflag & FSESS_INITED))
		goto fake;

	if ((err = fdisp_simple_putget(&fdi, FUSE_STATFS, data->rvp, td,
	    NULL))) {
		if (err == ENOTCONN)
			/*
			 * We want to seem a legitimate fs even if the daemon
			 * is stiff dead... (so that, eg., we can still do path
			 * based unmounting after the daemon dies).
			 */
			goto fake;

		return (err);
	}

	fsfo = fdi.answ;

	sbp->f_blocks  = fsfo->st.blocks;
	sbp->f_bfree   = fsfo->st.bfree;
	sbp->f_bavail  = fsfo->st.bavail;
	sbp->f_files   = fsfo->st.files;
	sbp->f_ffree   = fsfo->st.ffree; /* cast from uint64_t to int64_t */
	sbp->f_namemax = fsfo->st.namelen;
	if (fuse_libabi_geq(fusefs_get_data(mp), 7, 3)) {
		/*
		 * fuse_kstatfs is created from a struct statvfs, we can fill
		 * the statfs struct by inverting sfs2svfs() of lib/libc/gen/statvfs.c
		 */
#if 0
		/*
		 * This would pretty much **ck up buffered IO,
		 * since this would overwrite mnt_stat.f_iosize
		 */
		sbp->f_iosize  = fsfo->st.bsize; /* cast from uint32_t to uint64_t */
#endif
		sbp->f_bsize = 0; /* userspace data is broken ... */
#if FUSE_KERNELABI_GEQ(7, 4)
		if (fuse_libabi_geq(fusefs_get_data(mp), 7, 4))
			/* ... unless both kernel and userspace speak 7.4 */
			sbp->f_bsize = fsfo->st.frsize; /* cast from uint32_t to uint64_t */
#endif
	} else
		/*
		 * fuse_kstatfs is also created from a struct statfs,
		 * conversion is direct
		 */
		sbp->f_bsize = fsfo->st.bsize; /* cast from uint32_t to uint64_t */

	DEBUG("fuse_statfs_out -- blocks: %llu, bfree: %llu, bavail: %llu, files: %llu, ffree: %llu, bsize: %i, namelen: %i\n",
	(unsigned long long)fsfo->st.blocks, (unsigned long long)fsfo->st.bfree, (unsigned long long)fsfo->st.bavail, (unsigned long long)fsfo->st.files, (unsigned long long)fsfo->st.ffree, fsfo->st.bsize, fsfo->st.namelen);

	fuse_ticket_drop(fdi.tick);

	return (0);
fake:
        sbp->f_blocks  = 0;
	sbp->f_bfree   = 0;
	sbp->f_bavail  = 0;
	sbp->f_files   = 0;
	sbp->f_ffree   = 0;
	sbp->f_namemax = 0;
	sbp->f_bsize   = 0;

	return (0);
}

/*
 *  ..._i, as "internal" -- we don't need to register it as a VFS op,
 *  so we might alter from the VFS_VGET signature
 */

int
fuse_vget_i(struct mount *mp, struct thread *td, uint64_t nodeid,
            enum vtype vtyp, struct vnode **vpp, enum vget_mode vmod,
            uint64_t parentid)
{
#define myflags LK_EXCLUSIVE | LK_RETRY
	int err = 0;
	struct fuse_vnode_data *fvdat;
	struct vnode *vp2;

	DEBUG("been asked for vno #%llu, parent #%llu\n",
	        (long long unsigned)nodeid, (long long unsigned)parentid);

	if (vtyp == VNON)
		return (EINVAL);

	if (nodeid == FUSE_ROOT_ID) {
		if (parentid != FUSE_NULL_ID)
			return (ENOENT);
		err = VFS_ROOT(mp, myflags, vpp);
		if (err)
			return (err);
		KASSERT(*vpp, ("we neither err'd nor found the root node"));
		goto found;
	}

	/*
	 * With vmod == VG_WANTNEW, caller wants to get a vnode for the id
	 * only if it's a new one. Hence, no use of trying to get
	 * to get one with the given id.
	 */
	if (vmod == VG_WANTNEW)
		*vpp = NULL;
	else if ((err = vfs_hash_get(mp, nodeid, /*flags*/ myflags, td, vpp,
		                     fuse_vnode_cmp, &nodeid)))
		return (err);

	/*
	 * If vmod == VG_FORCENEW, we also want a new vnode, but instead of
	 * just bitching when there is an old one with the given id, we
	 * go and search & destroy those ones...
	 */
	 if (*vpp && vmod == VG_FORCENEW) {
		fuse_vnode_teardown(*vpp, td, NULL, vtyp);
		*vpp = NULL;
	}

audit:
	if (*vpp) {
		DEBUG("vnode taken from hash\n");
		if ((*vpp)->v_type == vtyp) {
			if (vtyp == VDIR && parentid != FUSE_NULL_ID &&
			    VTOFUD(*vpp)->parent_nid != parentid) {
				DEBUG("parent mismatch\n");
				if (VTOFUD(*vpp)->parent_nid == FUSE_NULL_ID) {
					/*
					 * Deleted directory is to be reused.
					 * We adjust the nodeid to the new scenario.
					 */
					struct parentmanager_param pmp;
					struct vnode *xvp;

					DEBUG("dir has no parent, pushing in required\n");
					pmp.nodeid = nodeid;
					pmp.parent_nid = parentid;
					pmp.valid = 0;
					err = vfs_hash_get(mp, pmp.nodeid, 0,
					                   td, &xvp,
					                   fuse_vnode_setparent_cmp,
					                   &pmp);
					KASSERT(xvp == NULL,
					        ("findparent routine has fetched a vnode"));
				} else
					/* parent mismatch for a directory */
					err = EIO;

				if (err) {
					vput(*vpp);
					*vpp = NULL;
					return (err);
				}
			}
			goto found;
		} else if ((*vpp)->v_type == VNON) {
			DEBUG2G("vnode #%llu with no type\n", VTOILLU(*vpp));
			(*vpp)->v_type = vtyp;
			goto found;
		} else {
			fuse_vnode_ditch(*vpp, td);
			vput(*vpp);
		}
	} else if (parentid == FUSE_NULL_ID) {
		DEBUG("no vpp, no parentid => ENOENT\n");
		*vpp = NULL;
		return (ENOENT);
	}

	/* as the big guys say, malloc for your data before getnewvnode() */

	fvdat = malloc(sizeof(*fvdat), M_FUSEVN, M_WAITOK | M_ZERO);
	err = getnewvnode("fuse", mp, &fuse_vnops, vpp);
#if _DEBUG
	DEBUG2G("allocated new vnode:\n");
	vn_printf(*vpp, " * ");
#endif

	if (err) {
	        free(fvdat, M_FUSEVN);
		VNASSERT(! *vpp, *vpp,
		         ("Maybe I misunderstood how getnewvnode() works..."));
	        return (err);
	}

	err = vn_lock(*vpp, myflags);
	if (err)
		printf("fuse4bsd: leaking vnode %p\n", *vpp);
	else
		err = insmntque(*vpp, mp);
	if (err) {
	        free(fvdat, M_FUSEVN);
	        return (err);
	}

	/*
	 * There is no harm in fully initializing the vnode before trying
	 * at insertion, because vnodes are gc-d anyway. For the same reason,
	 * they _do_ have to be fully initialized here -- the gc routines should
	 * get the node in an as much predictable state as it's possible.
	 */
	fuse_vnode_init(*vpp, fvdat, nodeid, vtyp, parentid);
	err = vfs_hash_insert(*vpp, nodeid, /*flags*/ myflags, td, &vp2,
	                      fuse_vnode_bgdrop_cmp, fvdat);

	if (err) {
		free(fvdat, M_FUSEVN);
		/* XXX do something to tear down allocated inode?
		 * (other fss' code doesn't, so neither I...)
		 */ 
		return (err);
	}

	if (vp2) {
		DEBUG("gee, vfs hash collision for node #%llu\n", (unsigned long long)nodeid);
		if (vmod == VG_WANTNEW) {
			vput(vp2);
			*vpp = NULL;
			return (EEXIST);
		} else if (vmod == VG_FORCENEW) {
			fuse_vnode_teardown(vp2, td, NULL, vtyp);
			*vpp = NULL;
			goto audit;
		}
		vpp = &vp2;
		goto audit;
	}

found:
#if _DEBUG
	DEBUG2G("\n");
	vn_printf(*vpp, " * ");
#endif
	return (0);
#undef myflags
}
