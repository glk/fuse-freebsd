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
#include "fuse_node.h"
#include "fuse_ipc.h"
#include "fuse_internal.h"

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

static vfs_mount_t fuse_vfs_mount;
static vfs_unmount_t fuse_vfs_unmount;
static vfs_root_t fuse_vfs_root;
static vfs_statfs_t fuse_vfs_statfs;

struct vfsops fuse_vfsops = {
	.vfs_mount   = fuse_vfs_mount,
	.vfs_unmount = fuse_vfs_unmount,
	.vfs_root    = fuse_vfs_root,
	.vfs_statfs  = fuse_vfs_statfs,
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

/*************
 *
 * >>> VFS ops
 *
 *************/

/*
 * Mount system call
 */
static int
fuse_vfs_mount(struct mount *mp)
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
		fuse_internal_send_init(data, td);

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

static int
fuse_vfs_unmount(struct mount *mp, int mntflags)
{
    int err   = 0;
    int flags = 0;

    struct fuse_data      *data;
    struct cdev           *fdev;
    struct fuse_dispatcher fdi;
    struct thread         *td = curthread;

    fuse_trace_printf_vfsop();

    GIANT_REQUIRED;

    if (mntflags & MNT_FORCE) {
        flags |= FORCECLOSE;
    }

    data = fusefs_get_data(mp);
    if (!data) {
        panic("no private data for mount point?");
    }

    /* There is 1 extra root vnode reference (mp->mnt_data). */
    err = vflush(mp, 1, flags, td);
    if (err) {
        debug_printf("vflush failed");
        return (err);
    }

    if (fdata_kick_get(data)) {
        goto alreadydead;
    }

    fdisp_init(&fdi, 0);
    fdisp_make(&fdi, mp, FUSE_DESTROY, 0, td, NULL);
    err = fdisp_wait_answ(&fdi);
    if (!err) {
        fuse_ticket_drop(fdi.tick);
    }

    fdata_kick_set(data);

alreadydead:
    data->mpri = FM_NOMOUNTED;
    data->mntco--;

    FUSE_LOCK();
    fdev = data->fdev;
    if (data->mntco == 0 && !(data->dataflag & FSESS_OPENED)) {
        data->fdev->si_drv1 = NULL;
        fdata_destroy(data);
    }
    FUSE_UNLOCK();

    MNT_ILOCK(mp);
    mp->mnt_data = NULL;
    mp->mnt_flag &= ~MNT_LOCAL;
    MNT_IUNLOCK(mp);

    dev_rel(fdev);

    return (0);
}        

static int
fuse_vfs_root(struct mount *mp, int lkflags, struct vnode **vpp)
{
    int err;

    err = fuse_vnode_get(mp, FUSE_ROOT_ID, NULL, vpp, NULL, VDIR, 0);
    return (err);
}

static int
fuse_vfs_statfs(struct mount *mp, struct statfs *sbp)
{
    struct fuse_dispatcher fdi;
    struct fuse_statfs_out *fsfo;
    struct fuse_data *data;
    int err = 0;	

    DEBUG2G("mp %p: %s\n", mp, mp->mnt_stat.f_mntfromname);
    data = fusefs_get_data(mp);

    if (!(data->dataflag & FSESS_INITED))
        goto fake;

    if ((err = fdisp_simple_vfs_statfs(&fdi, mp))) {
        if (err == ENOTCONN) {
            /*
             * We want to seem a legitimate fs even if the daemon
             * is stiff dead... (so that, eg., we can still do path
             * based unmounting after the daemon dies).
             */
            goto fake;
        }
        return (err);
    }

    fsfo = fdi.answ;

    sbp->f_blocks  = fsfo->st.blocks;
    sbp->f_bfree   = fsfo->st.bfree;
    sbp->f_bavail  = fsfo->st.bavail;
    sbp->f_files   = fsfo->st.files;
    sbp->f_ffree   = fsfo->st.ffree; /* cast from uint64_t to int64_t */
    sbp->f_namemax = fsfo->st.namelen;
    sbp->f_bsize   = fsfo->st.frsize; /* cast from uint32_t to uint64_t */

    DEBUG("fuse_statfs_out -- blocks: %llu, bfree: %llu, bavail: %llu, "
        "files: %llu, ffree: %llu, bsize: %i, namelen: %i\n",
        (unsigned long long)fsfo->st.blocks, (unsigned long long)fsfo->st.bfree,
        (unsigned long long)fsfo->st.bavail, (unsigned long long)fsfo->st.files,
        (unsigned long long)fsfo->st.ffree, fsfo->st.bsize, fsfo->st.namelen);

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
