/*
 * Module load/unload stuff.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/buf.h>
#include <sys/sysctl.h>

#include "fuse.h"

static void			 fuse_bringdown(eventhandler_tag eh_tag);
static int			 fuse_loader(struct module *m, int what, void *arg);

int fuse_useco = 0;
#if USE_FUSE_LOCK
struct mtx fuse_mtx;
#endif


#ifdef USE_OLD_CLONEHANDLER_API
extern void fusedev_clone(void *arg, char *name, int namelen, struct cdev **dev);
#else
extern void fusedev_clone(void *arg, struct ucred *cred, char *name,
                          int namelen, struct cdev **dev);
#endif

extern struct vfsops fuse_vfsops;
extern struct cdevsw fuse_cdevsw;
extern struct vop_vector fuse_vnops;
extern struct fileops fuse_fileops;
extern struct clonedevs *fuseclones;
#if FMASTER
extern struct cdevsw fmaster_cdevsw[5];
static struct cdev *fmaster_dev[5];
#endif
extern int fuse_pbuf_freecnt;
#if FUSE_HAS_CREATE
extern struct vop_vector fuse_germ_vnops;
extern vop_access_t fuse_germ_access;
#endif

static struct vfsconf fuse_vfsconf = {
	.vfc_version = VFS_VERSION,
	.vfc_name = "fusefs",
	.vfc_vfsops = &fuse_vfsops,
	.vfc_typenum = -1,
	.vfc_flags = VFCF_SYNTHETIC
};

SYSCTL_INT(_vfs_fuse, OID_AUTO, kernelabi_major, CTLFLAG_RD,
            0, FUSE_KERNEL_VERSION, "FUSE kernel abi major version");
SYSCTL_INT(_vfs_fuse, OID_AUTO, kernelabi_minor, CTLFLAG_RD,
            0, FUSE_KERNEL_MINOR_VERSION, "FUSE kernel abi minor version");

/******************************
 *
 * >>> Module management stuff
 *
 ******************************/

static void
fuse_bringdown(eventhandler_tag eh_tag)
{
#if FMASTER
	int i;
#endif

	EVENTHANDLER_DEREGISTER(dev_clone, eh_tag);

	clone_cleanup(&fuseclones);
#if USE_FUSE_LOCK
	mtx_destroy(&fuse_mtx);
#endif
#if FMASTER
	for (i = 0; i < 5; i++) {
		DEBUG("destroying fmaster%d\n", i);	
		destroy_dev(fmaster_dev[i]);
	}
#endif
}

static int
fuse_loader(struct module *m, int what, void *arg)
{
	static eventhandler_tag  eh_tag = NULL;
	int err = 0;
#if FMASTER
	int i;
	char *fmaster_name = "fmasterx";
#endif

	GIANT_REQUIRED;

	switch (what) {
	case MOD_LOAD:                /* kldload */

		fuse_fileops.fo_ioctl    = vnops.fo_ioctl;
		fuse_fileops.fo_poll     = vnops.fo_poll;
		fuse_fileops.fo_kqfilter = vnops.fo_kqfilter;
		fuse_fileops.fo_stat     = vnops.fo_stat;

		fuse_pbuf_freecnt = nswbuf / 2 + 1;

#if FUSE_HAS_CREATE
		memcpy(&fuse_germ_vnops, &dead_vnodeops, sizeof(struct vop_vector));
		fuse_germ_vnops.vop_access = fuse_germ_access;
		fuse_germ_vnops.vop_open = fuse_vnops.vop_open;
#endif

		clone_setup(&fuseclones);
#ifdef USE_FUSE_LOCK
		mtx_init(&fuse_mtx, "fuse_mtx", NULL, MTX_DEF);
#endif
		eh_tag = EVENTHANDLER_REGISTER(dev_clone, fusedev_clone, 0,
		                               1000);
		if (eh_tag == NULL) {
			clone_cleanup(&fuseclones);
#if USE_FUSE_LOCK
			mtx_destroy(&fuse_mtx);
#endif
			return (ENOMEM);
		}
#if FMASTER
		for (i=0; i<5; i++) {
			fmaster_name[7] = i + '0';
			fmaster_dev[i] = make_dev(&fmaster_cdevsw[i], 0,
                                                  UID_ROOT, GID_WHEEL,
						  S_IWUSR, fmaster_name);
		}
#endif
		/* Duh, it's static... */
		/* vfs_register(&fuse_vfsconf); */

		/* vfs_modevent ignores its first arg */
		if ((err = vfs_modevent(NULL, what, &fuse_vfsconf)))
			fuse_bringdown(eh_tag);
		else
			printf("fuse4bsd: version %s, FUSE ABI %d.%d\n"
#ifdef KERNCONFDIR
			       "fuse4bsd: compiled against kernel config "
			       KERNCONFDIR "\n"
#endif
			       , FUSE4BSD_VERSION,
			       FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);

		break;
	case MOD_UNLOAD:
		KASSERT(fuse_useco >= 0,
		        ("fuse_useco is negative: %d", fuse_useco));
		if (fuse_useco > 0) {
			DEBUG2G("fuse_useco %d\n", fuse_useco);
		        return (EBUSY);
		}

		if ((err = vfs_modevent(NULL, what, &fuse_vfsconf)))
			return (err);

		/*
		 * at this point the counter falls below zero thus new init
		 * attempts will know that no brownie for them
		 */
		fuse_useco--;

		fuse_bringdown(eh_tag);

		/* vfs_unregister(&fuse_vfsconf); */

		break;
	default:
		return (EINVAL);
	}

	return (err);
}

/* Registering the module */

static moduledata_t fuse_moddata = {
	"fuse",
	fuse_loader,
	&fuse_vfsconf
};               	
DECLARE_MODULE(fuse, fuse_moddata, SI_SUB_VFS, SI_ORDER_MIDDLE);
MODULE_VERSION(fuse, 1);
