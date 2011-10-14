/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

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
#include <sys/fnv_hash.h>
#include <sys/priv.h>
#include <security/mac/mac_framework.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>

#include "fuse.h"
#include "fuse_node.h"
#include "fuse_internal.h"
#include "fuse_io.h"
#include "fuse_ipc.h"

#define FUSE_DEBUG_MODULE VNOPS
#include "fuse_debug.h"

MALLOC_DEFINE(M_FUSEVN, "fuse_vnode", "fuse vnode private data");

static int fuse_node_count = 0;
SYSCTL_INT(_vfs_fuse, OID_AUTO, node_count, CTLFLAG_RD,
            &fuse_node_count, 0, "");

int fuse_data_cache_enable = 1;
SYSCTL_INT(_vfs_fuse, OID_AUTO, data_cache_enable, CTLFLAG_RW,
           &fuse_data_cache_enable, 0, "");

int fuse_data_cache_invalidate = 0;
SYSCTL_INT(_vfs_fuse, OID_AUTO, data_cache_invalidate, CTLFLAG_RW,
           &fuse_data_cache_invalidate, 0, "");

int fuse_mmap_enable = 1;
SYSCTL_INT(_vfs_fuse, OID_AUTO, mmap_enable, CTLFLAG_RW,
           &fuse_mmap_enable, 0, "");

int fuse_refresh_size = 0;
SYSCTL_INT(_vfs_fuse, OID_AUTO, refresh_size, CTLFLAG_RW,
           &fuse_refresh_size, 0, "");

int fuse_sync_resize = 1;
SYSCTL_INT(_vfs_fuse, OID_AUTO, sync_resize, CTLFLAG_RW,
           &fuse_sync_resize, 0, "");

int fuse_fix_broken_io = 0;
SYSCTL_INT(_vfs_fuse, OID_AUTO, fix_broken_io, CTLFLAG_RW,
           &fuse_fix_broken_io, 0, "");

static void
fuse_vnode_init(struct vnode *vp, struct fuse_vnode_data *fvdat,
    uint64_t nodeid, enum vtype vtyp)
{
    int i;

    fvdat->nid = nodeid;
    if (nodeid == FUSE_ROOT_ID) {
        vp->v_vflag |= VV_ROOT;
    }
    vp->v_type = vtyp;
    vp->v_data = fvdat;

    for (i = 0; i < FUFH_MAXTYPE; i++)
        fvdat->fufh[i].fh_type = FUFH_INVALID;

    atomic_add_acq_int(&fuse_node_count, 1);
}

void
fuse_vnode_destroy(struct vnode *vp)
{
    struct fuse_vnode_data *fvdat = vp->v_data;

    vp->v_data = NULL;
    free(fvdat, M_FUSEVN);

    atomic_subtract_acq_int(&fuse_node_count, 1);
}

static int
fuse_vnode_cmp(struct vnode *vp, void *nidp)
{
    return (VTOI(vp) != *((uint64_t *)nidp));
}

static uint32_t __inline
fuse_vnode_hash(uint64_t id)
{
    return (fnv_32_buf(&id, sizeof(id), FNV1_32_INIT));
}

static int
fuse_vnode_alloc(struct mount *mp,
            struct thread *td,
            uint64_t nodeid,
            enum vtype vtyp,
            struct vnode **vpp)
{
    const int lkflags = LK_EXCLUSIVE | LK_RETRY;
    struct fuse_vnode_data *fvdat;
    struct vnode *vp2;
    int err = 0;

    DEBUG("been asked for vno #%ju\n", (uintmax_t)nodeid);

    if (vtyp == VNON) {
        return EINVAL;
    }

    *vpp = NULL;
    err = vfs_hash_get(mp, fuse_vnode_hash(nodeid), lkflags, td, vpp,
        fuse_vnode_cmp, &nodeid);
    if (err)
        return (err);

    if (*vpp) {
        MPASS((*vpp)->v_type == vtyp && (*vpp)->v_data != NULL);
        DEBUG("vnode taken from hash\n");
        return (0);
    }

    fvdat = malloc(sizeof(*fvdat), M_FUSEVN, M_WAITOK | M_ZERO);
    err = getnewvnode("fuse", mp, &fuse_vnops, vpp);
    if (err) {
        free(fvdat, M_FUSEVN);
        return (err);
    }

    vn_lock(*vpp, lkflags);
    err = insmntque(*vpp, mp);
    ASSERT_VOP_ELOCKED(*vpp, "fuse_vnode_alloc");
    if (err) {
        VOP_UNLOCK(*vpp, 0);
        free(fvdat, M_FUSEVN);
        *vpp = NULL;
        return (err);
    }

    fuse_vnode_init(*vpp, fvdat, nodeid, vtyp);
    err = vfs_hash_insert(*vpp, fuse_vnode_hash(nodeid), lkflags,
        td, &vp2, fuse_vnode_cmp, &nodeid);

    if (err) {
        VOP_UNLOCK(*vpp, 0);
        fuse_vnode_destroy(*vpp);
        *vpp = NULL;
        return (err);
    }

    /*
     * XXXIP: Prevent silent vnode reuse. It may happen because several fuse
     * filesystems ignore inode numbers
     */
    KASSERT(vp2 == NULL,
        ("vfs hash collision for node #%ju\n", (uintmax_t)nodeid));
    ASSERT_VOP_ELOCKED(*vpp, "fuse_vnode_alloc");

    return (0);
}

int
fuse_vnode_get(struct mount         *mp,
               uint64_t              nodeid,
               struct vnode         *dvp,
               struct vnode         **vpp,
               struct componentname *cnp,
               enum vtype            vtyp)
{
    struct thread *td = (cnp != NULL ? cnp->cn_thread : curthread);
    int err = 0;

    debug_printf("dvp=%p\n", dvp);

    err = fuse_vnode_alloc(mp, td, nodeid, vtyp, vpp);
    if (err) {
        return err;
    }

    if (dvp != NULL) {
        MPASS((cnp->cn_flags & ISDOTDOT) == 0);
        MPASS(!(cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.'));
        fuse_vnode_setparent(*vpp, dvp);
    }
    if (dvp != NULL && cnp != NULL && (cnp->cn_flags & MAKEENTRY) != 0) {
        ASSERT_VOP_LOCKED(*vpp, "fuse_vnode_get");
        ASSERT_VOP_LOCKED(dvp, "fuse_vnode_get");
        cache_enter(dvp, *vpp, cnp);
    }
    VTOFUD(*vpp)->nlookup++;

    return 0;
}

void
fuse_vnode_open(struct vnode *vp, int32_t fuse_open_flags, struct thread *td)
{
    /*
     * Funcation is called for every vnode open.
     * Merge fuse_open_flags it may be 0
     *
     * XXXIP: Handle FOPEN_DIRECT_IO and FOPEN_KEEP_CACHE
     */

    if (vnode_vtype(vp) == VREG) {
        /* XXXIP prevent getattr, by using cached node size */
        vnode_create_vobject(vp, 0, td);
    }
}

int
fuse_isvalid_attr(struct vnode *vp)
{
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct timespec uptsp;

    nanouptime(&uptsp);
    return fuse_timespec_cmp(&uptsp, &fvdat->cached_attrs_valid, <=);
}

int
fuse_vnode_savesize(struct vnode *vp, struct ucred *cred)
{
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct thread *td = curthread;
    struct fuse_filehandle *fufh = NULL;
    struct fuse_dispatcher  fdi;
    struct fuse_setattr_in *fsai;
    int err = 0;

    DEBUG("inode=%jd size=%jd\n", VTOI(vp), fvdat->filesize);
    ASSERT_VOP_ELOCKED(vp, "fuse_io_extend");

    if (fuse_isdeadfs(vp)) {
        return EBADF;
    }

    if (vnode_vtype(vp) == VDIR) {
        return EISDIR;
    }

    if (vfs_isrdonly(vnode_mount(vp))) {
        return EROFS;
    }

    if (cred == NULL) {
        cred = td->td_ucred;
    }

    fdisp_init(&fdi, sizeof(*fsai));
    fdisp_make_vp(&fdi, FUSE_SETATTR, vp, td, cred);
    fsai = fdi.indata;
    fsai->valid = 0;

    // Truncate to a new value.
    fsai->size = fvdat->filesize;
    fsai->valid |= FATTR_SIZE;

    fuse_filehandle_getrw(vp, FUFH_WRONLY, &fufh);
    if (fufh) {
        fsai->fh = fufh->fh_id;
        fsai->valid |= FATTR_FH;
    }

    err = fdisp_wait_answ(&fdi);
    fdisp_destroy(&fdi);
    if (err == 0)
	    fvdat->flag &= ~FN_SIZECHANGE;

    fuse_invalidate_attr(vp);

    return err;
}

void
fuse_vnode_refreshsize(struct vnode *vp, struct ucred *cred)
{

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct vattr va;

    if ((fvdat->flag & FN_SIZECHANGE) != 0 ||
        (fuse_refresh_size == 0 && fvdat->filesize != 0) ||
	fuse_isvalid_attr(vp))
        return;

    VOP_GETATTR(vp, &va, cred);
    DEBUG("refreshed file size: %jd\n", VTOFUD(vp)->filesize);
}

int
fuse_vnode_setsize(struct vnode *vp, struct ucred *cred, off_t newsize)
{
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    off_t oldsize;
    int err = 0;

    DEBUG("inode=%jd oldsize=%jd newsize=%jd\n",
        VTOI(vp), fvdat->filesize, newsize);
    ASSERT_VOP_ELOCKED(vp, "fuse_vnode_setsize");

    oldsize = fvdat->filesize;
    fvdat->filesize = newsize;
    fvdat->flag |= FN_SIZECHANGE;

    if (newsize < oldsize) {
        err = vtruncbuf(vp, cred, curthread, newsize, fuse_iosize(vp));
    }

    vnode_pager_setsize(vp, newsize);
    fuse_invalidate_attr(vp);

    return err;
}
