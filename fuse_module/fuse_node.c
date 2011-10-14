/*
 * Copyright (C) 2006 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#include "fuse.h"
#include "fuse_ipc.h"
#include "fuse_locking.h"
#include "fuse_node.h"

void
FSNodeScrub(struct fuse_vnode_data *fvdat)
{
    lck_mtx_destroy(fvdat->createlock, fuse_lock_group);
    lck_rw_destroy(fvdat->nodelock, fuse_lock_group);
    lck_rw_destroy(fvdat->truncatelock, fuse_lock_group);
    fvdat->fMagic = kFSNodeBadMagic;
}       

errno_t
FSNodeGetOrCreateFileVNodeByID(mount_t    mp,
                               uint64_t   nodeid,
                               vnode_t    dvp,
                               enum vtype vtyp,
                               uint64_t   insize,
                               vnode_t   *vnPtr,
                               int        flags)
{
    int      err;
    int      junk;
    vnode_t  vn;
    HNodeRef hn;
    vnode_t  dirVN;
    dev_t    dummy_device;
    struct fuse_vnode_data *fvdat = NULL;
    struct fuse_data *mntdata;
    int markroot = FALSE;
    uint64_t size = 0;

    if (insize == 0xffffffff) {
        markroot = TRUE;
    } else {
        size = insize;
    }

    hn = NULL;
    vn = NULL;
    dirVN = NULL;

    mntdata = vfs_fsprivate(mp);
    dummy_device = (dev_t)mntdata->fdev;

    err = HNodeLookupCreatingIfNecessary(dummy_device,
                                         (ino_t)nodeid, // XXXXXXXX
                                         0 /* fork index */,
                                         &hn,
                                         &vn);
    if ((err == 0) && (vn == NULL)) {

        struct vnode_fsparam params;
        fvdat = (struct fuse_vnode_data *)FSNodeGenericFromHNode(hn);
        if (!fvdat->fInitialised) {
            int k;
            fvdat->fMagic = kFSNodeMagic;
            fvdat->fInitialised = TRUE;
            fvdat->nid = nodeid;
            fvdat->vtype = vtyp;
            fvdat->parent = NULL;
            fvdat->filesize = size;
            fvdat->newfilesize = 0;
            fvdat->nlookup = 0;
            if (dvp) {
                fvdat->parent_nid = VTOFUD(dvp)->nid;
            } else {
                fvdat->parent_nid = 0;
            }
            for (k = 0; k < FUFH_MAXTYPE; k++) {
                fvdat->fufh[k].fufh_flags = 0;
            }
            fvdat->createlock = lck_mtx_alloc_init(fuse_lock_group, fuse_lock_attr);
            fvdat->nodelock = lck_rw_alloc_init(fuse_lock_group, fuse_lock_attr);
            fvdat->truncatelock = lck_rw_alloc_init(fuse_lock_group, fuse_lock_attr);
            fvdat->creator = current_thread();
            fvdat->flag = flags;
            //LIST_INIT(&fvdat->fh_head);
        }

        if (err == 0) {
            params.vnfs_mp         = mp;
            params.vnfs_vtype      = vtyp;
            params.vnfs_str        = NULL;
            params.vnfs_dvp        = NULL; // dvp; XXXXXXXXXXXXXXXXXXXXXXXXXX
            params.vnfs_fsnode     = hn;
            params.vnfs_vops       = fuse_vnode_operations;
            params.vnfs_marksystem = FALSE;
            params.vnfs_rdev       = 0;
            params.vnfs_cnp        = NULL;
            params.vnfs_flags      = VNFS_NOCACHE | VNFS_CANTCACHE;
            params.vnfs_filesize   = size;
            params.vnfs_markroot   = markroot;

            err = vnode_create(VNCREATE_FLAVOR, sizeof(params), &params, &vn);
        }

        if (err == 0) {
            HNodeAttachVNodeSucceeded(hn, 0 /* forkIndex */, vn);
            if (markroot == TRUE) {
                fvdat->parent = vn;
            }
        } else {
            if (HNodeAttachVNodeFailed(hn, 0 /* forkIndex */)) {
                FSNodeScrub(fvdat);
                HNodeScrubDone(hn);
            }
        }
    }

    if (err == 0) {
        *vnPtr = vn;
        vnode_settag(vn, VT_KERNFS);
    }

    if (dirVN != NULL) {
        junk = vnode_put(dirVN);
        /* assert(junk == 0); */
    }

    /* assert((err == 0) == (*vnPtr != NULL); */

    return err;
}

int
fuse_vget_i(mount_t               mp,
            uint64_t              nodeid,
            vfs_context_t         context,
            vnode_t               dvp,
            vnode_t              *vpp,
            struct componentname *cnp,
            enum vtype            vtyp,
            uint64_t              size,
            enum vget_mode        mode,
            uint64_t              parentid)
{
    int err = 0;

    debug_printf("dvp=%p\n", dvp);

    if (vtyp == VNON) {
        return EINVAL;
    }

#if 0 //XROOT
    if (nodeid == FUSE_ROOT_ID) {
        *vpp = fusefs_get_data(mp)->rvp; //XROOT
        err = vnode_get(*vpp);
        if (err) {
            *vpp = NULLVP;
            return err;
        }
        goto found;
    }
#endif

    err = FSNodeGetOrCreateFileVNodeByID(mp, nodeid, dvp, vtyp, size, vpp, 0);
    if (err) {
        return err;
    }

    cache_enter(dvp, *vpp, cnp);

found:
    VTOFUD(*vpp)->nlookup++;

    return 0;
}
