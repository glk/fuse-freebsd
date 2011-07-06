/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_NODE_H_
#define _FUSE_NODE_H_

#include <sys/types.h>
#include <sys/mutex.h>

#include "fuse_file.h"

#define FN_CREATING          0x00000002
#define FN_REVOKED           0x00000020

struct fuse_vnode_data {
    /** self **/
    uint64_t   nid;

    /** parent **/
    /* XXXIP very likely to be stale, it's not updated in rename() */
    uint64_t   parent_nid;

    /** I/O **/
    struct     fuse_filehandle fufh[FUFH_MAXTYPE];

    /** flags **/
    /* XXX: Clean up this multi-flag nonsense. Really. */
    uint32_t   flag;
    int        flags;
    uint32_t   c_flag;

    /** meta **/

    struct timespec   cached_attrs_valid;
    struct vattr      cached_attrs;
    off_t             filesize;
    uint64_t          nlookup;
    enum vtype        vtype;

    /*
     * The nodelock must be held when data in the FUSE node is accessed or
     * modified. Typically, we would take this lock at the beginning of a
     * vnop and drop it at the end of the vnop.
     */
    struct sx  nodelock;
    void      *nodelockowner;

    /*
     * The truncatelock guards against the EOF changing on us (that is, a
     * file resize) unexpectedly.
     */
    struct sx  truncatelock;
};

#define VTOFUD(vp) \
    ((struct fuse_vnode_data *)((vp)->v_data))
#define VTOI(vp)    (VTOFUD(vp)->nid)
#define VTOVA(vp)   (&(VTOFUD(vp)->cached_attrs))
#define VTOILLU(vp) ((uint64_t)(VTOFUD(vp) ? VTOI(vp) : 0))

#define FUSE_NULL_ID 0

extern struct vop_vector fuse_vnops;
extern int fuse_data_cache_enable;
extern int fuse_mmap_enable;

static __inline__
void
fuse_invalidate_attr(struct vnode *vp)
{
    if (VTOFUD(vp)) {
        bzero(&VTOFUD(vp)->cached_attrs_valid, sizeof(struct timespec));
    }
}

static __inline int
fuse_vnode_cache_enable(struct vnode *vp)
{
    return (fuse_data_cache_enable);
}

static __inline int
fuse_vnode_mmap_enable(struct vnode *vp)
{
    return (fuse_mmap_enable && fuse_data_cache_enable);
}

int fuse_isvalid_attr(struct vnode *vp);

void fuse_vnode_destroy(struct vnode *vp);

int fuse_vnode_get(struct mount         *mp,
                   uint64_t              nodeid,
                   struct vnode         *dvp,
                   struct vnode        **vpp,
                   struct componentname *cnp,
                   enum vtype            vtyp,
                   uint64_t              size);

void fuse_vnode_open(struct vnode *vp,
                     int32_t fuse_open_flags,
                     struct thread *td);

void fuse_vnode_setsize(struct vnode *vp, off_t newsize);

#endif /* _FUSE_NODE_H_ */
