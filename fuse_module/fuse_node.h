/*
 * Copyright (C) 2006 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_NODE_H_
#define _FUSE_NODE_H_

#include <sys/types.h>
#include <sys/mutex.h>

#include "fuse_file.h"
#include "fuse_nodehash.h"

enum {
    kFSNodeMagic    = 1,
    kFSNodeBadMagic = 2,
    kHNodeMagic     = 3,
};

#define FN_CREATING      0x00000001

struct fuse_vnode_data {
    uint32_t   fMagic;
    boolean_t  fInitialised;
    uint64_t   nid;
    uint64_t   nlookup;
    enum vtype vtype;
    uint64_t   parent_nid;

    struct mtx createlock;
    void      *creator;
    /* XXX: Clean up this multi-flag nonsense. Really. */
    int        flag;
    int        flags;
    uint32_t   c_flag;

    /*
     * The nodelock must be held when data in the FUSE node is accessed or
     * modified. Typically, we would take this lock at the beginning of a
     * vnop and drop it at the end of the vnop.
     */
    struct sx *nodelock;
    void      *nodelockowner;

    /*
     * The truncatelock guards against the EOF changing on us (that is, a
     * file resize) unexpectedly.
     */
    struct sx  *truncatelock;

    struct vnode *c_vp;
    struct vnode *parent;
    off_t      filesize; 
    off_t      newfilesize;

    struct     fuse_filehandle fufh[3];

    struct vattr      cached_attrs;
    struct timespec   cached_attrs_valid;
};
typedef struct fuse_vnode_data * fusenode_t;

#define VTOFUD(vp) \
    ((struct fuse_vnode_data *)FSNodeGenericFromHNode((vp)->v_data))
#define VTOI(vp)    (VTOFUD(vp)->nid)
#define VTOVA(vp)   (&(VTOFUD(vp)->cached_attrs))
#define VTOILLU(vp) ((unsigned long long)(VTOFUD(vp) ? VTOI(vp) : 0))

#define FUSE_NULL_ID 0

static __inline void
fuse_invalidate_attr(struct vnode *vp)
{
    if (VTOFUD(vp)) {
        bzero(&VTOFUD(vp)->cached_attrs_valid, sizeof(struct timespec));
    }
}

MALLOC_DECLARE(M_FUSEVN);

vfs_hash_cmp_t fuse_vnode_cmp;
vfs_hash_cmp_t fuse_vnode_setparent_cmp;

void fuse_vnode_init(struct vnode *vp, struct fuse_vnode_data *fvdat,
                     uint64_t nodeid, enum vtype vtyp, uint64_t parentid);
void fuse_vnode_ditch(struct vnode *vp, struct thread *td);
void fuse_vnode_teardown(struct vnode *vp, struct thread *td,
                         struct ucred *cred, enum vtype vtyp);

enum vget_mode { VG_NORMAL, VG_WANTNEW, VG_FORCENEW };

struct get_filehandle_param {
    enum fuse_opcode opcode;
    uint8_t          do_gc:1;
    uint8_t          do_new:1;
    int explicitidentity;
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

#define C_NEED_RVNODE_PUT    0x00001
#define C_NEED_DVNODE_PUT    0x00002
#define C_ZFWANTSYNC         0x00004
#define C_FROMSYNC           0x00008
#define C_MODIFIED           0x00010
#define C_NOEXISTS           0x00020
#define C_DELETED            0x00040
#define C_HARDLINK           0x00080
#define C_FORCEUPDATE        0x00100
#define C_HASXATTRS          0x00200
#define C_NEED_DATA_SETSIZE  0x01000
#define C_NEED_RSRC_SETSIZE  0x02000

#define C_CREATING           0x04000
#define C_ACCESS_NOOP        0x08000

int
FSNodeGetOrCreateFileVNodeByID(struct mount *mp,
                               uint64_t   nodeid,
                               struct vnode *dvp,
                               enum vtype vtyp,
                               uint64_t   insize,
                               struct vnode **vnPtr,
                               int        flags);

void FSNodeScrub(struct fuse_vnode_data *fvdat);

int
fuse_vget_i(struct mount *mp,
            struct thread *td,
            uint64_t nodeid,
            enum vtype vtyp,
            struct vnode **vpp,
            enum vget_mode vmod,
            uint64_t parentid);
#ifdef XXXIP
int
fuse_vget_i(struct mount         *mp,
            uint64_t              nodeid,
            vfs_context_t         context,
            struct vnode         *dvp,
            struct vnode         *vpp,
            struct componentname *cnp,
            enum vtype            vtyp,
            uint64_t              size,
            enum vget_mode        mode,
            uint64_t              parentid);
#endif

#endif /* _FUSE_NODE_H_ */
