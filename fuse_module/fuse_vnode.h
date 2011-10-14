/*
 * Private data of a fuse vnode
 */
struct fuse_vnode_data {
	uint64_t nid;
	uint64_t nlookup;
	uint64_t parent_nid;

	int flags;
	LIST_HEAD(, fuse_filehandle) fh_head;
	int fh_counter;

	struct vattr cached_attrs;
	struct timespec cached_attrs_valid;

#ifdef FUSE_HAS_CREATE
	struct componentname *germcnp;
#endif
};

#define VTOFUD(vp) (((struct fuse_vnode_data *)(vp)->v_data))
#define VTOI(vp) (VTOFUD(vp)->nid)
#define VTOVA(vp) (&(VTOFUD(vp)->cached_attrs))
#define VTOILLU(vp) ((unsigned long long)(VTOFUD(vp) ? VTOI(vp) : 0))

#define FUSE_NULL_ID 0

static __inline void
fuse_invalidate_attr(struct vnode *vp)
{
	if (VTOFUD(vp))
		bzero(&VTOFUD(vp)->cached_attrs_valid, sizeof(struct timespec));
}

MALLOC_DECLARE(M_FUSEVN);

/* Parameter structure for parent management via the VFS hash */
struct parentmanager_param {
	uint64_t nodeid;
	uint64_t parent_nid;
	uint8_t valid:1;
};

/*
 * vnode comparison routines for the VFS hash
 */
vfs_hash_cmp_t fuse_vnode_cmp;
vfs_hash_cmp_t fuse_vnode_setparent_cmp;

/*
 * vnode management routines
 */
void fuse_vnode_init(struct vnode *vp, struct fuse_vnode_data *fvdat,
                     uint64_t nodeid, enum vtype vtyp, uint64_t parentid);
/* prohibit further usage of vnode */
void fuse_vnode_ditch(struct vnode *vp, struct thread *td);
/* lazy vnode teardown routine */
void fuse_vnode_teardown(struct vnode *vp, struct thread *td,
                         struct ucred *cred, enum vtype vtyp);

enum vget_mode { VG_NORMAL, VG_WANTNEW, VG_FORCENEW };

int fuse_vget_i(struct mount *mp, struct thread *td, uint64_t nodeid,
                enum vtype vtyp, struct vnode **vpp, enum vget_mode vmod,
                uint64_t parentid);

/* parameter struct for fuse_get_filehandle() */
struct get_filehandle_param {
	enum fuse_opcode opcode;
	uint8_t do_gc:1;
	uint8_t do_new:1;
};

int fuse_get_filehandle(struct vnode *vp, struct thread *td, struct ucred *cred,
                   int mode, struct fuse_filehandle **fufhp,
                   struct get_filehandle_param *gefhp);
