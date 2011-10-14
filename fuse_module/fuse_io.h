/*
 * Fuse filehandle, for in-kernel bookkeping of daemon's filehandles
 * (which are presented to us as an opque 64 bit id, see the fh_id
 * member of the struct).
 * It serves as private data for in-kernel file structures, but can
 * as well occur standalone.
 */

struct fuse_filehandle {
	struct vnode *fh_vp;
	uint64_t fh_id;
	int mode;
	struct ucred *cred;
	pid_t pid;
	int useco;
	LIST_ENTRY(fuse_filehandle) fh_link;
	struct file *fp;
	int flags;
	enum fuse_opcode op;
};

#define FTOFH(fp) ((struct fuse_filehandle *)(fp)->f_data)

#define ASSERT_VOP_ELOCKED__FH(vp) ASSERT_VOP_ELOCKED((vp), "unsafe filehandle access")
#define ASSERT_VOP_LOCKED__FH(vp) ASSERT_VOP_LOCKED((vp), "unsafe filehandle access")

/* prototype for processing an input data buffer and an uio
   for reading related acivities */
typedef	int fuse_buffeater_t(struct uio *uio, size_t reqsize, void *buf, size_t bufsize, void *param);

/* data used through an I/O operation */
struct fuse_io_data {
	struct vnode *vp;
	struct fuse_filehandle *fufh;
	struct uio *uio;
	struct ucred *cred;
	struct thread *td;
	enum fuse_opcode opcode;
	fuse_buffeater_t *buffeater;
	void *param;
};

int fuse_io_dispatch(struct vnode *vp, struct fuse_filehandle *fufh,
                     struct uio *uio, struct ucred *cred, int flag,
                     struct thread *td);
int fuse_io_file(struct file *fp, struct uio *uio, struct ucred *cred,
                 int flags, struct thread *td);
int fuse_io_vnode(struct vnode *vp, struct ucred *cred, struct uio *uio,
                  int ioflag);
int fuse_strategy_i(struct vnode *vp, struct buf *bp,
                    struct fuse_filehandle *fufh, enum fuse_opcode op);

/*
 * XXX for blocking vnode usage, it seems that changing vnops to dead ones
 * is not enough: file ops don't look at the vnode...
 * so as an ad hoc solution we'll test against this macro to the top of file
 * specific ops.
 * Tell me if there is an "official" way to handle this.
 */

static __inline int
_file_is_bad(struct file *fp)
{
	return (fp->f_ops == &badfileops ||
                fp->f_ops == &vnops ||
                fp->f_vnode->v_type == VBAD ||
                fp->f_vnode->v_op == &dead_vnodeops ||
                fp->f_vnode->v_data == NULL ||
                fp->f_data == NULL ||
                FTOFH(fp)->fh_vp->v_type == VBAD);
}

/*
 * In kern_open() of vfs_syscalls.c, if the f_data slot is not set
 * up at open time, the vnode of the file will be put there.
 * So "f_data == f_vnode" means someting like "the file is not
 * initialized". I don't know how stable this convention is, so relying
 * on it might be somewhat bogus; yet this saves us from on more locking
 * for nothing (when allocating a dummy data field).
 * As a compromise, the respective test is wrapped into a macro, to provide
 * some abstraction...
 */

static __inline int
_file_is_fat(struct file *fp)
{
	return (fp->f_vnode && fp->f_data != fp->f_vnode);
}
