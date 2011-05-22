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

