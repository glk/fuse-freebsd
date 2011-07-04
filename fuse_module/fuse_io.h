#ifndef _FUSE_IO_H_
#define _FUSE_IO_H_

/* prototype for processing an input data buffer and an uio
   for reading related acivities */
typedef	int fuse_buffeater_t(struct uio *uio, size_t reqsize,
    void *buf, size_t bufsize, void *param);

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

int fuse_io_dispatch(struct vnode *vp, struct uio *uio, int ioflag,
    struct ucred *cred);
int fuse_io_strategy(struct vnode *vp, struct buf *bp,
    struct fuse_filehandle *fufh, enum fuse_opcode op);

#endif /* _FUSE_IO_H_ */
