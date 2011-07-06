#ifndef _FUSE_IO_H_
#define _FUSE_IO_H_

int fuse_io_dispatch(struct vnode *vp, struct uio *uio, int ioflag,
    struct ucred *cred);
int fuse_io_strategy(struct vnode *vp, struct buf *bp);

#endif /* _FUSE_IO_H_ */
