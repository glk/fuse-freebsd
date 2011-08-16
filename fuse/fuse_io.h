/*
 * Copyright (C) 2005 Csaba Henk.
 * All Rights Reserved.
 * See COPYRIGHT file for additional information.
 */

#ifndef _FUSE_IO_H_
#define _FUSE_IO_H_

int fuse_io_dispatch(struct vnode *vp, struct uio *uio, int ioflag,
    struct ucred *cred);
int fuse_io_strategy(struct vnode *vp, struct buf *bp);
int fuse_io_flushbuf(struct vnode *vp, int waitfor, struct thread *td);
int fuse_io_invalbuf(struct vnode *vp, struct thread *td);

#endif /* _FUSE_IO_H_ */
