/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_FILE_H_
#define _FUSE_FILE_H_

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vnode.h>

typedef enum fufh_type {
    FUFH_INVALID = -1,
    FUFH_RDONLY  = 0,
    FUFH_WRONLY  = 1,
    FUFH_RDWR    = 2,
    FUFH_MAXTYPE = 3,
} fufh_type_t;

struct fuse_filehandle {
    uint64_t fh_id;
    fufh_type_t fh_type;
};

#define FUFH_IS_VALID(f)  ((f)->fh_type != FUFH_INVALID)

static __inline__
fufh_type_t
fuse_filehandle_xlate_from_mmap(int fflags)
{
    if (fflags & (PROT_READ | PROT_WRITE)) {
        return FUFH_RDWR;
    } else if (fflags & (PROT_WRITE)) {
        return FUFH_WRONLY;
    } else if ((fflags & PROT_READ) || (fflags & PROT_EXEC)) {
        return FUFH_RDONLY;
    } else {
        return FUFH_INVALID;
    }
}

static __inline__
fufh_type_t
fuse_filehandle_xlate_from_fflags(int fflags)
{
    if ((fflags & FREAD) && (fflags & FWRITE)) {
        return FUFH_RDWR;
    } else if (fflags & (FWRITE)) {
        return FUFH_WRONLY;
    } else if (fflags & (FREAD)) {
        return FUFH_RDONLY;
    } else {
        panic("FUSE: What kind of a flag is this (%x)?", fflags);
    }
}

static __inline__
int
fuse_filehandle_xlate_to_oflags(fufh_type_t type)
{
    int oflags = -1;

    switch (type) {

    case FUFH_RDONLY:
        oflags = O_RDONLY;
        break;

    case FUFH_WRONLY:
        oflags = O_WRONLY;
        break;

    case FUFH_RDWR:
        oflags = O_RDWR;
        break;

    default:
        break;
    }

    return oflags;
}

int fuse_filehandle_valid(struct vnode *vp, fufh_type_t fufh_type);
int fuse_filehandle_get(struct vnode *vp, fufh_type_t fufh_type,
                        struct fuse_filehandle **fufhp);
int fuse_filehandle_getrw(struct vnode *vp, fufh_type_t fufh_type,
                          struct fuse_filehandle **fufhp);

void fuse_filehandle_init(struct vnode *vp, fufh_type_t fufh_type,
		          struct fuse_filehandle **fufhp, uint64_t fh_id);
int fuse_filehandle_open(struct vnode *vp, fufh_type_t fufh_type,
                         struct fuse_filehandle **fufhp, struct thread *td,
                         struct ucred *cred);
int fuse_filehandle_close(struct vnode *vp, fufh_type_t fufh_type,
                          struct thread *td, struct ucred *cred,
                          fuse_op_waitfor_t waitfor);

#endif /* _FUSE_FILE_H_ */
