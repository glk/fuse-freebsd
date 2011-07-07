/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#include "config.h"

#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>

#include "fuse.h"
#include "fuse_file.h"
#include "fuse_internal.h"
#include "fuse_ipc.h"
#include "fuse_node.h"

#define FUSE_DEBUG_MODULE FILE
#include "fuse_debug.h"

static int fuse_fh_count = 0;
SYSCTL_INT(_vfs_fuse, OID_AUTO, filehandle_count, CTLFLAG_RD,
            &fuse_fh_count, 0, "");

int
fuse_filehandle_open(struct vnode *vp,
                     fufh_type_t fufh_type,
                     struct fuse_filehandle **fufhp,
                     struct thread *td,
                     struct ucred *cred)
{
    struct fuse_dispatcher  fdi;
    struct fuse_open_in    *foi;
    struct fuse_open_out   *foo;

    int err    = 0;
    int isdir  = 0;
    int oflags = 0;
    int op     = FUSE_OPEN;

    fuse_trace_printf("fuse_filehandle_get(vp=%p, fufh_type=%d)\n",
                      vp, fufh_type);

    if (fuse_filehandle_valid(vp, fufh_type)) {
        panic("FUSE: filehandle_get called despite valid fufh (type=%d)",
              fufh_type);
        /* NOTREACHED */
    }

    /*
     * Note that this means we are effectively FILTERING OUT open() flags.
     */
    oflags = fuse_filehandle_xlate_to_oflags(fufh_type);

    if (vnode_isdir(vp)) {
        isdir = 1;
        op = FUSE_OPENDIR;
        if (fufh_type != FUFH_RDONLY) {
            printf("FUSE: non-rdonly fh requested for a directory?\n");
            fufh_type = FUFH_RDONLY;
        }
    }

    fdisp_init(&fdi, sizeof(*foi));
    fdisp_make_vp(&fdi, op, vp, td, cred);

    foi = fdi.indata;
    foi->flags = oflags;

    if ((err = fdisp_wait_answ(&fdi))) {
        debug_printf("OUCH ... daemon didn't give fh (err = %d)\n", err);
        if (err == ENOENT) {
            fuse_internal_vnode_disappear(vp);
        }
        return err;
    }

    foo = fdi.answ;

    fuse_filehandle_init(vp, fufh_type, fufhp, foo->fh);
    fuse_vnode_open(vp, foo->open_flags, td);
    
    fuse_ticket_drop(fdi.tick);

    return 0;
}

int
fuse_filehandle_close(struct vnode *vp,
                      fufh_type_t fufh_type,
                      struct thread *td,
                      struct ucred *cred,
                      fuse_op_waitfor_t waitfor)
{
    struct fuse_dispatcher  fdi;
    struct fuse_release_in *fri;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh  = NULL;

    int err   = 0;
    int isdir = 0;
    int op    = FUSE_RELEASE;

    fuse_trace_printf("fuse_filehandle_put(vp=%p, fufh_type=%d)\n",
                      vp, fufh_type);

    fufh = &(fvdat->fufh[fufh_type]);
    if (!FUFH_IS_VALID(fufh)) {
        panic("FUSE: filehandle_put called on invalid fufh (type=%d)",
              fufh_type);
        /* NOTREACHED */
    }

    if (fuse_isdeadfs(vp)) {
        goto out;
    }

    if (vnode_isdir(vp)) {
        op = FUSE_RELEASEDIR;
        isdir = 1;
    }

    fdisp_init(&fdi, sizeof(*fri));
    fdisp_make_vp(&fdi, op, vp, td, cred);
    fri = fdi.indata;
    fri->fh = fufh->fh_id;
    fri->flags = fuse_filehandle_xlate_to_oflags(fufh_type);

    if (waitfor == FUSE_OP_FOREGROUNDED) {
        if ((err = fdisp_wait_answ(&fdi))) {
            goto out;
        } else {
            fuse_ticket_drop(fdi.tick);
        }
    } else {
        fuse_insert_callback(fdi.tick, NULL);
        fuse_insert_message(fdi.tick);
    }

out:
    atomic_subtract_acq_int(&fuse_fh_count, 1);
    fufh->fh_id = (uint64_t)-1;
    fufh->fh_type = FUFH_INVALID;
    fuse_invalidate_attr(vp);

    return err;
}

int
fuse_filehandle_valid(struct vnode *vp, fufh_type_t fufh_type)
{
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh;

    fufh = &(fvdat->fufh[fufh_type]);
    return FUFH_IS_VALID(fufh);
}

int
fuse_filehandle_get(struct vnode *vp, fufh_type_t fufh_type,
    struct fuse_filehandle **fufhp)
{
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh;

    fufh = &(fvdat->fufh[fufh_type]);
    if (!FUFH_IS_VALID(fufh)) {
        printf("FUSE: filehandle is not valid (type=%d)\n", fufh_type);
	return EBADF;
    }
    if (fufhp != NULL)
        *fufhp = fufh;
    return 0;
}

int
fuse_filehandle_getrw(struct vnode *vp, fufh_type_t fufh_type,
    struct fuse_filehandle **fufhp)
{
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh;

    fufh = &(fvdat->fufh[fufh_type]);
    if (!FUFH_IS_VALID(fufh)) {
        fufh_type = FUFH_RDWR;
    }
    return fuse_filehandle_get(vp, fufh_type, fufhp);
}

void
fuse_filehandle_init(struct vnode *vp,
                     fufh_type_t fufh_type,
		     struct fuse_filehandle **fufhp,
                     uint64_t fh_id)
{
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh;

    DEBUG("id=%jd type=%d\n", (intmax_t)fh_id, fufh_type);
    fufh = &(fvdat->fufh[fufh_type]);
    MPASS(!FUFH_IS_VALID(fufh));
    fufh->fh_id = fh_id;
    fufh->fh_type = fufh_type;
    if (!FUFH_IS_VALID(fufh)) {
        panic("FUSE: init: invalid filehandle id (type=%d)", fufh_type);
    }

    if (fufhp != NULL)
        *fufhp = fufh;

    atomic_add_acq_int(&fuse_fh_count, 1);
}
