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

static uint64_t fuse_fh_upcall_count = 0;
SYSCTL_QUAD(_vfs_fuse, OID_AUTO, fh_upcall_count, CTLFLAG_RD,
            &fuse_fh_upcall_count, 0, "");

int
fuse_filehandle_get(struct vnode *vp,
                    struct thread *td,
                    struct ucred *cred,
                    fufh_type_t fufh_type)
{
    struct fuse_dispatcher  fdi;
    struct fuse_open_in    *foi;
    struct fuse_open_out   *foo;
    struct fuse_filehandle *fufh;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    int err    = 0;
    int isdir  = 0;
    int oflags = fuse_filehandle_xlate_to_oflags(fufh_type);
    int op     = FUSE_OPEN;

    fuse_trace_printf("fuse_filehandle_get(vp=%p, fufh_type=%d)\n",
                      vp, fufh_type);

    fufh = &(fvdat->fufh[fufh_type]);

    if (fufh->fufh_flags & FUFH_VALID) {
        printf("FUSE: filehandle_get called despite valid fufh (type=%d)",
              fufh_type);
        return 0;
    }

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

    fuse_fh_upcall_count++;
    if ((err = fdisp_wait_answ(&fdi))) {
        debug_printf("OUCH ... daemon didn't give fh (err = %d)\n", err);
        return err;
    }

    foo = fdi.answ;

    fufh->fh_id = foo->fh;
    fufh->fufh_flags |= (0 | FUFH_VALID);
    fufh->open_count = 1;
    fufh->open_flags = oflags;
    fufh->fuse_open_flags = foo->open_flags;
    fufh->type = fufh_type;
    
    fuse_ticket_drop(fdi.tick);

    return 0;
}

int
fuse_filehandle_put(struct vnode *vp, struct thread *td, struct ucred *cred, fufh_type_t fufh_type,
                    int foregrounded)
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
    if (!(fufh->fufh_flags & FUFH_VALID)) {
        printf("trying to put invalid filehandle?\n");
        return 0;
    }

    if (fufh->open_count != 0) {
        panic("FUSE: filehandle_put called on a valid fufh (type=%d)",
              fufh_type);
        /* NOTREACHED */
    }

    if (fufh->fufh_flags & FUFH_MAPPED) {
        panic("trying to put mapped fufh\n");
    }

    if (vnode_isdir(vp)) {
        op = FUSE_RELEASEDIR;
        isdir = 1;
    }

    fdisp_init(&fdi, sizeof(*fri));
    fdisp_make_vp(&fdi, op, vp, td, cred);
    fri = fdi.indata;
    fri->fh = fufh->fh_id;
    fri->flags = fufh->open_flags;

    if (foregrounded) {
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
    fufh->fufh_flags &= ~FUFH_VALID;

    return err;
}
