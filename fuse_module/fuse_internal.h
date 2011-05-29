/*
 * Copyright (C) 2006 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_INTERNAL_H_
#define _FUSE_INTERNAL_H_

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include "fuse_ipc.h"
#include "fuse_node.h"

/* access related data */

#define FACCESS_VA_VALID   0x01 /* flag to sign to reuse cached attributes
                                   regardless of cache timeout */
#define FACCESS_DO_ACCESS  0x02 /* flag showing if we are to do access check */
#define FACCESS_STICKY     0x04 /* do sticky dir permission check */
#define FACCESS_CHOWN      0x08 /* do permission check for owner changing */
#define FACCESS_NOCHECKSPY 0x10 /* don't check if daemon is allowed to spy on
                                   user */
#define FACCESS_SETGID     0x12 /* do permission check for setting setgid flag */

#define FACCESS_XQUERIES FACCESS_STICKY | FACCESS_CHOWN | FACCESS_SETGID

#define FVP_ACCESS_NOOP   0x01 /* vnode based control flag for doing access check */

struct fuse_access_param {
	uid_t xuid;
	gid_t xgid;

	unsigned facc_flags;
};


/* fuse start/stop */

int fuse_internal_init_callback(struct fuse_ticket *tick, struct uio *uio);
void fuse_internal_send_init(struct fuse_data *data, struct thread *td);

#endif /* _FUSE_INTERNAL_H_ */
