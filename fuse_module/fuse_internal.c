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
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/fcntl.h>

#include "fuse.h"
#include "fuse_node.h"
#include "fuse_ipc.h"
#include "fuse_internal.h"

int
fuse_init_handler(struct fuse_ticket *tick, struct uio *uio)
{
    int err = 0;
    struct fuse_data     *data = tick->tk_data;
#if FUSE_KERNELABI_GEQ(7, 5)
    struct fuse_init_out *fiio;
#else
    struct fuse_init_in_out *fiio;
#endif

    if ((err = tick->tk_aw_ohead.error)) {
        goto out;
    }

    if ((err = fticket_pull(tick, uio))) {
        goto out;
    }

    fiio = fticket_resp(tick)->base;

    /* XXX is the following check adequate? */
    if (fiio->major < 7) {
        DEBUG2G("userpace version too low\n");
        err = EPROTONOSUPPORT;
        goto out;
    }

    data->fuse_libabi_major = fiio->major;
    data->fuse_libabi_minor = fiio->minor;

    if (FUSE_KERNELABI_GEQ(7, 5) && fuse_libabi_geq(data, 7, 5)) {
#if FUSE_KERNELABI_GEQ(7, 5)
        if (fticket_resp(tick)->len == sizeof(struct fuse_init_out)) {
            data->max_write = fiio->max_write;
        } else {
            err = EINVAL;
        }
#endif
    } else {
        /* Old fix values */
        data->max_write = 4096;
    }

out:
    fuse_ticket_drop(tick);

    if (err) {
        fdata_kick_set(data);
    }

    mtx_lock(&data->ticket_mtx);
    data->dataflag |= FSESS_INITED;
    wakeup(&data->ticketer);
    mtx_unlock(&data->ticket_mtx);

    return (0);
}

void
fuse_send_init(struct fuse_data *data, struct thread *td)
{
#if FUSE_KERNELABI_GEQ(7, 5)
    struct fuse_init_in   *fiii;
#else
    struct fuse_init_in_out *fiii;
#endif
    struct fuse_dispatcher fdi;

    fdisp_init(&fdi, sizeof(*fiii));
    fdisp_make(&fdi, data->mp, FUSE_INIT, 0, td, NULL);
    fiii = fdi.indata;
    fiii->major = FUSE_KERNEL_VERSION;
    fiii->minor = FUSE_KERNEL_MINOR_VERSION;

    fuse_insert_callback(fdi.tick, fuse_init_handler);
    fuse_insert_message(fdi.tick);
}
