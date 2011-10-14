/*
 * I/O methods for fuse devices.
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
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <sys/poll.h>
#include <sys/selinfo.h>

#include "fuse.h"
#include "fuse_ipc.h"

#define FUSE_DEBUG_MODULE DEVICE
#include "fuse_debug.h"

static __inline int fuse_ohead_audit(struct fuse_out_header *ohead,
                                     struct uio *uio);

static d_open_t  fuse_device_open;
static d_close_t fuse_device_close;
static d_poll_t  fuse_device_poll;
static d_read_t  fuse_device_read;
static d_write_t fuse_device_write;

void fuse_device_clone(void *arg, struct ucred *cred, char *name,
                          int namelen, struct cdev **dev);

static struct cdevsw fuse_device_cdevsw = {
	.d_open = fuse_device_open,
	.d_close = fuse_device_close,
	.d_name = "fuse",
	.d_poll = fuse_device_poll,
	.d_read = fuse_device_read,
	.d_write = fuse_device_write,
	.d_version = D_VERSION,
	.d_flags = D_NEEDMINOR,
};

/*
 * This struct is not public, but we are eager to use it,
 * so we have to put its def here.
 */
struct clonedevs {
	LIST_HEAD(,cdev)	head;
};

struct clonedevs *fuseclones;

/****************************
 *
 * >>> Fuse device op defs
 *
 ****************************/

/* 
 * Resources are set up on a per-open basis
 */
static int
fuse_device_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct fuse_data *fdata;	

	if (dev->si_usecount > 1)
		goto busy;

	DEBUG("device %p\n", dev);

	fdata = fdata_alloc(dev, td->td_ucred);

	FUSE_LOCK();
	if (fuse_get_devdata(dev)) {
		FUSE_UNLOCK();
		fdata_destroy(fdata);
		goto busy;
	} else {
		fdata->dataflags |= FSESS_OPENED;
		dev->si_drv1 = fdata;
	}	
	FUSE_UNLOCK();

	DEBUG("%s: device opened by thread %d.\n", dev->si_name, td->td_tid);

	return(0);

busy:
	return (EBUSY);
}

static int
fuse_device_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	struct fuse_data *data;

	FUSE_LOCK();
	data = fuse_get_devdata(dev);
	if (! data)
		panic("no fuse data upon fuse device close");
	KASSERT(data->dataflags | FSESS_OPENED,
	        ("fuse device is already closed upon close"));
	fdata_set_dead(data);
        data->dataflags &= ~FSESS_OPENED;
	fuse_lck_mtx_lock(data->aw_mtx);

	/* wakup poll()ers */
	selwakeuppri(&data->ks_rsel, PZERO + 1);

	DEBUG("mntco %d\n", data->mntco);
	if (data->mntco > 0) {
		struct fuse_ticket *tick;

		/* Don't let syscall handlers wait in vain */
		while ((tick = fuse_aw_pop(data))) {
			fuse_lck_mtx_lock(tick->tk_aw_mtx);
			fticket_set_answered(tick);
			tick->tk_aw_errno = ENOTCONN;
			wakeup(tick);
			fuse_lck_mtx_unlock(tick->tk_aw_mtx);
			fuse_lck_mtx_unlock(data->aw_mtx);
			FUSE_ASSERT_AW_DONE(tick);
			fuse_ticket_drop(tick);
			fuse_lck_mtx_lock(data->aw_mtx);
		}
		fuse_lck_mtx_unlock(data->aw_mtx);

		FUSE_UNLOCK();
		goto out;
	}
	dev->si_drv1 = NULL;
	fuse_lck_mtx_unlock(data->aw_mtx);
	FUSE_UNLOCK();

	fdata_destroy(data);

out:
	DEBUG("%s: device closed by thread %d.\n", dev->si_name, td->td_tid);
	return(0);
}

int
fuse_device_poll(struct cdev *dev, int events, struct thread *td)
{
	struct fuse_data *data;
	int revents = 0;

	data = fuse_get_devdata(dev);

	if (events & (POLLIN | POLLRDNORM)) {
		fuse_lck_mtx_lock(data->ms_mtx);
		if (fdata_get_dead(data) || STAILQ_FIRST(&data->ms_head))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &data->ks_rsel);
		fuse_lck_mtx_unlock(data->ms_mtx);
	}

	if (events & (POLLOUT | POLLWRNORM)) {
		revents |= events & (POLLOUT | POLLWRNORM);
	}

	return (revents);
}

/*
 * fuse_device_read hangs on the queue of VFS messages.
 * When it's notified that there is a new one, it picks that and
 * passes up to the daemon
 */
int
fuse_device_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	int err = 0;
	struct fuse_data *data;
	struct fuse_ticket *tick;
	void *buf[] = { NULL, NULL, NULL };
	int buflen[3];
	int i;

	data = fuse_get_devdata(dev);

	DEBUG("fuse device being read on thread %d\n", uio->uio_td->td_tid);

	fuse_lck_mtx_lock(data->ms_mtx);
again:
	if (fdata_get_dead(data)) {
		DEBUG2G("we know early on that reader should be kicked so we don't wait for news\n");
		fuse_lck_mtx_unlock(data->ms_mtx);
		return (ENODEV);
	}

	if (!(tick = fuse_ms_pop(data))) {
		/* check if we may block */
		if (ioflag & O_NONBLOCK) {
			/* get outa here soon */
			fuse_lck_mtx_unlock(data->ms_mtx);
			return (EAGAIN);
		}
		else {
			err = msleep(data, &data->ms_mtx, PCATCH, "fu_msg", 0);
			if (err != 0) {
				fuse_lck_mtx_unlock(data->ms_mtx);
				return (fdata_get_dead(data) ? ENODEV : err);
			}
			tick = fuse_ms_pop(data);
		}
	}
	if (!tick) {
		/*
		 * We can get here if fuse daemon suddenly terminates,
		 * eg, by being hit by a SIGKILL
		 * -- and some other cases, too, tho not totally clear, when
		 * (cv_signal/wakeup_one signals the whole process ?)
		 */
		DEBUG("no message on thread #%d\n", uio->uio_td->td_tid);
		goto again;
	}
	fuse_lck_mtx_unlock(data->ms_mtx);

	if (fdata_get_dead(data)) {
		/*
		 * somebody somewhere -- eg., umount routine --
		 * wants this liaison finished off
		 */
		DEBUG2G("reader is to be sacked\n");
		if (tick) {
			DEBUG2G("weird -- \"kick\" is set tho there is message\n");
			FUSE_ASSERT_MS_DONE(tick);
			fuse_ticket_drop(tick);
		}
		return (ENODEV); /* This should make the daemon get off of us */
	}
	DEBUG("message got on thread #%d\n", uio->uio_td->td_tid);

	KASSERT(tick->tk_ms_bufdata || tick->tk_ms_bufsize == 0,
	        ("non-null buf pointer with positive size"));

	switch (tick->tk_ms_type) {
	case FT_M_FIOV:
		buf[0] = tick->tk_ms_fiov.base;
		buflen[0] =  tick->tk_ms_fiov.len;
		break;
	case FT_M_BUF:
		buf[0] = tick->tk_ms_fiov.base;
		buflen[0] =  tick->tk_ms_fiov.len;
		buf[1] = tick->tk_ms_bufdata;
		buflen[1] =  tick->tk_ms_bufsize;
		break;
	default:
		panic("unknown message type for fuse_ticket %p", tick);
	}

	for (i = 0; buf[i]; i++) {
		/*
		 * Why not ban mercilessly stupid daemons who can't keep up
		 * with us? (There is no much use of a partial read here...)
		 */
		/*
		 * XXX note that in such cases Linux FUSE throws EIO at the
		 * syscall invoker and stands back to the message queue. The
		 * rationale should be made clear (and possibly adopt that
		 * behaviour). Keeping the current scheme at least makes
		 * fallacy as loud as possible...
		 */
		if (uio->uio_resid < buflen[i]) {
			fdata_set_dead(data);
			DEBUG2G("daemon is stupid, kick it off...\n");
			err = ENODEV;
			break;
		}
		err = uiomove(buf[i], buflen[i], uio);
		if (err)
			break;
	}

	FUSE_ASSERT_MS_DONE(tick);
	fuse_ticket_drop(tick);

	return (err);
}

static __inline int
fuse_ohead_audit(struct fuse_out_header *ohead, struct uio *uio)
{
	DEBUG("Out header -- len: %i, error: %i, unique: %llu; iovecs: %d\n",
	          ohead->len, ohead->error, (unsigned long long)ohead->unique,
                  uio->uio_iovcnt);

	if (uio->uio_resid + sizeof(struct fuse_out_header) != ohead->len) {
		DEBUG("Format error: body size differs from size claimed by header\n");
		return (EINVAL);
	}

	if (uio->uio_resid && ohead->error) {
		DEBUG("Format error: non zero error but message had a body\n");
		return (EINVAL);
	}

	/* Sanitize the linuxism of negative errnos */
	ohead->error = -(ohead->error);

	return (0);
}	

/*
 * fuse_device_write first reads the header sent by the daemon.
 * If that's OK, looks up ticket/callback node by the unique id seen in header.
 * If the callback node contains a handler function, the uio is passed over
 * that.
 */
static int
fuse_device_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct fuse_out_header ohead;
	int err = 0;
	struct fuse_data *data;
	struct fuse_ticket *tick, *x_tick;
	int found = 0;

	DEBUG("resid: %zd, iovcnt: %d, thread: %d\n",
		uio->uio_resid, uio->uio_iovcnt, uio->uio_td->td_tid);

	data = fuse_get_devdata(dev);

	if (uio->uio_resid < sizeof(struct fuse_out_header)) {
		DEBUG("got less than a header!\n");
		fdata_set_dead(data);
		return (EINVAL);
	}

	if ((err = uiomove(&ohead, sizeof(struct fuse_out_header), uio)) != 0)
		return (err);

	/*	
	 * We check header information (which is redundant) and compare it with
	 * what we see. If we see some inconsistency we discard the whole
	 * answer and proceed on as if it had never existed. In particular, no
	 * pretender will be woken up, regardless the "unique" value in the
	 * header.
	 */
	if ((err = fuse_ohead_audit(&ohead, uio))) {
		fdata_set_dead(data);
		return (err);
	}
	
	/* Pass stuff over to callback if there is one installed */

	/* Looking for ticket with the unique id of header */
	fuse_lck_mtx_lock(data->aw_mtx);
	TAILQ_FOREACH_SAFE(tick, &data->aw_head, tk_aw_link,
	                   x_tick) {
		DEBUG("bumped into callback #%llu\n",
                         (unsigned long long)tick->tk_unique);
		if (tick->tk_unique == ohead.unique) {
			found = 1;
			fuse_aw_remove(tick);
			break;
		}
	}
	fuse_lck_mtx_unlock(data->aw_mtx);

	if (found) {
		if (tick->tk_aw_handler) {
			/* We found a callback with proper handler.
			 * In this case the out header will be 0wnd by
			 * the callback, so the fun of freeing that is
			 * left for her.
			 * (Then, by all chance, she'll just get that's done
			 * via ticket_drop(), so no manual mucking around...)
			 */
			DEBUG("pass ticket to a callback\n");
			memcpy(&tick->tk_aw_ohead, &ohead, sizeof(ohead));
			err = tick->tk_aw_handler(tick, uio);
		} else {
			/* pretender doesn't wanna do anything with answer */
			DEBUG("stuff devalidated, so we drop it\n");
		}
		FUSE_ASSERT_AW_DONE(tick);
		fuse_ticket_drop(tick);
	} else {
		/* no callback at all! */
		DEBUG("erhm, no handler for this response\n");
		err = EINVAL;
	}

	return (err);
}

/*
 * Modeled after tunclone() of net/if_tun.c ...
 * boosted with a hack so that devices can be reused.
 */
void
fuse_device_clone(void *arg, struct ucred *cred, char *name, int namelen,
              struct cdev **dev)
{
	/*
	 * Why cloning? We do need per-open info, but we could as well put our
	 * hands on the file struct assigned to an open by implementing
	 * d_fdopen instead of d_open.
	 * 
	 * From that on, the usual way to per-open (that is, file aware)
	 * I/O would be pushing our preferred set of ops into the f_op
	 * field of that file at open time. But that wouldn't work in
	 * FreeBSD, as the devfs open routine (which is the one who calls
	 * the device's d_(fd)open) overwrites that f_op with its own
	 * file ops mercilessly.
	 *
	 * Yet... even if we could get devfs to keep our file ops intact,
	 * I'd still say cloning is better. It makes fuse daemons' identity
	 * explicit and globally visible to userspace, and we are not forced
	 * to get the mount done by the daemon itself like in linux (where 
	 * I/O is file aware by default). (The possibilities of getting the
	 * daemon do the mount or getting the mount util spawn the daemon
	 * are still open, of course; I guess I will go for the latter 
	 * appcocroach.)
	 */

	int i, unit;

	if (*dev != NULL)
		return;

	if (strcmp(name, "fuse") == 0) {
		struct cdev *xdev;

		unit = -1;

		/*
		 * Before falling back to the standard routine, we try
		 * to find an existing free device by ourselves, so that
		 * it will be reused instead of having the clone machinery
		 * dummily spawn a new one.
		 */
		dev_lock();
		LIST_FOREACH(xdev, &fuseclones->head, si_clone) {
			KASSERT(xdev->si_flags & SI_CLONELIST,
			    ("Dev %p(%s) should be on clonelist", xdev, xdev->si_name));

			if (! xdev->si_drv1) {
				unit = dev2unit(xdev);
				break;
			}
		}
		dev_unlock();
	} else if (dev_stdclone(name, NULL, "fuse", &unit) != 1) {
		return;
	}

	/* find any existing device, or allocate new unit number */
	i = clone_create(&fuseclones, &fuse_device_cdevsw, &unit, dev, 0);
	if (i) {
		*dev = make_dev(&fuse_device_cdevsw,
				unit,
			        UID_ROOT, GID_OPERATOR,
		                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP,
                                "fuse%d", unit);
		if (*dev == NULL)
			return;
	}

	KASSERT(*dev, ("no device after apparently successful cloning"));
	dev_ref(*dev);
	(*dev)->si_drv1 = NULL;
	(*dev)->si_flags |= SI_CHEAPCLONE;

	DEBUG("clone done: %d\n",unit);
}
