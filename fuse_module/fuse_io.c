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
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vnode_pager.h>
#include <vm/vm_object.h>

#include "fuse.h"
#include "fuse_file.h"
#include "fuse_node.h"
#include "fuse_internal.h"
#include "fuse_ipc.h"
#include "fuse_io.h"

#define FUSE_DEBUG_MODULE IO
#include "fuse_debug.h"


static int fuse_read_directbackend(struct vnode *vp, struct uio *uio,
    struct ucred *cred, struct fuse_filehandle *fufh);
static int fuse_read_biobackend(struct vnode *vp, struct uio *uio,
    struct ucred *cred, struct fuse_filehandle *fufh);
static int fuse_write_directbackend(struct vnode *vp, struct uio *uio,
    struct ucred *cred, struct fuse_filehandle *fufh);
static int fuse_write_biobackend(struct vnode *vp, struct uio *uio,
    struct ucred *cred, struct fuse_filehandle *fufh);

static int fuse_std_buffeater(struct uio *uio, size_t reqsize, void *buf,
    size_t bufsize, void *param);

int
fuse_io_dispatch(struct vnode *vp, struct uio *uio, int ioflag,
    struct ucred *cred)
{
    struct fuse_filehandle *fufh;
    int err, directio;

    MPASS(vp->v_type == VREG);

    err = fuse_filehandle_getrw(vp,
        (uio->uio_rw == UIO_READ) ? FUFH_RDONLY : FUFH_WRONLY, &fufh);
    if (err) {
        DEBUG("fetching filehandle failed\n");
        return err;
    }

    /*
     * Ideally, when the daemon asks for direct io at open time, the
     * standard file flag should be set according to this, so that would
     * just change the default mode, which later on could be changed via
     * fcntl(2).
     * But this doesn't work, the O_DIRECT flag gets cleared at some point
     * (don't know where). So to make any use of the Fuse direct_io option,
     * we hardwire it into the file's private data (similarly to Linux,
     * btw.).
     */
    directio = (ioflag & IO_DIRECT) || !fuse_vnode_cache_enable(vp);

    switch (uio->uio_rw) {
    case UIO_READ:
        if (directio) {
            DEBUG("direct read of vnode %ju via file handle %ju\n",
                (uintmax_t)VTOILLU(vp), (uintmax_t)fufh->fh_id);
            err = fuse_read_directbackend(vp, uio, cred, fufh);
        } else {
            DEBUG("buffered read of vnode %ju\n", (uintmax_t)VTOILLU(vp));
            err = fuse_read_biobackend(vp, uio, cred, fufh);
        }
        break;
    case UIO_WRITE:
        if (directio) {
            DEBUG("direct write of vnode %ju via file handle %ju\n",
                (uintmax_t)VTOILLU(vp), (uintmax_t)fufh->fh_id);
            err = fuse_write_directbackend(vp, uio, cred, fufh);
        } else {
            DEBUG("buffered write of vnode %ju\n", (uintmax_t)VTOILLU(vp));
            err = fuse_write_biobackend(vp, uio, cred, fufh);
        }
        break;
    default:
        panic("uninterpreted mode passed to fuse_io_dispatch");
    }

    fuse_invalidate_attr(vp);

    return (err);
}

static int
fuse_read_biobackend(struct vnode *vp, struct uio *uio,
    struct ucred *cred, struct fuse_filehandle *fufh)
{
    struct buf *bp;
    daddr_t lbn;
    int bcount;
    int err = 0, n = 0, on = 0;
    off_t filesize;

    const int biosize = fuse_iosize(vp);

    DEBUG("resid=%zx offset=%jx fsize=%jx\n",
        uio->uio_resid, uio->uio_offset, VTOFUD(vp)->filesize);

    if (uio->uio_resid == 0)
        return (0);
    if (uio->uio_offset < 0)
        return (EINVAL);

    bcount = MIN(MAXBSIZE, biosize);
    filesize = VTOFUD(vp)->filesize;

    do {
        lbn = uio->uio_offset / biosize;
        on = uio->uio_offset & (biosize - 1);

        DEBUG2G("biosize %d, lbn %d, on %d\n", biosize, (int)lbn, on);

        /*
         * Obtain the buffer cache block.  Figure out the buffer size
         * when we are at EOF.  If we are modifying the size of the
         * buffer based on an EOF condition we need to hold
         * nfs_rslock() through obtaining the buffer to prevent
         * a potential writer-appender from messing with n_size.
         * Otherwise we may accidently truncate the buffer and
         * lose dirty data.
         *
         * Note that bcount is *not* DEV_BSIZE aligned.
         */
        if ((off_t)lbn * biosize >= filesize) {
            bcount = 0;
        } else if ((off_t)(lbn + 1) * biosize > filesize) {
            bcount = filesize - (off_t)lbn * biosize;
        }

        bp = getblk(vp, lbn, bcount, PCATCH, 0, 0);

        if (!bp)
            return (EINTR);

        /*
         * If B_CACHE is not set, we must issue the read.  If this
         * fails, we return an error.
         */

        if ((bp->b_flags & B_CACHE) == 0) {
            bp->b_iocmd = BIO_READ;
            vfs_busy_pages(bp, 0);
            err = fuse_io_strategy(vp, bp);
            if (err) {
                brelse(bp);
                return (err);
            }
        }

        /*
         * on is the offset into the current bp.  Figure out how many
         * bytes we can copy out of the bp.  Note that bcount is
         * NOT DEV_BSIZE aligned.
         *
         * Then figure out how many bytes we can copy into the uio.
         */

        n = 0;
        if (on < bcount)
            n = MIN((unsigned)(bcount - on), uio->uio_resid);
        if (n > 0) {
            DEBUG2G("feeding buffeater with %d bytes of buffer %p, saying %d was asked for\n",
                n, bp->b_data + on, n + (int)bp->b_resid);
            err = fuse_std_buffeater(uio, n + bp->b_resid, bp->b_data + on, n,
                NULL);
        }
        brelse(bp);
        DEBUG2G("end of turn, err %d, uio->uio_resid %zd, n %d\n",
            err, uio->uio_resid, n);
    } while (err == 0 && uio->uio_resid > 0 && n > 0);

    return ((err == -1) ? 0 : err);
}

static int
fuse_read_directbackend(struct vnode *vp, struct uio *uio,
    struct ucred *cred, struct fuse_filehandle *fufh)
{
    struct fuse_dispatcher fdi;
    struct fuse_read_in *fri;
    int err = 0;

    if (uio->uio_resid == 0)
        return (0);

    fdisp_init(&fdi, 0);

    /*
     * XXX In "normal" case we use an intermediate kernel buffer for
     * transmitting data from daemon's context to ours. Eventually, we should
     * get rid of this. Anyway, if the target uio lives in sysspace (we are
     * called from pageops), and the input data doesn't need kernel-side
     * processing (we are not called from readdir) we can already invoke
     * an optimized, "peer-to-peer" I/O routine.
     */
    while (uio->uio_resid > 0) {
        fdi.iosize = sizeof(*fri);
        fdisp_make_vp(&fdi, FUSE_READ, vp, uio->uio_td, cred);
        fri = fdi.indata;
        fri->fh = fufh->fh_id;
        fri->offset = uio->uio_offset;
        fri->size = MIN(uio->uio_resid,
            fuse_get_mpdata(vp->v_mount)->max_read);

        DEBUG2G("fri->fh %ju, fri->offset %ju, fri->size %ju\n",
            (uintmax_t)fri->fh, (uintmax_t)fri->offset, (uintmax_t)fri->size);
        if ((err = fdisp_wait_answ(&fdi)))
            goto out;

        DEBUG2G("complete: got iosize=%d, requested fri.size=%zd; "
            "resid=%zd offset=%ju\n",
            fri->size, fdi.iosize, uio->uio_resid, (uintmax_t)uio->uio_offset);

        if ((err = fuse_std_buffeater(uio, fri->size, fdi.answ, fdi.iosize, NULL)))
            break;
    }

    fuse_ticket_drop(fdi.tick);

out:
    return ((err == -1) ? 0 : err);
}

/* Simple standard way for transmitting input */
static int
fuse_std_buffeater(struct uio *uio, size_t reqsize, void *buf, size_t bufsize, void *param)
{
    int err;

    if ((err = uiomove(buf, MIN(reqsize, bufsize), uio)))
        return (err);

    if (bufsize < reqsize)
        return (-1);

    return (0);
}


static int
fuse_write_directbackend(struct vnode *vp, struct uio *uio,
    struct ucred *cred, struct fuse_filehandle *fufh)
{	
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_write_in *fwi;
    struct fuse_dispatcher fdi;
    size_t chunksize;
    int diff;
    int err = 0;

    if (! uio->uio_resid)
        return (0);

    fdisp_init(&fdi, 0);

    while (uio->uio_resid > 0) {
        chunksize = MIN(uio->uio_resid,
            fuse_get_mpdata(vp->v_mount)->max_write);

        fdi.iosize = sizeof(*fwi) + chunksize;
        fdisp_make_vp(&fdi, FUSE_WRITE, vp, uio->uio_td, cred);

        fwi = fdi.indata;
        fwi->fh = fufh->fh_id;
        fwi->offset = uio->uio_offset;
        fwi->size = chunksize;

        if ((err = uiomove((char *)fdi.indata + sizeof(*fwi),
            chunksize, uio)))
            break;

        if ((err = fdisp_wait_answ(&fdi)))
            return(err);

        diff = chunksize - ((struct fuse_write_out *)fdi.answ)->size;
        if (diff < 0) {
            err = EINVAL;
            break;
        }

        uio->uio_resid += diff;
        uio->uio_offset -= diff; 
        if (uio->uio_offset > fvdat->filesize)
            fuse_vnode_setsize(vp, uio->uio_offset);
    }

    fuse_ticket_drop(fdi.tick);

    return (err);
}

static int
fuse_write_biobackend(struct vnode *vp, struct uio *uio,
    struct ucred *cred, struct fuse_filehandle *fufh)
{
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct buf *bp;
    daddr_t lbn;
    int bcount;
    int n, on, err = 0;

    const int biosize = fuse_iosize(vp);

    KASSERT(uio->uio_rw == UIO_WRITE, ("ncl_write mode"));
    DEBUG("resid=%zx offset=%jx fsize=%jx\n",
        uio->uio_resid, uio->uio_offset, fvdat->filesize);
    if (vp->v_type != VREG)
        return (EIO);
    if (uio->uio_offset < 0)
        return (EINVAL);
    if (uio->uio_resid == 0)
        return (0);

    /*
     * Find all of this file's B_NEEDCOMMIT buffers.  If our writes
     * would exceed the local maximum per-file write commit size when
     * combined with those, we must decide whether to flush,
     * go synchronous, or return err.  We don't bother checking
     * IO_UNIT -- we just make all writes atomic anyway, as there's
     * no point optimizing for something that really won't ever happen.
     */
    do {
        lbn = uio->uio_offset / biosize;
        on = uio->uio_offset & (biosize-1);
        n = MIN((unsigned)(biosize - on), uio->uio_resid);

        DEBUG2G("lbn %ju, on %d, n %d, uio offset %ju, uio resid %zd\n",
            (uintmax_t)lbn, on, n, (uintmax_t)uio->uio_offset, uio->uio_resid);

again:
        /*
         * Handle direct append and file extension cases, calculate
         * unaligned buffer size.
         */
        if (uio->uio_offset == fvdat->filesize && n) {
            /*
             * Get the buffer (in its pre-append state to maintain
             * B_CACHE if it was previously set).  Resize the
             * nfsnode after we have locked the buffer to prevent
             * readers from reading garbage.
             */
            bcount = on;
            DEBUG("getting block from OS, bcount %d\n", bcount);
            bp = getblk(vp, lbn, bcount, PCATCH, 0, 0);

            if (bp != NULL) {
                long save;

		fuse_vnode_setsize(vp, uio->uio_offset + n);

                save = bp->b_flags & B_CACHE;
                bcount += n;
                allocbuf(bp, bcount);
                bp->b_flags |= save;
            }
        } else {
            /*
             * Obtain the locked cache block first, and then
             * adjust the file's size as appropriate.
             */
            bcount = on + n;
            if ((off_t)lbn * biosize + bcount < fvdat->filesize) {
                if ((off_t)(lbn + 1) * biosize < fvdat->filesize)
                    bcount = biosize;
                else
                    bcount = fvdat->filesize - (off_t)lbn * biosize;
            }
            DEBUG("getting block from OS, bcount %d\n", bcount);
            bp = getblk(vp, lbn, bcount, PCATCH, 0, 0);
            if (uio->uio_offset + n > fvdat->filesize) {
                fuse_vnode_setsize(vp, uio->uio_offset + n);
            }
        }

        if (!bp) {
            err = EINTR;
            break;
        }

        /*
         * Issue a READ if B_CACHE is not set.  In special-append
         * mode, B_CACHE is based on the buffer prior to the write
         * op and is typically set, avoiding the read.  If a read
         * is required in special append mode, the server will
         * probably send us a short-read since we extended the file
         * on our end, resulting in b_resid == 0 and, thusly,
         * B_CACHE getting set.
         *
         * We can also avoid issuing the read if the write covers
         * the entire buffer.  We have to make sure the buffer state
         * is reasonable in this case since we will not be initiating
         * I/O.  See the comments in kern/vfs_bio.c's getblk() for
         * more information.
         *
         * B_CACHE may also be set due to the buffer being cached
         * normally.
         */

        if (on == 0 && n == bcount) {
            bp->b_flags |= B_CACHE;
            bp->b_flags &= ~B_INVAL;
            bp->b_ioflags &= ~BIO_ERROR;
        }

        if ((bp->b_flags & B_CACHE) == 0) {
            bp->b_iocmd = BIO_READ;
            vfs_busy_pages(bp, 0);
            fuse_io_strategy(vp, bp);
            if ((err = bp->b_error)) {
                brelse(bp);
                break;
            }
        }
        if (bp->b_wcred == NOCRED)
            bp->b_wcred = crhold(cred);

        /*
         * If dirtyend exceeds file size, chop it down.  This should
         * not normally occur but there is an append race where it
         * might occur XXX, so we log it.
         *
         * If the chopping creates a reverse-indexed or degenerate
         * situation with dirtyoff/end, we 0 both of them.
         */

        if (bp->b_dirtyend > bcount) {
            DEBUG("FUSE append race @%lx:%d\n",
                (long)bp->b_blkno * biosize,
                bp->b_dirtyend - bcount);
            bp->b_dirtyend = bcount;
        }

        if (bp->b_dirtyoff >= bp->b_dirtyend)
            bp->b_dirtyoff = bp->b_dirtyend = 0;

        /*
         * If the new write will leave a contiguous dirty
         * area, just update the b_dirtyoff and b_dirtyend,
         * otherwise force a write rpc of the old dirty area.
         *
         * While it is possible to merge discontiguous writes due to
         * our having a B_CACHE buffer ( and thus valid read data
         * for the hole), we don't because it could lead to
         * significant cache coherency problems with multiple clients,
         * especially if locking is implemented later on.
         *
         * as an optimization we could theoretically maintain
         * a linked list of discontinuous areas, but we would still
         * have to commit them separately so there isn't much
         * advantage to it except perhaps a bit of asynchronization.
         */

        if (bp->b_dirtyend > 0 &&
            (on > bp->b_dirtyend || (on + n) < bp->b_dirtyoff)) {
            /*
             * Yes, we mean it. Write out everything to "storage"
             * immediatly, without hesitation. (Apart from other
             * reasons: the only way to know if a write is valid
             * if its actually written out.)
             */
            bwrite(bp);
            if (bp->b_error == EINTR) {
                err = EINTR;
                break;
            }
            goto again;
        }

        err = uiomove((char *)bp->b_data + on, n, uio);

        /*
         * Since this block is being modified, it must be written
         * again and not just committed.  Since write clustering does
         * not work for the stage 1 data write, only the stage 2
         * commit rpc, we have to clear B_CLUSTEROK as well.
         */
        bp->b_flags &= ~(B_NEEDCOMMIT | B_CLUSTEROK);

        if (err) {
            bp->b_ioflags |= BIO_ERROR;
            bp->b_error = err;
            brelse(bp);
            break;
        }

        /*
         * Only update dirtyoff/dirtyend if not a degenerate
         * condition.
         */
        if (n) {
            if (bp->b_dirtyend > 0) {
                bp->b_dirtyoff = MIN(on, bp->b_dirtyoff);
                bp->b_dirtyend = MAX((on + n), bp->b_dirtyend);
            } else {
                bp->b_dirtyoff = on;
                bp->b_dirtyend = on + n;
            }
            vfs_bio_set_valid(bp, on, n);
        }

        err = bwrite(bp);
        if (err)
            break;
    } while (uio->uio_resid > 0 && n > 0);

    return (err);
}

int
fuse_io_strategy(struct vnode *vp, struct buf *bp)
#if 0
{
    struct fuse_filehandle *fufh;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct ucred *cred;
    struct uio *uiop;
    struct uio uio;
    struct iovec io;
    int error = 0;

    const int biosize = fuse_iosize(vp);

    MPASS(vp->v_type == VREG);
    MPASS(bp->b_iocmd == BIO_READ || bp->b_iocmd == BIO_WRITE);
    DEBUG("inode=%jd offset=%jd resid=%jd\n",
        VTOI(vp), ((off_t)bp->b_blkno) * biosize, bp->b_bcount);

    error = fuse_filehandle_getrw(vp,
	(bp->b_iocmd == BIO_READ) ? FUFH_RDONLY : FUFH_WRONLY, &fufh);
    if (error) {
        DEBUG("fetching filehandle failed\n");
        bp->b_ioflags |= BIO_ERROR;
        bp->b_error = error;
        return (error);
    }

    cred = bp->b_iocmd == BIO_READ ? bp->b_rcred : bp->b_wcred;

    uiop = &uio;
    uiop->uio_iov = &io;
    uiop->uio_iovcnt = 1;
    uiop->uio_segflg = UIO_SYSSPACE;
    uiop->uio_td = curthread;

    /*
     * clear BIO_ERROR and B_INVAL state prior to initiating the I/O.  We
     * do this here so we do not have to do it in all the code that
     * calls us.
     */
    bp->b_flags &= ~B_INVAL;
    bp->b_ioflags &= ~BIO_ERROR;

    KASSERT(!(bp->b_flags & B_DONE),
        ("fuse_io_strategy: bp %p already marked done", bp));
    if (bp->b_iocmd == BIO_READ) {
        io.iov_len = uiop->uio_resid = bp->b_bcount;
        io.iov_base = bp->b_data;
        uiop->uio_rw = UIO_READ;

        uiop->uio_offset = ((off_t)bp->b_blkno) * biosize;
        error = fuse_read_directbackend(vp, uiop, cred, fufh);

        if (!error && uiop->uio_resid) {
            /*
             * If we had a short read with no error, we must have
             * hit a file hole.  We should zero-fill the remainder.
             * This can also occur if the server hits the file EOF.
             *
             * Holes used to be able to occur due to pending
             * writes, but that is not possible any longer.
             */
            int nread = bp->b_bcount - uiop->uio_resid;
            int left  = uiop->uio_resid;

            if (left > 0)
                bzero((char *)bp->b_data + nread, left);
            uiop->uio_resid = 0;
        }
        if (error) {
            bp->b_ioflags |= BIO_ERROR;
            bp->b_error = error;
        }
    } else {
        /*
         * If we only need to commit, try to commit
         */
        if (bp->b_flags & B_NEEDCOMMIT) {
            DEBUG("write: B_NEEDCOMMIT flags set\n");
        }

        /*
         * Setup for actual write
         */
        if ((off_t)bp->b_blkno * biosize + bp->b_dirtyend > fvdat->filesize)
            bp->b_dirtyend = fvdat->filesize - (off_t)bp->b_blkno * biosize;

        if (bp->b_dirtyend > bp->b_dirtyoff) {
            io.iov_len = uiop->uio_resid = bp->b_dirtyend
              - bp->b_dirtyoff;
            uiop->uio_offset = (off_t)bp->b_blkno * biosize
              + bp->b_dirtyoff;
            io.iov_base = (char *)bp->b_data + bp->b_dirtyoff;
            uiop->uio_rw = UIO_WRITE;

            error = fuse_write_directbackend(vp, uiop, cred, fufh);

            if (error == EINTR || error == ETIMEDOUT
                || (!error && (bp->b_flags & B_NEEDCOMMIT))) {

                bp->b_flags &= ~(B_INVAL|B_NOCACHE);
                if ((bp->b_flags & B_PAGING) == 0) {
                    bdirty(bp);
                    bp->b_flags &= ~B_DONE;
                }
                if ((error == EINTR || error == ETIMEDOUT) &&
                    (bp->b_flags & B_ASYNC) == 0)
                    bp->b_flags |= B_EINTR;
            } else {
                if (error) {
                    bp->b_ioflags |= BIO_ERROR;
                    bp->b_flags |= B_INVAL;
                    bp->b_error = error;
                }
                bp->b_dirtyoff = bp->b_dirtyend = 0;
            }
        } else {
            bp->b_resid = 0;
            bufdone(bp);
            return (0);
        }
    }
    bp->b_resid = uiop->uio_resid;
    bufdone(bp);
    return (error);
}
#else
{
    struct fuse_filehandle *fufh;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_dispatcher fdi;
    struct ucred *cred; 
    int err = 0;
    int chunksize, respsize;
    caddr_t bufdat;
    int biosize = fuse_iosize(vp);

    if (!(vp->v_type == VREG || vp->v_type == VDIR)) {
        DEBUG("for vnode #%ju v_type is %d, dropping\n",
            (uintmax_t)VTOILLU(vp), vp->v_type);
        return (EOPNOTSUPP);
    }

    if (bp->b_iocmd != BIO_READ && bp->b_iocmd != BIO_WRITE) {
        DEBUG("for vnode #%ju bio tried with biocmd %#x, dropping\n",
            (uintmax_t)VTOILLU(vp), bp->b_iocmd);
        return (EOPNOTSUPP);
    }

    /*
     * clear BIO_ERROR and B_INVAL state prior to initiating the I/O. We
     * do this here so we do not have to do it in all the code that
     * calls us.
     */
    bp->b_flags &= ~B_INVAL;
    bp->b_ioflags &= ~BIO_ERROR;

    KASSERT(!(bp->b_flags & B_DONE),
        ("fuse_strategy: bp %p already marked done", bp));

    if (bp->b_bcount == 0)
        return (0);

    cred = bp->b_iocmd == BIO_READ ? bp->b_rcred : bp->b_wcred;

    err = fuse_filehandle_getrw(vp,
	(bp->b_iocmd == BIO_READ) ? FUFH_RDONLY : FUFH_WRONLY, &fufh);
    if (err) {
        DEBUG("fetching filehandle failed\n");
        goto out;
    }

    DEBUG2G("vp #%ju, fufh #%ju\n",
	(uintmax_t)VTOILLU(vp), (uintmax_t)fufh->fh_id);

    fdisp_init(&fdi, 0);

    if (bp->b_iocmd == BIO_READ) {
        struct fuse_read_in *fri;
        int ioff = 0;

        bufdat = bp->b_data;
        bp->b_resid = bp->b_bcount;
        while (bp->b_resid > 0) {
            DEBUG2G("starting bio with resid %ld\n", bp->b_resid);	
            chunksize = MIN(bp->b_resid,
                fuse_get_mpdata(vp->v_mount)->max_read);
            fdi.iosize = sizeof(*fri);
            fdisp_make_vp(&fdi, FUSE_READ, vp, curthread, cred);

            fri = fdi.indata;
            fri->fh = fufh->fh_id;
            fri->offset = ((off_t)bp->b_blkno) * biosize + ioff;
            chunksize = MIN(chunksize,
                MIN(fri->offset + bp->b_resid,
                fvdat->filesize) - fri->offset);
            if (chunksize == 0) {
                respsize = -1;
                goto eval;
            }
            fri->size = chunksize;
            fdi.tick->tk_aw_type = FT_A_BUF;
            fdi.tick->tk_aw_bufdata = bufdat;

            DEBUG("waiting for answer\n");
            if ((err = fdisp_wait_answ(&fdi)))
                goto out;

            respsize = fdi.tick->tk_aw_bufsize;
            DEBUG2G("chunksize %d, respsize %d, bp->b_resid %ld, bp->b_bcount %ld\n",
                chunksize, respsize, bp->b_resid, bp->b_bcount);
            bp->b_resid -= respsize;
            bufdat += respsize;
            ioff += respsize;

eval:
            DEBUG2G("%d bytes asked for from offset %llu, passing on the %d we got\n",
                chunksize, (long long unsigned)fri->offset, respsize);

            if (respsize < chunksize) {
                /*
                 * if we don't get enough data, just fill the
                 * rest with zeros.
                 */ 
                DEBUG("zeroing tail of %ld bytes\n",
                    bp->b_resid);
                bzero((char *)bp->b_data + bp->b_bcount - bp->b_resid,
                    bp->b_resid);
                if (chunksize)
                    bp->b_resid = 0;
                break;
            }
            if (respsize > chunksize) {
                fuse_ticket_drop(fdi.tick);
                err = EINVAL;
                goto out;
            }
            DEBUG("bp->b_data %p\n", bp->b_data);
        }
    } else {
        struct fuse_write_in *fwi;
        struct fuse_write_out *fwo;
        int diff;
        int merr = 0;

        bufdat = bp->b_data + bp->b_dirtyoff;
        while (bp->b_dirtyend > bp->b_dirtyoff) {
            chunksize = MIN(bp->b_dirtyend - bp->b_dirtyoff,
                fuse_get_mpdata(vp->v_mount)->max_write);

            fdi.iosize = sizeof(*fwi);
            fdisp_make_vp(&fdi, FUSE_WRITE, vp, NULL, cred);

            fwi = fdi.indata;
            fwi->fh = fufh->fh_id;
            fwi->offset = (off_t)bp->b_blkno * biosize + bp->b_dirtyoff;
            fwi->size = chunksize;
            fdi.tick->tk_ms_type = FT_M_BUF;
            fdi.tick->tk_ms_bufdata = bufdat;
            fdi.tick->tk_ms_bufsize = chunksize;

            if ((err = fdisp_wait_answ(&fdi))) {
                merr = 1;
                break;
            }

            fwo = fdi.answ;
            diff = chunksize - fwo->size;
            if (diff < 0) {
                err = EINVAL;
                break;
            }
            if (diff > 0) {
                /*
                 * Tolerating a short read would mean
                 * keeping dirty data around and we
                 * don't do that.
                 */
                err = EIO;
                break;
            }

            bp->b_dirtyoff += fwo->size; 
        }

        if (bp->b_dirtyend == bp->b_dirtyoff)
            bp->b_dirtyend = bp->b_dirtyoff = 0;

        bp->b_resid = bp->b_dirtyend - bp->b_dirtyoff;

        if (merr)
            goto out;
    }

    if (fdi.tick)
        fuse_ticket_drop(fdi.tick);
    else
        DEBUG("no ticket on leave\n");

out:
    if (err) {
        bp->b_ioflags |= BIO_ERROR;
        bp->b_error = err;
    }
    DEBUG("calling bufdone\n");      
    bufdone(bp);

    return (err);
}	
#endif
