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

#if (__FreeBSD__ >= 8)
#define vfs_bio_set_validclean vfs_bio_set_valid
#endif

#include "fuse.h"
#include "fuse_node.h"
#include "fuse_session.h"
#include "fuse_io.h"

int fuse_read_directbackend(struct fuse_io_data *fioda);
static int fuse_io_p2p(struct fuse_io_data *fioda, struct fuse_dispatcher *fdip);
static int fuse_read_biobackend(struct fuse_io_data *fioda);
static int fuse_write_directbackend(struct fuse_io_data *fioda);
static int fuse_write_biobackend(struct fuse_io_data *fioda);

static fuse_buffeater_t fuse_std_buffeater; 

/****************
 *
 * >>> Low level I/O routines and interface to them
 *
 ****************/

/* main I/O dispatch routine */
int
fuse_io_dispatch(struct vnode *vp, struct fuse_filehandle *fufh, struct uio *uio,
                 struct ucred *cred, int flag, struct thread *td)
{
	int err;
	struct fuse_io_data fioda;
	int directio;

	RECTIFY_TDCR(td, cred);
	ASSERT_VOP_LOCKED__FH(vp);

	if (fufh)
		fufh->useco++;
	else if ((err = fuse_get_filehandle(vp, NULL, cred, flag, &fufh, NULL))) {
		DEBUG2G("no filehandle for vnode #%llu\n", VTOILLU(vp));
		return (err);
	}

	bzero(&fioda, sizeof(fioda));
	fioda.vp = vp;
	fioda.fufh = fufh;
	fioda.uio = uio;
	fioda.cred = cred;
	fioda.td = td;

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
	directio = (flag & O_DIRECT) || (fufh->flags & FOPEN_DIRECT_IO);

	switch (uio->uio_rw) {
	case UIO_READ:
		fioda.opcode = FUSE_READ;
		fioda.buffeater = fuse_std_buffeater;

		if (directio) {
			DEBUG2G("direct read of vnode %llu via file handle %llu\n",
			        VTOILLU(vp), (unsigned long long)fufh->fh_id);
			err = fuse_read_directbackend(&fioda);
		} else {
			DEBUG2G("buffered read of vnode %llu\n", VTOILLU(vp));
			err = fuse_read_biobackend(&fioda);
		}
		break;
	case UIO_WRITE:
		if (directio) {
			DEBUG2G("direct write of vnode %llu via file handle %llu\n",
		        	VTOILLU(vp), (unsigned long long)fufh->fh_id);
			err = fuse_write_directbackend(&fioda);
		} else {
			DEBUG2G("buffered write of vnode %llu\n", VTOILLU(vp));
			err = fuse_write_biobackend(&fioda);
		}
		break;
	default:
		panic("uninterpreted mode passed to fuse_io_dispatch");
	}

	if (VTOFUD(vp))
		fufh->useco--;
	else
		DEBUG2G("poor nasty nasty vnode %p...\n", vp);
	fuse_invalidate_attr(vp);

	return (err);
}

/* dispatch routine for file based I/O */
int
fuse_io_file(struct file *fp, struct uio *uio, struct ucred *cred, int flags,
	     struct thread *td)
{
	struct fuse_filehandle *fufh;
	struct vattr va;
	struct vnode *vp, *ovl_vp = fp->f_vnode;
	int err = 0;

	vn_lock(ovl_vp, LK_EXCLUSIVE | LK_RETRY);

	if (_file_is_bad(fp) || ! _file_is_fat(fp)) {
		err = EBADF;
		goto out;
	}
	fufh = FTOFH(fp);
	vp = fufh->fh_vp;
	ASSERT_VOP_LOCKED__FH(vp);

	if (uio->uio_resid == 0)
		goto out;

	if (uio->uio_rw == UIO_WRITE && fp->f_flag & O_APPEND) {
		if ((err = VOP_GETATTR(vp, &va, cred)))
			goto out;
		uio->uio_offset = va.va_size;
	} else if ((flags & FOF_OFFSET) == 0)
		uio->uio_offset = fp->f_offset;

	err = fuse_io_dispatch(vp, fufh->op == FUSE_OPEN ? fufh : NULL, uio,
	                       cred, fp->f_flag, td);

	if ((flags & FOF_OFFSET) == 0)
		fp->f_offset = uio->uio_offset;
	fp->f_nextoff = uio->uio_offset;

out:
	VOP_UNLOCK(ovl_vp, 0);
	DEBUG("leaving with %d\n", err);
	return (err);
}

/* dispatch routine for vnode based I/O */
int
fuse_io_vnode(struct vnode *vp, struct ucred *cred, struct uio *uio,
              int ioflag)
{
	int fflag = (uio->uio_rw == UIO_READ) ? FREAD : FWRITE;
	int err;

	if (ioflag & IO_DIRECT)
		fflag |= O_DIRECT;
	if (ioflag & IO_NDELAY)
		fflag |= FNONBLOCK;
	if (ioflag & IO_APPEND)
		fflag |= O_APPEND;
	if (ioflag & IO_ASYNC)
		fflag |= O_ASYNC;
	if (ioflag & IO_SYNC)
		fflag |= O_SYNC;

	err = fuse_io_dispatch(vp, NULL, uio, cred, fflag, NULL);

	DEBUG("return with %d\n", err);
	return (err);
}

int
fuse_read_biobackend(struct fuse_io_data *fioda)
{

	struct vnode *vp = fioda->vp;
	struct fuse_filehandle *fufh = fioda->fufh;
	struct uio *uio = fioda->uio;
	enum fuse_opcode op = fioda->opcode;
	fuse_buffeater_t *buffe = fioda->buffeater;
	void *param = fioda->param;

	int biosize;
	struct buf *bp;
	daddr_t lbn;
	int bcount;
	int bbcount;
	int err = 0, n = 0, on = 0;

	if (uio->uio_resid == 0)
		return (0);

	biosize = vp->v_mount->mnt_stat.f_iosize;
	bcount = MIN(MAXBSIZE, biosize);

	DEBUG2G("entering loop\n");
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
			err = fuse_strategy_i(vp, bp, fufh, op);
#if _DEBUG
			prettyprint(bp->b_data, 48);
			printf("\n");
			prettyprint(bp->b_data + PAGE_SIZE, 48);
			printf("\n");
#endif
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
		/*
		 * If we zero pad the buf, bp->b_resid will be 0, so then
		 * just ignore it
		 */
		bbcount = bcount - bp->b_resid;
		if (on < bbcount)
			n = bbcount - on;
		if (n > 0) {
			DEBUG2G("feeding buffeater with %d bytes of buffer %p, saying %d was asked for\n",
			        n, bp->b_data + on, n + (int)bp->b_resid);
#if 0 && _DEBUG
		        prettyprint(bp->b_data + on, n);
			printf("\n");
#endif
		        err = buffe(uio, n + bp->b_resid, bp->b_data + on, n,
			            param);
		}
		brelse(bp);
		DEBUG2G("end of turn, err %d, uio->uio_resid %d, n %d\n",
		      err, uio->uio_resid, n);
	} while (err == 0 && uio->uio_resid > 0 && n > 0);

	return ((err == -1) ? 0 : err);
}

int
fuse_read_directbackend(struct fuse_io_data *fioda)
{
	struct vnode *vp = fioda->vp;
	struct fuse_filehandle *fufh = fioda->fufh;
	struct uio *uio = fioda->uio;
	struct ucred *cred = fioda->cred;
	struct thread *td = fioda->td;
	enum fuse_opcode op = fioda->opcode;
	fuse_buffeater_t *buffe = fioda->buffeater;
	void *param = fioda->param;

	struct fuse_dispatcher fdi;
	struct fuse_read_in *fri;
	int err = 0;

	if (uio->uio_resid == 0)
		return (0);

	DEBUG("bug daemon for food\n");

	fdisp_init(&fdi, 0);

	/*
	 * XXX In "normal" case we use an intermediate kernel buffer for
	 * transmitting data from daemon's context to ours. Eventually, we should
	 * get rid of this. Anyway, if the target uio lives in sysspace (we are
	 * called from pageops), and the input data doesn't need kernel-side
	 * processing (we are not called from readdir) we can already invoke
	 * an optimized, "peer-to-peer" I/O routine.
	 */
	if (buffe == fuse_std_buffeater && uio->uio_segflg == UIO_SYSSPACE) {
		if ((err = fuse_io_p2p(fioda, &fdi)))
			goto out;
		else
			goto done;
	}

	while (uio->uio_resid > 0) {
		fdi.iosize = sizeof(*fri);
		fdisp_make_vp(&fdi, op, vp, td, cred);
		fri = fdi.indata;
		fri->fh = fufh->fh_id;
		fri->offset = uio->uio_offset;
		fri->size = MIN(uio->uio_resid,
		                fusefs_get_data(vp->v_mount)->max_read);
	
		DEBUG2G("fri->fh %llu, fri->offset %d, fri->size %d\n",
		        (unsigned long long)fri->fh, (int)fri->offset, fri->size);
		if ((err = fdisp_wait_answ(&fdi)))
			goto out;
	
		DEBUG2G("%d bytes asked for from offset %d, passing on the %d we got\n",
		        uio->uio_resid, (int)uio->uio_offset, (int)fdi.iosize);

		if ((err = buffe(uio, fri->size, fdi.answ, fdi.iosize, param)))
			break;
	}

done:
	fuse_ticket_drop(fdi.tick);

out:
	return ((err == -1) ? 0 : err);
}

/* direct I/O routine with no intermediate buffer */
static int
fuse_io_p2p(struct fuse_io_data *fioda, struct fuse_dispatcher *fdip)
{
	struct vnode *vp = fioda->vp;
	struct fuse_filehandle *fufh = fioda->fufh;
	struct uio *uio = fioda->uio;
	struct ucred *cred = fioda->cred;
	struct thread *td = fioda->td;
        enum fuse_opcode op;

	int err = 0;
	int chunksize = 0;
	struct iovec *iov;
	int nmax = (uio->uio_rw == UIO_READ) ?
	  fusefs_get_data(vp->v_mount)->max_read :
	  fusefs_get_data(vp->v_mount)->max_write;

	op = fioda->opcode ?:
	       ((uio->uio_rw == UIO_READ) ? FUSE_READ : FUSE_WRITE);

	iov = uio->uio_iov;
	while (uio->uio_resid > 0) {
		int transfersize;

		chunksize = MIN(iov->iov_len, nmax);

		if (uio->uio_rw == UIO_READ) {
			struct fuse_read_in *fri;

			fdip->iosize = sizeof(struct fuse_read_in);
			fdisp_make_vp(fdip, op, vp, td, cred);
			fri = fdip->indata;
			fri->fh = fufh->fh_id;
			fri->offset = uio->uio_offset;
			fri->size = chunksize;
			fdip->tick->tk_aw_type = FT_A_BUF;
			fdip->tick->tk_aw_bufdata = iov->iov_base;
		} else {
			struct fuse_write_in *fwi;

			fdip->iosize = sizeof(struct fuse_write_in) + chunksize;
			fdisp_make_vp(fdip, op, vp, td, cred);
			fwi = fdip->indata;
			fwi->fh = fufh->fh_id;
			fwi->offset = uio->uio_offset;
			fwi->size = chunksize;
			fdip->tick->tk_ms_type = FT_M_BUF;
			fdip->tick->tk_ms_bufdata = iov->iov_base;
			fdip->tick->tk_ms_bufsize = chunksize;
		}

		DEBUG2G("chunksize %d\n", chunksize);
		fdip->finh->len = (sizeof *fdip->finh) + chunksize;
		err = fdisp_wait_answ(fdip);

		if (err)
			return (err);

		transfersize = (uio->uio_rw == UIO_READ) ?
		                   fdip->tick->tk_aw_ohead.len - sizeof(struct fuse_out_header) :
		                   ((struct fuse_write_out *)fdip->answ)->size; 

		uio->uio_resid -= transfersize;
		uio->uio_offset += transfersize;
		iov->iov_len -= transfersize;
		iov->iov_base = (char *)iov->iov_base + transfersize;

		if (iov->iov_len == 0) {
			iov++;
			uio->uio_iovcnt--;
		}
		DEBUG2G("resid %d, offset %llu, iovcnt %d, iov_len %d, "
		        "transfersize %d\n",
		        uio->uio_resid, (long long unsigned)uio->uio_offset,
			uio->uio_iovcnt, iov->iov_len, transfersize);

		if (transfersize < chunksize)
			break;
	}

	return (0);
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
fuse_write_directbackend(struct fuse_io_data *fioda)
{	
	struct vnode *vp = fioda->vp;
	uint64_t fh_id = fioda->fufh->fh_id;
	struct uio *uio = fioda->uio;
	struct ucred *cred = fioda->cred;
	struct thread *td = fioda->td;

	size_t chunksize;
	int diff;
	struct fuse_write_in *fwi;
	struct fuse_dispatcher fdi;
	int err = 0;

	if (! uio->uio_resid)
		return (0);

	fdisp_init(&fdi, 0);

	if (uio->uio_segflg == UIO_SYSSPACE) {
		if ((err = fuse_io_p2p(fioda, &fdi)))
			return (err);
		else
			goto out;
	}

	while (uio->uio_resid > 0) {
		chunksize = MIN(uio->uio_resid,
		                fusefs_get_data(vp->v_mount)->max_write);

		fdi.iosize = sizeof(*fwi) + chunksize;
		fdisp_make_vp(&fdi, FUSE_WRITE, vp, td, cred);
	
		fwi = fdi.indata;
		fwi->fh = fh_id;
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
	}

out:
	fuse_ticket_drop(fdi.tick);

	return (err);
}

/*
 * Vnode op for write using bio
 */
static int
fuse_write_biobackend(struct fuse_io_data *fioda)
{
	struct vnode *vp = fioda->vp;
	struct uio *uio = fioda->uio;
	struct ucred *cred = fioda->cred;

	int biosize;

	struct buf *bp;
	daddr_t lbn;
	int bcount;
	int n, on, err = 0;
	vm_ooffset_t fsize = vp->v_object->un_pager.vnp.vnp_size;

	DEBUG2G("fsize %lld\n", (long long int)fsize); 

	biosize = vp->v_mount->mnt_stat.f_iosize;

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
		
		DEBUG2G("lbn %d, on %d, n %d, uio offset %d, uio resid %d\n",
		        (int)lbn, on, n, (int)uio->uio_offset, uio->uio_resid);

again:
		/*
		 * Handle direct append and file extension cases, calculate
		 * unaligned buffer size.
		 */

		if (uio->uio_offset == fsize && n) {
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

				fsize = uio->uio_offset + n;
				vnode_pager_setsize(vp, fsize);

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
			if ((off_t)lbn * biosize + bcount < fsize) {
				if ((off_t)(lbn + 1) * biosize < fsize)
					bcount = biosize;
				else
					bcount = fsize - (off_t)lbn * biosize;
			}
			DEBUG("getting block from OS, bcount %d\n", bcount);
			bp = getblk(vp, lbn, bcount, PCATCH, 0, 0);
			if (uio->uio_offset + n > fsize) {
				fsize = uio->uio_offset + n;
				vnode_pager_setsize(vp, fsize);
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
			fuse_strategy_i(vp, bp, NULL, 0);
			if ((err =  bp->b_error)) {
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
			DEBUG2G("Fuse append race @%lx:%d\n",
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
			vfs_bio_set_validclean(bp, on, n);
		}

		bwrite(bp);
		if ((err =  bp->b_error))
			break;
	} while (uio->uio_resid > 0 && n > 0);

	return (err);
}

/* core strategy like routine */
int
fuse_strategy_i(struct vnode *vp, struct buf *bp, struct fuse_filehandle *fufh,
                enum fuse_opcode op)
{
	struct fuse_dispatcher fdi;
	struct ucred *cred; 
	int err = 0;
	int chunksize, respsize;
	caddr_t bufdat;
	int biosize = vp->v_mount->mnt_stat.f_iosize;

	if (! (vp->v_type == VREG || vp->v_type == VDIR)) {
		DEBUG("for vnode #%llu v_type is %d, dropping\n",
		      VTOILLU(vp), vp->v_type);
		return (EOPNOTSUPP);
	}

	if (bp->b_iocmd != BIO_READ && bp->b_iocmd != BIO_WRITE) {
		DEBUG("for vnode #%llu bio tried with biocmd %#x, dropping\n",
		       VTOILLU(vp), bp->b_iocmd);
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

#if _DEBUG
	DEBUG2G("reading from block #%d at vnode:\n", (int)bp->b_blkno);
	vn_printf(vp, " * ");
#endif
	if (fufh) {
		DEBUG2G("we have a useable filehandle passed on\n");
		fufh->useco++;
	} else
		err = fuse_get_filehandle(vp, NULL, cred,
	                             bp->b_iocmd == BIO_READ ? FREAD : FWRITE,
		                     &fufh, NULL);

	if (err) {
		DEBUG2G("fetching filehandle failed\n");
		goto out;
	}

	DEBUG2G("vp #%llu, fufh #%llu\n", VTOILLU(vp), (unsigned long long)fufh->fh_id);

	fdisp_init(&fdi, 0);

	if (bp->b_iocmd == BIO_READ) {
		struct fuse_read_in *fri;
		int ioff = 0;
#if FUSELIB_CONFORM_BIOREAD
		struct vattr va;

		if ((err = VOP_GETATTR(vp, &va, cred)))
			goto out;
#endif

		bufdat = bp->b_data;
		bp->b_resid = bp->b_bcount;
		while (bp->b_resid > 0) {
			DEBUG2G("starting bio with resid %ld\n", bp->b_resid);	
			chunksize = MIN(bp->b_resid,
			                fusefs_get_data(vp->v_mount)->max_read);
			fdi.iosize = sizeof(*fri);
			if (! op)
				op = vp->v_type == VDIR ? FUSE_READDIR : FUSE_READ;
			fdisp_make_vp(&fdi, op, vp, curthread, cred);
		
			fri = fdi.indata;
			fri->fh = fufh->fh_id;
			fri->offset = ((off_t)bp->b_blkno) * biosize + ioff;
#if FUSELIB_CONFORM_BIOREAD
			chunksize = MIN(chunksize,
			                MIN(fri->offset + bp->b_resid,
			                    va.va_size) - fri->offset);
			if (chunksize == 0) {
				respsize = -1;
				goto eval;
			}
#endif
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

#if FUSELIB_CONFORM_BIOREAD
eval:
#endif
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
#if FUSELIB_CONFORM_BIOREAD
				if (chunksize)
					bp->b_resid = 0;
#endif
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
			                fusefs_get_data(vp->v_mount)->max_write);
	
			fdi.iosize = sizeof(*fwi);
			op = op ?: FUSE_WRITE;
			fdisp_make_vp(&fdi, op, vp, NULL, cred);
		
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
	if (fufh)
		fufh->useco--;

	if (err) {
		bp->b_ioflags |= BIO_ERROR;
		bp->b_error = err;
	}
	DEBUG("calling bufdone\n");      
	bufdone(bp);

	return (err);
}	
