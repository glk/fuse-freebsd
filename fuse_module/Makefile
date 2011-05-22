.undef KERNCONF

.include "../Makefile.common"

SRCS = fuse_main.c    \
       fuse_msg.c     \
       fuse_dev.c     \
       fuse_vfsops.c  \
       fuse_vnops.c   \
       fuse_io.c      \
       fuse_subr.c    \
       fuse.h         \
       fuse_session.h \
       fuse_internal.h \
       fuse_io.h      \
       fuse_node.h    \
       vnode_if.h

CFLAGS+= -I../include

.if defined(FMASTER)
SRCS+= fmaster.c
CFLAGS+= -DFMASTER
.endif

.if defined(KERNCONF)
KERNCONF1!= echo ${KERNCONF} | sed -e 's/ .*//g'
KRNLOBJDIR!=	make -C /usr/src -f /usr/src/Makefile.inc1 -V KRNLOBJDIR
KERNCONFDIR= ${KRNLOBJDIR}/${KERNCONF1}
.endif

.if defined(KERNCONFDIR)
CFLAGS+= -DKERNCONFDIR="\"${KERNCONFDIR}\"" -I${KERNCONFDIR}
.endif

.if defined(DEBUG_MSG)
DEBUG_FLAGS+= -D_DEBUG_MSG
.endif

.if defined(FMASTER) || defined(DEBUG) || defined(DEBUG2G) || \
    defined(DEBUG3G) || defined(DEBUG_MSG)
SRCS+= fuse_opnames.c
.endif

KMOD=fuse

CLEANFILES+= fuse_opnames.c fuse_opnames.o fuse_subr.o fmaster.o vnode_if.h \
             vnode_if_typedef.h vnode_if_newproto.h fuse.ko.debug \
	     fuse.ko.symbols

fuse.ko: fuse_kernel.h

fuse_opnames.c:
	env OUTF=fuse_opnames.c ${AWK} -f ../tools/genopnames.awk fuse_kernel.h

.include <bsd.kmod.mk>
