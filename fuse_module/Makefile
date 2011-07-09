.undef KERNCONF

.include "../Makefile.common"

SRCS=	fuse.h		\
	fuse_kernel.h	\
	fuse_device.c	\
	fuse_file.c	\
	fuse_file.h	\
	fuse_internal.c	\
	fuse_internal.h	\
	fuse_io.c	\
	fuse_io.h	\
	fuse_ipc.c	\
	fuse_ipc.h	\
	fuse_main.c	\
	fuse_node.c	\
	fuse_node.h	\
	fuse_vfsops.c	\
	fuse_vnops.c	\
	vnode_if.h

CFLAGS+= -I../include
DEBUG_FLAGS+= -g
# -DFUSE_DEBUG_VNOPS=1

.if defined(KERNCONF)
KERNCONF1!= echo ${KERNCONF} | sed -e 's/ .*//g'
KRNLOBJDIR!=	make -C /usr/src -f /usr/src/Makefile.inc1 -V KRNLOBJDIR
KERNCONFDIR= ${KRNLOBJDIR}/${KERNCONF1}
.endif

.if defined(KERNCONFDIR)
CFLAGS+= -DKERNCONFDIR="\"${KERNCONFDIR}\"" -I${KERNCONFDIR}
.endif

KMOD=fuse

.include <bsd.kmod.mk>
