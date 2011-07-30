KMOD=	fuse

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

DEBUG_FLAGS+= -g
# -DFUSE_DEBUG_VNOPS=1 -DFUSE_DEBUG_IPC=1 -DFUSE_DEBUG_VFSOPS=1

.include <bsd.kmod.mk>
