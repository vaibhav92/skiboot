#ifndef PNOR_H
#define PNOR_H

#include <libflash/libffs.h>

enum pnor_op {
	PNOR_OP_READ,
	PNOR_OP_WRITE,
};

extern int pnor_operation(const char *pnor_path, struct ffs_handle *ffsh,
			  const char *name, uint64_t offset, void *data,
			  size_t size, enum pnor_op);

extern int pnor_init(const char *pnor_path, struct ffs_handle **ffsh);

#endif /*PNOR_H*/
