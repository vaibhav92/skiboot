/* Copyright 2013-2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <libflash/libffs.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <pnor.h>

int pnor_init(const char *pnor_path, struct ffs_handle **ffsh)
{
	int rc, fd;
	uint32_t size;

	/* Open device and ffs */
	fd = open(pnor_path, O_RDWR);
	if (fd < 0) {
		perror(pnor_path);
		return -1;
	}

	/* A mtd device does not give us a size when stat'd */
	size = lseek(fd, 0, SEEK_END);
	if (size < 0) {
		perror(pnor_path);
		goto out;
	}

	printf("Found PNOR: %d bytes\n", size);

	rc = ffs_open_image(fd, size, 0, ffsh);
	if (rc)
		fprintf(stderr, "Failed to open pnor partition table\n");

out:
	close(fd);

	return rc;
}

void dump_parts(struct ffs_handle *ffs) {
	int i, rc;
	uint32_t start, size, act_size;
	char *name;

	printf(" %10s %8s %8s %8s\n", "name", "start", "size", "act_size"); 
	for (i = 0; ; i++) {
		rc = ffs_part_info(ffs, i, &name, &start, &size, &act_size);
		if (rc)
			break;
		printf(" %10s %08x %08x %08x\n", name, start, size, act_size);
		free(name);
	}
}

int pnor_operation(const char *pnor_path, struct ffs_handle *ffsh,
		   const char *name, uint64_t offset, void *data, size_t size,
		   enum pnor_op op)
{
	int rc, fd;
	uint32_t pstart, psize, idx;

	if (!ffsh)
		return -1;

	rc = ffs_lookup_part(ffsh, name, &idx);
	if (rc)
		return -1;

	ffs_part_info(ffsh, idx, NULL, &pstart, &psize, NULL);
	if (rc)
		return -1;

	if (size > psize || offset > psize || size + offset > psize)
		return -1;

	fd = open(pnor_path, O_RDWR);
	if (fd < 0) {
		perror(pnor_path);
		return fd;
	}

	rc = lseek(fd, pstart, SEEK_SET);
	if (rc < 0) {
		perror(pnor_path);
		goto out;
	}

	switch (op) {
	case PNOR_OP_READ:
		rc = read(fd, data, size);
		break;
	case PNOR_OP_WRITE:
		rc = write(fd, data, size);
		break;
	default:
		rc  = -1;
		fprintf(stderr, "PNOR: Invalid operation\n");
		goto out;
	}

	if (rc < 0)
		perror(pnor_path);

out:
	close(fd);

	return rc;
}
