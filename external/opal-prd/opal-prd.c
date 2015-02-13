
/*
 * Basic mmap test case
 */

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <err.h>

#include <endian.h>

#include <sys/ioctl.h>

#include <types.h>
#include <asm/opal-prd.h>
#include <opal.h>

#include "hostboot-interface.h"

struct opal_prd_ctx {
	int			fd;
	struct opal_prd_info	info;
	long			page_size;
	void			*code_addr;
	size_t			code_size;
	bool			debug;
};

static struct opal_prd_ctx *ctx;

static const char *opal_prd_devnode = "/dev/opal-prd";
static const char *hbrt_code_region_name = "ibm,hbrt-code-image";
static const int opal_prd_version = 1;
static const uint64_t opal_prd_ipoll = 0xf000000000000000;

/* This is the "real" HBRT call table for calling into HBRT as
 * provided by it. It will be used by the assembly thunk
 */
struct runtime_interfaces *hservice_runtime;
struct runtime_interfaces hservice_runtime_fixed;

/* This is the callback table provided by assembly code */
extern struct host_interfaces hinterface;

/* Create opd to call hostservice init */
struct func_desc {
	void *addr;
	void *toc;
} hbrt_entry;

static struct opal_prd_range *find_range(const char *name)
{
	struct opal_prd_range *range;
	unsigned int i;

	for (i = 0; i < OPAL_PRD_MAX_RANGES; i++) {
		range = &ctx->info.ranges[i];

		if (!strncmp(range->name, name, sizeof(range->name)))
			return range;
	}

	return NULL;
}

static void pr_debug(struct opal_prd_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	if (!ctx->debug)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* HBRT init wrappers */
extern struct runtime_interfaces *call_hbrt_init(struct host_interfaces *);

/* hservice Call wrappers */

extern void call_cxxtestExecute(void *);
extern int call_handle_attns(uint64_t i_proc,
			uint64_t i_ipollStatus,
			uint64_t i_ipollMask);
extern void call_process_occ_error (uint64_t i_chipId);
extern int call_enable_attns(void);
extern int call_enable_occ_actuation(bool i_occActivation);
extern void call_process_occ_reset(uint64_t i_chipId);

/* Dummy calls for hservices */
static inline void __fsp_only_assert(const char *name)
{
	printf("error: %s is only implemented for FSP\n", name);
	exit(EXIT_FAILURE);
}
#define fsp_stub(name) \
	void hservice_ ##name(void) { __fsp_only_assert(#name); }

fsp_stub(send_error_log);
fsp_stub(lid_load);
fsp_stub(lid_unload);
fsp_stub(wakeup);
fsp_stub(report_occ_failure);

void hservice_puts(const char *str)
{
	printf("%s\n", str);
}

void hservice_assert(void)
{
	printf("HBRT Called ASSERT() running while(1)\n");
	while(1);
}

void *hservice_malloc(size_t size)
{
	return malloc(size);
}

void hservice_free(void *ptr)
{
	free(ptr);
}

void *hservice_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

int hservice_scom_read(uint64_t chip_id, uint64_t addr, void *buf)
{
	int rc;
	struct opal_prd_scom scom;

	scom.chip = chip_id;
	scom.addr = addr;

	rc = ioctl(ctx->fd, OPAL_PRD_SCOM_READ, &scom);
	if (rc) {
		perror("ioctl scom_read");
		return 0;
	}

	printf("scom read: chip %lx addr %lx val %lx\n",
			chip_id, addr, scom.data);

	*(uint64_t *)buf = htobe64(scom.data);

	return 0;
}

int hservice_scom_write(uint64_t chip_id, uint64_t addr,
                               const void *buf)
{
	int rc;
	struct opal_prd_scom scom;

	scom.chip = chip_id;
	scom.addr = addr;
	scom.data = be64toh(*(uint64_t *)buf);

	rc = ioctl(ctx->fd, OPAL_PRD_SCOM_WRITE, &scom);
	if (rc) {
		perror("ioctl scom_write");
		return 0;
	}

	printf("scom write: chip %lx addr %lx val %lx\n",
			chip_id, addr, scom.data);

	return 0;
}

uint64_t hservice_get_reserved_mem(const char *name)
{
	uint64_t align_physaddr, offset;
	struct opal_prd_range *range;
	void *addr;

	printf("hservice_get_reserved_mem: %s\n", name);

	range = find_range(name);
	if (!range) {
		printf("no such range %s", name);
		return 0;
	}

	printf("Mapping 0x%016lx 0x%08lx %s\n", range->physaddr, range->size,
			range->name);

	align_physaddr = range->physaddr & ~(ctx->page_size-1);
	offset = range->physaddr & (ctx->page_size-1);
	addr = mmap(NULL, range->size, PROT_WRITE | PROT_READ,
				MAP_PRIVATE, ctx->fd, align_physaddr);

	if (addr == MAP_FAILED) {
		perror("mmap");
		return 0;
	}

	printf("hservice_get_reserved_mem: %s address %p\n", name, addr);
	if (addr)
		return (uint64_t)addr + offset;

	return 0;
}

void hservice_nanosleep(uint64_t i_seconds, uint64_t i_nano_seconds)
{
	const struct timespec ns = {
		.tv_sec = i_seconds,
		.tv_nsec = i_nano_seconds
	};

	nanosleep(&ns, NULL);
}

int hservice_set_page_execute(void *addr)
{
	pr_debug(ctx, "FIXME: hservice_set_page_execute(%p)\n", addr);
	return -1;
}

int hservice_clock_gettime(clockid_t i_clkId, struct timespec *o_tp)
{
	return clock_gettime(i_clkId, o_tp);
}

int hservice_pnor_read(uint32_t i_proc, const char* i_partitionName,
		uint64_t i_offset, void* o_data, size_t i_sizeBytes)
{
	printf("FIXME:Calling ........hservice_pnor_read()\n");
	return -1;
}

int hservice_pnor_write(uint32_t i_proc, const char* i_partitionName,
		uint64_t i_offset, void* o_data, size_t i_sizeBytes)
{
	printf("FIXME:Calling ........hservice_pnor_write()\n");
	return -1;
}

int hservice_i2c_read(uint64_t i_master, uint8_t i_engine, uint8_t i_port,
		uint16_t i_devAddr, uint32_t i_offsetSize, uint32_t i_offset,
		uint32_t i_length, void* o_data)
{
	printf("FIXME: %s\n", __func__);
	return -1;
}

int hservice_i2c_write(uint64_t i_master, uint8_t i_engine, uint8_t i_port,
		uint16_t i_devAddr, uint32_t i_offsetSize, uint32_t i_offset,
		uint32_t i_length, void* i_data)
{
	printf("FIXME: %s\n", __func__);
	return -1;
}

int hservice_ipmi_msg(void *tx_buf, size_t tx_size,
		void *rx_buf, size_t *rx_size)
{
	printf("FIXME: %s\n", __func__);
	return -1;
}

int hservice_memory_error(uint64_t i_start_addr, uint64_t i_endAddr,
		enum MemoryError_t i_errorType)
{
	printf("FIXME: %s\n", __func__);
	return -1;
}

void hservices_init(void *code)
{
	uint64_t *s, *d;
	int i, sz;

	printf("code Address : [%p]\n", code);

	/* We enter at 0x100 into the image. */
	/* Load func desc in BE since we reverse it in thunk */

	hbrt_entry.addr = (void *)htobe64((unsigned long)code + 0x100);
	hbrt_entry.toc = 0; /* No toc for init entry point */

	if (memcmp(code, "HBRTVERS", 8) != 0) {
		printf("HBRT: Bad signature for ibm,hbrt-code-image!"
				"exiting\n");
		exit(-1);
	}

	printf("HBRT: calling ibm,hbrt_init() %p\n", hservice_runtime);
	hservice_runtime = call_hbrt_init(&hinterface);
	printf("HBRT: hbrt_init passed..... %p version %016lx\n",
			hservice_runtime, hservice_runtime->interface_version);

	sz = sizeof(struct runtime_interfaces)/sizeof(uint64_t);
	s = (uint64_t *)hservice_runtime;
	d = (uint64_t *)&hservice_runtime_fixed;
	/* Byte swap the function pointers */
	for (i = 0; i < sz; i++) {
		d[i] = be64toh(s[i]);
		printf(" 	hservice_runtime_fixed[%d] = %016lx\n",
				i, d[i]);
	}

}

static void fixup_hinterface_table(void)
{
	uint64_t *t64;
	unsigned int i, sz;

	/* Swap interface version */
	hinterface.interface_version =
		htobe64(hinterface.interface_version);

	/* Swap OPDs */
	sz = sizeof(struct host_interfaces) / sizeof(uint64_t);
	t64 = (uint64_t *)&hinterface;
	for (i = 1; i < sz; i++) {
		uint64_t *opd = (uint64_t *)t64[i];
		if (!opd)
			continue;
		t64[i] = htobe64(t64[i]);
		opd[0] = htobe64(opd[0]);
		opd[1] = htobe64(opd[1]);
		opd[2] = htobe64(opd[2]);
	}
}

static int map_hbrt_file(struct opal_prd_ctx *ctx, const char *name)
{
	struct stat statbuf;
	int fd, rc;
	void *buf;

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		warn("open(%s)", name);
		return -1;
	}

	rc = fstat(fd, &statbuf);
	if (rc < 0) {
		warn("fstat(%s)", name);
		close(fd);
		return -1;
	}

	buf = mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE, fd, 0);
	close(fd);

	if (buf == MAP_FAILED) {
		warn("mmap(%s)", name);
		return -1;
	}

	ctx->code_addr = buf;
	ctx->code_size = statbuf.st_size;
	return -0;
}

static int map_hbrt_physmem(struct opal_prd_ctx *ctx, const char *name)
{
	struct opal_prd_range *range;
	void *buf;

	range = find_range(name);
	if (!range) {
		warn("can't find code region %s\n", name);
		return -1;
	}

	buf = mmap(NULL, range->size, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE, ctx->fd, range->physaddr);
	if (buf == MAP_FAILED) {
		warn("mmap(range:%s)\n", name);
		return -1;
	}

	ctx->code_addr = buf;
	ctx->code_size = range->size;
	return 0;
}

static void dump_hbrt_map(struct opal_prd_ctx *ctx)
{
	const char *dump_name = "hbrt.bin";
	int fd, rc;

	if (!ctx->debug)
		return;

	fd = open(dump_name, O_WRONLY | O_CREAT, 0644);
	if (fd < 0)
		err(EXIT_FAILURE, "couldn't open %s for writing", dump_name);

	ftruncate(fd, 0);
	rc = write(fd, ctx->code_addr, ctx->code_size);
	close(fd);

	if (rc != ctx->code_size)
		warn("write to %s failed", dump_name);
	else
		printf("dumped HBRT binary to %s\n", dump_name);
}

static int prd_init(struct opal_prd_ctx *ctx)
{
	int rc;

	ctx->page_size = sysconf(_SC_PAGE_SIZE);

	/* set up the device, and do our get_info ioctl */
	ctx->fd = open(opal_prd_devnode, O_RDWR);
	if (ctx->fd < 0) {
		warn("Can't open PRD device %s\n", opal_prd_devnode);
		return -1;
	}

	rc = ioctl(ctx->fd, OPAL_PRD_GET_INFO, &ctx->info);
	if (rc) {
		warn("Can't get PRD info");
		return -1;
	}

	return 0;
}

static int handle_msg_attn(struct opal_prd_ctx *ctx, struct opal_prd_msg *msg)
{
	uint64_t proc, ipoll_mask, ipoll_status;
	int rc;

	proc = be64toh(msg->attn.proc);
	ipoll_status = be64toh(msg->attn.ipoll_status);
	ipoll_mask = be64toh(msg->attn.ipoll_mask);

	rc = call_handle_attns(proc, ipoll_status, ipoll_mask);
	if (rc) {
		fprintf(stderr, "enable_attns(%lx,%lx,%lx) failed, rc %d",
				proc, ipoll_status, ipoll_mask, rc);
		return -1;
	}

	/* send the response */
	msg->type = OPAL_PRD_MSG_TYPE_ATTN_ACK;
	msg->attn_ack.proc = htobe64(proc);
	msg->attn_ack.ipoll_ack = htobe64(ipoll_status);
	rc = write(ctx->fd, &msg, sizeof(msg));

	if (rc != sizeof(msg)) {
		warn("write(ATTN_ACK) failed");
		return -1;
	}

	return 0;
}

static int run_attn_loop(struct opal_prd_ctx *ctx)
{
	struct opal_prd_msg msg;
	int rc;

	if (!hservice_runtime->handle_attns) {
		printf("no handle_attns call, aborting\n");
		return -1;
	}

	if (hservice_runtime->enable_attns) {
		pr_debug(ctx, "calling enable_attns()\n");
		rc = call_enable_attns();
		if (rc) {
			fprintf(stderr, "enable_attns() failed, aborting\n");
			return -1;
		}
	}

	/* send init message, to unmask interrupts */
	msg.type = OPAL_PRD_MSG_TYPE_INIT;
	msg.init.version = htobe64(opal_prd_version);
	msg.init.ipoll = htobe64(opal_prd_ipoll);

	pr_debug(ctx, "writing init message\n");
	rc = write(ctx->fd, &msg, sizeof(msg));
	if (rc != sizeof(msg)) {
		warn("init message failed, aborting");
		return -1;
	}

	for (;;) {
		rc = read(ctx->fd, &msg, sizeof(msg));
		if (rc == EAGAIN)
			continue;

		if (rc != sizeof(msg)) {
			warn("read on opal prd device failed");
			return -1;
		}

		switch (msg.type) {
		case OPAL_PRD_MSG_TYPE_ATTN:
			rc = handle_msg_attn(ctx, &msg);
		default:
			warn("Invalid incoming message type 0x%x\n", msg.type);
			return -1;
		}

	}

	return 0;
}


int main(int argc, char *argv[])
{
	char *hbrt_filename = NULL;
	struct opal_prd_ctx _ctx;
	uint64_t val;
	int rc;

	ctx = &_ctx;
	memset(ctx, 0, sizeof(*ctx));

	/* Parse options */
	while(1) {
		static struct option opal_diag_options[] = {
			{"file", required_argument, NULL, 'f'},
			{"debug", no_argument, NULL, 'd'},
			{"help", no_argument, NULL, 'h'},
		};
		int c, idx=1;
		c = getopt_long(argc, argv, "h", opal_diag_options, &idx);
		if (c == EOF)
			break;
		switch (c) {
		case 'f':
			hbrt_filename = optarg;
			printf("Using hostboot file: %s\n", hbrt_filename);
			break;
		case 'd':
			ctx->debug = true;
			break;
		case 'h':
			printf("Usage: %s [--file <hbrt-image>] \n", argv[0]);
			printf("By default use image from memory\n");
			return EXIT_SUCCESS;
		}
	}

	rc = prd_init(ctx);
	if (rc)
		err(EXIT_FAILURE, "Error initialising PRD setup");


	if (hbrt_filename) {
		rc = map_hbrt_file(ctx, hbrt_filename);
		if (rc)
			err(EXIT_FAILURE, "can't access hbrt file %s",
					hbrt_filename);
	} else {
		rc = map_hbrt_physmem(ctx, hbrt_code_region_name);
		if (rc)
			err(EXIT_FAILURE, "can't access hbrt physical memory");
		dump_hbrt_map(ctx);
	}

	pr_debug(ctx, "hbrt map at %p, size 0x%zx\n",
			ctx->code_addr, ctx->code_size);

	fixup_hinterface_table();

	pr_debug(ctx, "calling hservices_init\n");
	hservices_init(ctx->code_addr);
	pr_debug(ctx, "hservices_init done\n");

	/* Test a scom */
	if (ctx->debug) {
		printf("trying scom read\n");
		fflush(stdout);
		hservice_scom_read(0x00, 0xf000f, &val);
		printf("f00f: %lx\n", val);
	}

	run_attn_loop(ctx);

	close(ctx->fd);

	return(0);
}

