/* Copyright 2014-2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * imitations under the License.
 */

#include <skiboot.h>
#include <opal.h>
#include <lock.h>
#include <xscom.h>
#include <chip.h>
#include <opal-api.h>
#include <opal-msg.h>
#include <fsp.h>

static enum {
	OPAL_PRD_INACTIVE,
	OPAL_PRD_ACTIVE,
} state = OPAL_PRD_INACTIVE;

static struct lock ipoll_lock = LOCK_UNLOCKED;

/* PRD registers */
#define PRD_IPOLL_REG_MASK	0x01020013
#define PRD_IPOLL_REG_STATUS	0x01020014
#define PRD_IPOLL_XSTOP		PPC_BIT(0) /* Xstop for host/core/millicode */
#define PRD_IPOLL_RECOV		PPC_BIT(1) /* Recoverable */
#define PRD_IPOLL_SPEC_ATTN	PPC_BIT(2) /* Special attention */
#define PRD_IPOLL_HOST_ATTN	PPC_BIT(3) /* Host attention */
#define PRD_IPOLL_MASK		PPC_BITMASK(0, 3)

static int queue_prd_msg_hbrt(struct opal_prd_msg *msg)
{
	uint64_t *buf;

	BUILD_ASSERT(sizeof(*msg) / sizeof(uint64_t) == 4);

	buf = (uint64_t *)msg;

	return _opal_queue_msg(OPAL_MSG_PRD, NULL, NULL, 4, buf);
}

static int queue_prd_msg_nop(struct opal_prd_msg *msg)
{
	(void)msg;
	return OPAL_UNSUPPORTED;
}

static int (*queue_prd_msg)(struct opal_prd_msg *msg) = queue_prd_msg_nop;

static int __ipoll_update_mask(uint64_t proc, bool set, uint64_t bits,
		uint64_t *newmask)
{
	uint64_t mask;
	int rc;

	rc = xscom_read(proc, PRD_IPOLL_REG_MASK, &mask);
	if (rc)
		return rc;

	if (set)
		mask |= bits & PRD_IPOLL_MASK;
	else
		mask &= ~(bits) & PRD_IPOLL_MASK;

	if (newmask)
		*newmask = mask;

	return xscom_write(proc, PRD_IPOLL_REG_MASK, mask);
}

static int ipoll_update_mask(uint64_t proc, bool set, uint64_t bits,
		uint64_t *newmask)
{
	int rc;

	lock(&ipoll_lock);
	rc = __ipoll_update_mask(proc, set, bits, newmask);
	unlock(&ipoll_lock);

	return rc;
}

/* Entry point for prd-related interrupts */
void prd_interrupt(uint32_t proc)
{
	uint64_t ipoll_status, ipoll_mask;
	struct opal_prd_msg msg;
	int rc;

	/* we shouldn't see any interrupts while we're not active,
	 * so just ensure we have everything masked */
	if (state != OPAL_PRD_ACTIVE) {
		ipoll_update_mask(proc, true, PRD_IPOLL_MASK, NULL);
		prlog(PR_ERR, "PRD: IRQ received, but no handlers active\n");
		return;
	}

	lock(&ipoll_lock);

	rc = xscom_read(proc, PRD_IPOLL_REG_STATUS, &ipoll_status);
	if (rc) {
		prlog(PR_ERR, "PRD: Unable to read ipoll irq status!\n");
		unlock(&ipoll_lock);
		return;
	}
	ipoll_status &= PRD_IPOLL_MASK;
	rc = __ipoll_update_mask(proc, true, ipoll_status, &ipoll_mask);

	unlock(&ipoll_lock);
	if (!rc) {
		prlog(PR_ERR, "PRD: Unable to mask ipoll interrupt\n");
		return;
	}

	msg.type = OPAL_PRD_MSG_TYPE_ATTN;
	msg.token = 0;
	msg.attn.proc = proc;
	msg.attn.ipoll_status = ipoll_status;
	msg.attn.ipoll_mask = ipoll_mask;

	queue_prd_msg(&msg);

	return;
}

/* incoming message handlers */
static int prd_msg_handle_attn_ack(struct opal_prd_msg *msg)
{
	int rc;

	rc = ipoll_update_mask(msg->attn_ack.proc, false,
			msg->attn_ack.ipoll_ack, NULL);
	if (rc)
		prlog(PR_ERR, "PRD: Unable to unmask ipoll!\n");

	return rc;
}

static int prd_msg_handle_init(struct opal_prd_msg *msg)
{
	struct proc_chip *chip;

	if (state == OPAL_PRD_ACTIVE)
		return OPAL_BUSY;

	state = OPAL_PRD_ACTIVE;

	lock(&ipoll_lock);
	for_each_chip(chip) {
		__ipoll_update_mask(chip->id, false, msg->init.ipoll, NULL);
	}
	unlock(&ipoll_lock);

	return OPAL_SUCCESS;
}

static int prd_msg_handle_fini(void)
{
	struct proc_chip *chip;

	if (state != OPAL_PRD_ACTIVE)
		return OPAL_SUCCESS;

	lock(&ipoll_lock);
	for_each_chip(chip) {
		__ipoll_update_mask(chip->id, true, PRD_IPOLL_MASK, NULL);
	}
	unlock(&ipoll_lock);

	state = OPAL_PRD_INACTIVE;

	return OPAL_SUCCESS;
}

/* Entry from the host above */
static int64_t opal_prd_msg(struct opal_prd_msg *msg)
{
	int rc;

	switch (msg->type) {
	case OPAL_PRD_MSG_TYPE_INIT:
		rc = prd_msg_handle_init(msg);
		break;
	case OPAL_PRD_MSG_TYPE_FINI:
		rc = prd_msg_handle_fini();
		break;
	case OPAL_PRD_MSG_TYPE_ATTN_ACK:
		rc = prd_msg_handle_attn_ack(msg);
		break;
	default:
		rc = OPAL_UNSUPPORTED;
	}

	return rc;
}

void prd_init(void)
{
	struct proc_chip *chip;

	/* mask everything */
	lock(&ipoll_lock);
	for_each_chip(chip) {
		__ipoll_update_mask(chip->id, true, PRD_IPOLL_MASK, NULL);
	}
	unlock(&ipoll_lock);

	if (fsp_present()) {
		/* todo: FSP implementation */
		queue_prd_msg = queue_prd_msg_nop;
	} else {
		queue_prd_msg = queue_prd_msg_hbrt;
		opal_register(OPAL_PRD_MSG, opal_prd_msg, 1);
	}
}
