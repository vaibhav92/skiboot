/* Copyright 2013-2014 IBM Corp.
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

#include <asm-utils.h>
#include <asm-offsets.h>
#include <processor.h>
#include <stack.h>

	.section ".text","ax"
	.balign	0x10

	/* void set_hid0(unsigned long hid0) */
.global set_hid0
set_hid0:
	sync
	mtspr	SPR_HID0,%r3
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	isync
	blr

.global trigger_attn
trigger_attn:
	sync
	isync
	attn
	blr

#ifdef STACK_CHECK_ENABLED
.global _mcount
_mcount:
	mr	%r3,%r1
	mflr	%r4
	b	__mcount_stack_check
#endif

.global mambo_read
mambo_read:
#define SIM_READ_CONSOLE_CODE 60
	li	%r3,SIM_READ_CONSOLE_CODE
	.long	0x000eaeb0
	extsw	%r3,%r3
	blr

.global mambo_write
mambo_write:
#define SIM_WRITE_CONSOLE_CODE 0
	li	%r6,0
	mr	%r5,%r4
	mr	%r4,%r3
	li	%r3,SIM_WRITE_CONSOLE_CODE
	.long	0x000eaeb0
	blr

.global mambo_sim_exit
mambo_sim_exit:
	li	%r3, 31	/* aka. SimExitCode */
	.long	0x000eaeb0
	b	.

.global mambo_get_time
mambo_get_time:
#define SIM_GET_TIME_CODE 70
	li	%r3,SIM_GET_TIME_CODE
	.long	0x000eaeb0
	blr

.global __worker_swap
__worker_swap:
	mflr	%r0
	std	%r0,16(%r1)
	stdu	%r1,-STACK_FRAMESIZE(%r1)

	/* Write back the frame pointer to struct work */
	std	%r1,0(%r3)

	/* Write return address to frame->pc */
	std	%r0,STACK_PC(%r1)

	/* Save a pile of context on the stack */
	SAVE_GPR(2,%r1)
	SAVE_GPR(14,%r1)
	SAVE_GPR(15,%r1)
	SAVE_GPR(16,%r1)
	SAVE_GPR(17,%r1)
	SAVE_GPR(18,%r1)
	SAVE_GPR(19,%r1)
	SAVE_GPR(20,%r1)
	SAVE_GPR(21,%r1)
	SAVE_GPR(22,%r1)
	SAVE_GPR(23,%r1)
	SAVE_GPR(24,%r1)
	SAVE_GPR(25,%r1)
	SAVE_GPR(26,%r1)
	SAVE_GPR(27,%r1)
	SAVE_GPR(28,%r1)
	SAVE_GPR(29,%r1)
	SAVE_GPR(30,%r1)
	SAVE_GPR(31,%r1)
	mfcr	%r3
	mfxer	%r4
	stw	%r3,STACK_CR(%r1)
	stw	%r4,STACK_XER(%r1)

	/* Swap stack pointer */
	mr	%r1,%r4

	/* Restore stuff */
	lwz	%r3,STACK_CR(%r1)
	lwz	%r4,STACK_XER(%r1)
	mtcr	%r3
	mtxer	%r4
	REST_GPR(2,%r1)
	REST_GPR(14,%r1)
	REST_GPR(15,%r1)
	REST_GPR(16,%r1)
	REST_GPR(17,%r1)
	REST_GPR(18,%r1)
	REST_GPR(19,%r1)
	REST_GPR(20,%r1)
	REST_GPR(21,%r1)
	REST_GPR(22,%r1)
	REST_GPR(23,%r1)
	REST_GPR(24,%r1)
	REST_GPR(25,%r1)
	REST_GPR(26,%r1)
	REST_GPR(27,%r1)
	REST_GPR(28,%r1)
	REST_GPR(29,%r1)
	REST_GPR(30,%r1)
	REST_GPR(31,%r1)

	/* Pop target address from frame->pc */
	ld	%r0,STACK_PC(%r1)

	/* Pop r3 which contains args on entry */
	REST_GPR(3,%r1)
	
	/* Pop frame */
	addi	%r1,%r1,STACK_FRAMESIZE

	/* Branch there. We shouldn't return except if the job is complete */
	mtctr	%r0
	bctrl

	/* The job did complete, suspend */
	b	work_done
