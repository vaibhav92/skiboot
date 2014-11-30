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
#ifndef __WORKER_H
#define __WORKER_H

#include <skiboot.h>
#include <stack.h>
#include <cpu.h>
#include <timer.h>
#include <timebase.h>

typedef void (*worker_entry_t)(void *arg);

enum worker_state {
	worker_off,
	worker_running,
	worker_delaying,
	worker_waiting,
};

struct worker {
	enum worker_state	state;
	struct stack_frame	*frame;
	struct stack_frame	*back_frame;
	void			*stack;
	struct timer		timer;
	uint64_t		time_limit;
	uint64_t		time_gap;
	uint64_t		time_target;
};

extern struct worker *new_worker(worker_entry_t entry, void *arg);
extern void start_work(struct worker *w);

/* Time limited workers will run for up to "limit" ticks,
 * and when expired, will wait for "gap" ticks before
 * resuming. Note that "gap" can be set to TIMER_POLL
 * to request a background poller roundtrip
 */
extern void work_set_time_limit(struct worker *w, uint64_t limit,
				uint64_t gap);

extern void work_delay(struct worker *w, uint64_t target);

static inline void work_may_schedule(void)
{
	struct worker *w = this_cpu()->cur_worker;

	if (w && w->time_limit && this_cpu()->lock_depth == 0 &&
	    tb_compare(mftb(), w->time_target) == TB_AAFTERB)
		work_delay(w, w->time_gap);
}

#endif /* __WORKER_H */
