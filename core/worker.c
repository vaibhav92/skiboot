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
#include <worker.h>

extern void __worker_swap(struct stack_frame **old, struct stack_frame *new);
extern void work_done(void) __noreturn;

static void suspend_current_work(void)
{
	struct cpu_thread *c = this_cpu();
	struct worker *w = c->cur_worker;

	if (!c)
		return;

	c->cur_worker = NULL;
	__worker_swap(&w->frame, w->back_frame);
}

void work_done(void)
{
	struct cpu_thread *c = this_cpu();
	struct worker *w = c->cur_worker;

	assert(w);
	assert(w->state == worker_running);

	prlog(PR_DEBUG, "WORK: %p done\n", w);

	w->state = worker_off;
	suspend_current_work();

	/* Should never happen */
	abort();
}

void work_delay(struct worker *w, uint64_t target)
{
	assert(w->state == worker_running);
	assert(this_cpu()->lock_depth == 0);

	w->state = worker_delaying;
	w->time_target = target;
	suspend_current_work();
}

static void resume_work(struct worker *w)
{
	struct cpu_thread *c = this_cpu();

	assert(c->cur_worker == NULL);
	c->cur_worker = w;

	/* Time limited worker, calculate new target */
	if (w->time_limit)
		w->time_target = mftb() + w->time_limit;

	w->state = worker_running;
	__worker_swap(&w->back_frame, w->frame);

	/* Worker has suspended, it is either finished 
	 * or needs a delayed wakeup
	 */
	assert(w->state == worker_delaying ||
	       w->state == worker_off);

	/* We schedule the wakeup here, not from the worker
	 * iself to avoid a race where the timer callback
	 * could occur too early
	 */
	if (w->state == worker_delaying) {
		w->state = worker_waiting;
		schedule_timer(&w->timer, w->time_target);
	}
}

void start_work(struct worker *w)
{
	struct cpu_thread *c = this_cpu();

	assert(w->state == worker_off);

	/* If we are in a worker, we can't just switch, our infrastructure
	 * can't just ping pong between them like that, we have to suspend
	 * first to one of our "main" threads, then resume the new one,
	 * so instead let's just schedule a short timer
	 */
	if (c->cur_worker) {
		w->state = worker_waiting;
		schedule_timer(&w->timer, 1);
	} else
		resume_work(w);
}

static void work_timer_func(struct timer *t __unused, void *data)
{
	struct worker *w = data;

	assert(w->state == worker_waiting);
	resume_work(w);
}

struct worker *new_worker(worker_entry_t entry, void *arg)
{
	struct worker *w = zalloc(sizeof(struct worker));

	if (!w)
		return NULL;
	w->stack = memalign(STACK_SIZE, STACK_SIZE);
	if (!w->stack) {
		free(w);
		return NULL;
	}
	memset(w->stack, 0, STACK_SIZE);
	w->frame = w->stack + STACK_SIZE - sizeof(STACK_SIZE) - 0x100;
	w->frame->pc = (uint64_t)entry;
	w->frame->gpr[3] = (uint64_t)arg;
	w->state = worker_off;

	init_timer(&w->timer, work_timer_func, w);

	return w;
}

void work_set_time_limit(struct worker *w, uint64_t limit, uint64_t gap)
{
	w->time_limit = limit;
	w->time_gap = gap;
	if (w == this_cpu()->cur_worker)
		w->time_target = mftb() + limit;
}
