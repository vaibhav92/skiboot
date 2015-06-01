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

#include <skiboot.h>
#include <opal.h>
#include <mem_region.h>
#include <device.h>
#include <timebase.h>
#include <timer.h>
#include <time-utils.h>
#include <lock.h>

static uint32_t *fake_ymd;
static uint64_t *fake_hmsm;

/* incase fake rtc clock not configured use these to store and hold rtc value */
static struct timer emulation_timer;

/* timebase when synchronization happened */
static unsigned long tb_synctime;

/* current rtc value */
struct tm tm_offset;

/* protects tm_offset & tb_synctime */
struct lock emulation_lock;

static int64_t fake_rtc_write(uint32_t ymd, uint64_t hmsm)
{
	*fake_ymd = ymd;
	*fake_hmsm = hmsm;

	return OPAL_SUCCESS;
}

static int64_t fake_rtc_read(uint32_t *ymd, uint64_t *hmsm)
{
	if (!ymd || !hmsm)
		return OPAL_PARAMETER;

	*ymd = *fake_ymd;
	*hmsm = *fake_hmsm;

	return OPAL_SUCCESS;
}

static int64_t emulated_rtc_write(uint32_t ymd, uint64_t hmsm)
{
	lock(&emulation_lock);
	datetime_to_tm(ymd, hmsm, &tm_offset);
	tb_synctime = mftb();
	unlock(&emulation_lock);

	return OPAL_SUCCESS;
}

static int64_t emulated_rtc_read(uint32_t *ymd, uint64_t *hmsm)
{
	if (!ymd || !hmsm)
		return OPAL_PARAMETER;

	lock(&emulation_lock);
	tm_to_datetime(&tm_offset, ymd, hmsm);
	unlock(&emulation_lock);

	return OPAL_SUCCESS;
}

/* update the emulated rtc. In case more than 60 seconds have passed
 * since last sync then recompute the tm_offset.
 */
static void __emulated_rtc_update(struct timer *tm __unused,
			       void *data __unused)
{
	time_t sec;

	if (try_lock(&emulation_lock)) {

		sec = tb_to_secs(mftb() - tb_synctime);
		tb_synctime = mftb();

		if ((sec + tm_offset.tm_sec) >= 60) {
			sec += mktime(&tm_offset);
			gmtime_r(&sec, &tm_offset);
		} else {
			tm_offset.tm_sec += sec;
		}

		unlock(&emulation_lock);
	}
	/* reschedule the timer */
	schedule_timer(&emulation_timer, secs_to_tb(1));
}

void fake_rtc_init(void)
{
	struct mem_region *rtc_region = NULL;
	uint32_t *rtc = NULL;
	struct dt_node *np;

	/* Read initial values from reserved memory */
	rtc_region = find_mem_region("ibm,fake-rtc");

	/* Check if we need to provide emulation */
	if (rtc_region) {
		rtc = (uint32_t *) rtc_region->start;

		fake_ymd = rtc;
		fake_hmsm = ((uint64_t *) &rtc[1]);

		opal_register(OPAL_RTC_READ, fake_rtc_read, 2);
		opal_register(OPAL_RTC_WRITE, fake_rtc_write, 2);

		prlog(PR_TRACE, "Init fake RTC to 0x%x 0x%llx\n",
		      *fake_ymd, *fake_hmsm);

	} else {
		const time_t sec = 0;

		/* use a timer to emulate fake rtc */
		gmtime_r(&sec, &tm_offset);
		tb_synctime = mftb();

		init_lock(&emulation_lock);

		init_timer(&emulation_timer, __emulated_rtc_update, NULL);
		schedule_timer(&emulation_timer, secs_to_tb(1));

		opal_register(OPAL_RTC_READ, emulated_rtc_read, 2);
		opal_register(OPAL_RTC_WRITE, emulated_rtc_write, 2);

		prlog(PR_TRACE, "Using emulated mode\n");
	}

	/* add the fake rtc dt node */
	np = dt_new(opal_node, "rtc");
	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");
}
