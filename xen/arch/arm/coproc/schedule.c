/*
 * xen/arch/arm/coproc/schedule.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "coproc.h"

/* for now */
static s_time_t coproc_wait_time = MILLISECS(1);

static char __initdata opt_vcoproc_sched[10] = "rrobin";
string_param("vcoproc_sched", opt_vcoproc_sched);

extern struct vcoproc_scheduler vcoproc_sched_rrobin_def;

static struct vcoproc_scheduler *const vcoproc_schedulers[] = {
	&vcoproc_sched_rrobin_def,
	NULL
};

#define VCOPROC_SCHED_OP(opsptr, fn, ...)                                          \
         (( (opsptr)->fn != NULL ) ? (opsptr)->fn(opsptr, ##__VA_ARGS__ )  \
          : (typeof((opsptr)->fn(opsptr, ##__VA_ARGS__)))0 )

void vcoproc_scheduler_set_current(const struct vcoproc_scheduler *sched, struct vcoproc_info *vcoproc)
{
	struct vcoproc_schedule_data *sd = sched->sd;

	sd->curr = vcoproc;
}

struct vcoproc_info *vcoproc_scheduler_get_current(const struct vcoproc_scheduler *sched)
{
	struct vcoproc_schedule_data *sd = sched->sd;

	return sd->curr;
}

int vcoproc_scheduler_vcoproc_init(struct vcoproc_scheduler *sched,
		struct vcoproc_info *vcoproc)
{
	vcoproc->is_running = 0;

	/* Fixme - last param NULL */
	vcoproc->sched_priv = VCOPROC_SCHED_OP(sched, alloc_vdata, vcoproc, NULL);
	if ( !vcoproc->sched_priv )
	{
		printk("Could not allocate scheduler-specific data for a vcoproc\n");
		return -ENOMEM;
	}

	VCOPROC_SCHED_OP(sched, insert_vcoproc, vcoproc);

	vcoproc_schedule(sched);

	return 0;
}

void vcoproc_scheduler_vcoproc_destroy(struct vcoproc_scheduler *sched,
		struct vcoproc_info *vcoproc)
{
	VCOPROC_SCHED_OP(sched, remove_vcoproc, vcoproc);
	VCOPROC_SCHED_OP(sched, free_vdata, vcoproc->sched_priv);
	vcoproc->sched_priv = NULL;

	vcoproc_schedule(sched);
}

void vcoproc_sheduler_context_saved(struct vcoproc_scheduler *sched, struct vcoproc_info *prev)
{
	VCOPROC_SCHED_OP(sched, context_saved, prev);
}

void vcoproc_sheduler_vcoproc_wake(struct vcoproc_scheduler *sched, struct vcoproc_info *vcoproc)
{
	VCOPROC_SCHED_OP(sched, wake, vcoproc);

	vcoproc_schedule(sched);
}

void vcoproc_sheduler_vcoproc_sleep(struct vcoproc_scheduler *sched, struct vcoproc_info *vcoproc)
{
	VCOPROC_SCHED_OP(sched, sleep, vcoproc);

	vcoproc_schedule(sched);
}

void vcoproc_sheduler_vcoproc_yield(struct vcoproc_scheduler *sched, struct vcoproc_info *vcoproc)
{
	VCOPROC_SCHED_OP(sched, yield, vcoproc);
}

/* TODO change prev and next states */
void vcoproc_schedule(struct vcoproc_scheduler *sched)
{
	struct vcoproc_info *prev = vcoproc_scheduler_get_current(sched);
	struct vcoproc_info *next = NULL;
	struct vcoproc_schedule_data *sd = sched->sd;
	struct vcoproc_task_slice next_slice;
	s_time_t now = NOW();

	stop_timer(&sd->s_timer);

	next_slice = sched->do_schedule(sched, now);
	next = next_slice.task;

	if ( unlikely(!prev && !next) )
		return;

	if ( vcoproc_context_switch(prev, next) )
	{
		if ( coproc_wait_time >= 0 )
			set_timer(&sd->s_timer, now + coproc_wait_time);

		vcoproc_sheduler_context_saved(sched, next);

		return vcoproc_continue_running(prev);
	}

	vcoproc_scheduler_set_current(sched, next);

	if ( next_slice.time >= 0 )
		set_timer(&sd->s_timer, now + next_slice.time);

	if ( prev == next )
		return vcoproc_continue_running(prev);

	vcoproc_sheduler_context_saved(sched, prev);
}

static void s_timer_fn(void *data)
{
	struct vcoproc_scheduler *sched = data;

	vcoproc_schedule(sched);
}

struct vcoproc_scheduler * __init vcoproc_scheduler_init(struct coproc_device *coproc)
{
	struct vcoproc_scheduler *sched;
	struct vcoproc_schedule_data *sd;
	int i;

	for ( i = 0; vcoproc_schedulers[i]; i++ )
	{
		if ( !strcmp(vcoproc_schedulers[i]->opt_name, opt_vcoproc_sched) )
			break;
	}

	if ( !vcoproc_schedulers[i] )
	{
		printk("Could not find vcoproc scheduler: %s\n", opt_vcoproc_sched);
		return NULL;
	}

	printk("Using vcoproc scheduler: %s\n", vcoproc_schedulers[i]->opt_name);

	sched = xmalloc(struct vcoproc_scheduler);
	if ( !sched )
	{
		printk("Could not allocate vcoproc scheduler\n");
		return NULL;
	}
	memcpy(sched, vcoproc_schedulers[i], sizeof(*sched));

	sd = xmalloc(struct vcoproc_schedule_data);
	if ( !sd )
	{
		printk("Could not allocate vcoproc schedule data\n");
		xfree(sched);
		return NULL;
	}
	sched->sd = sd;
	init_timer(&sd->s_timer, s_timer_fn, sched, 0);
	vcoproc_scheduler_set_current(sched, NULL);

	if ( VCOPROC_SCHED_OP(sched, init) )
	{
		printk("Could not init vcoproc scheduler\n");
		xfree(sched);
		sched = NULL;
	}

	return sched;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
