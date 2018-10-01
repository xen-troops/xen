/*
 * xen/arch/arm/coord_suspend.h
 *
 * Coordinated suspend support
 *
 * Joshua Kuhlmann <joshua.kuhlmann@aggios.com>
 * Copyright (c) 2018 Aggios Inc
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

#ifndef __ARCH_ARM_COORD_SUSPEND_H__
#define __ARCH_ARM_COORD_SUSPEND_H__

int coord_suspend_init(struct domain *d);
void coord_suspend_trigger(struct domain *d);

#endif
