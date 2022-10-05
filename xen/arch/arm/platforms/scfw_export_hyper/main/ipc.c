/*
 * Copyright 2018 NXP
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

/* Includes */
#include <xen/config.h>
#include <xen/err.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/guest_access.h>
#include <xen/device_tree.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/hypercall.h>

#include <asm/sci.h>

#include "rpc.h"

struct scu_mu
{
    void __iomem *base;
    spinlock_t lock;
};

/* Local Defines */
#define MU_SIZE 0x10000

/* Local Types */
sc_ipc_t mu_ipcHandle;

/* Local functions */

/* Local variables */
static uint32_t gIPCport;
static struct scu_mu *scu_mu;
static bool scu_mu_init;

/*--------------------------------------------------------------------------*/
/* RPC command/response                                                     */
/*--------------------------------------------------------------------------*/
void sc_call_rpc(sc_ipc_t handle, sc_rpc_msg_t *msg, sc_bool_t no_resp)
{
	spin_lock(&scu_mu->lock);

	sc_ipc_write(handle, msg);
	if (!no_resp)
		sc_ipc_read(handle, msg);

	spin_unlock(&scu_mu->lock);
}
EXPORT_SYMBOL(sc_call_rpc);

/*--------------------------------------------------------------------------*/
/* Get MU base address for specified IPC channel                            */
/*--------------------------------------------------------------------------*/
static uint32_t *sc_ipc_get_mu_base(uint32_t id)
{
	uint32_t *base;

	/* Check parameters */
	if (id >= SC_NUM_IPC)
		base = NULL;
	else
		base = (uint32_t *) (scu_mu->base + (id * MU_SIZE));

	return base;
}

/*--------------------------------------------------------------------------*/
/* Get the MU ID used by Linux                                              */
/*--------------------------------------------------------------------------*/
int sc_ipc_getMuID(uint32_t *mu_id)
{
	if (scu_mu_init) {
		*mu_id = gIPCport;
		return SC_ERR_NONE;
	}
	return SC_ERR_UNAVAILABLE;
}

EXPORT_SYMBOL(sc_ipc_getMuID);

/*--------------------------------------------------------------------------*/
/* Open an IPC channel                                                      */
/*--------------------------------------------------------------------------*/
sc_err_t sc_ipc_requestInt(sc_ipc_t *handle, uint32_t id)
{
	return SC_ERR_NONE;
}

/*--------------------------------------------------------------------------*/
/* Open an IPC channel                                                      */
/*--------------------------------------------------------------------------*/
sc_err_t sc_ipc_open(sc_ipc_t *handle, uint32_t id)
{
	uint32_t *base;

	spin_lock(&scu_mu->lock);

	if (!scu_mu_init) {
		spin_unlock(&scu_mu->lock);
		return SC_ERR_UNAVAILABLE;
	}
	/* Get MU base associated with IPC channel */
	base = sc_ipc_get_mu_base(id);

	if (base == NULL) {
		spin_unlock(&scu_mu->lock);
		return SC_ERR_IPC;
	}

	spin_unlock(&scu_mu->lock);

	return SC_ERR_NONE;
}
EXPORT_SYMBOL(sc_ipc_open);
/*--------------------------------------------------------------------------*/
/* Close an IPC channel                                                     */
/*--------------------------------------------------------------------------*/
void sc_ipc_close(sc_ipc_t handle)
{
	uint32_t *base;

	spin_lock(&scu_mu->lock);

	if (!scu_mu_init) {
		spin_unlock(&scu_mu->lock);
		return;
	}

	/* Get MU base associated with IPC channel */
	base = sc_ipc_get_mu_base(gIPCport);

	/* TBD ***** What needs to be done here? */
	spin_unlock(&scu_mu->lock);
}
EXPORT_SYMBOL(sc_ipc_close);

/*!
 * This function reads a message from an IPC channel.
 *
 * @param[in]     ipc         id of channel read from
 * @param[out]    data        pointer to message buffer to read
 *
 * This function will block if no message is available to be read.
 */
void sc_ipc_read(sc_ipc_t handle, void *data)
{
	uint32_t *base;
	uint8_t count = 0;
	sc_rpc_msg_t *msg = (sc_rpc_msg_t *) data;

	/* Get MU base associated with IPC channel */
	base = sc_ipc_get_mu_base(gIPCport);

	if ((base == NULL) || (msg == NULL))
		return;

	/* Read first word */
	MU_ReceiveMsg(base, 0, (uint32_t *) msg);
	count++;

	/* Check size */
	if (msg->size > SC_RPC_MAX_MSG) {
		*((uint32_t *) msg) = 0;
		return;
	}

	/* Read remaining words */
	while (count < msg->size) {
		MU_ReceiveMsg(base, count % MU_RR_COUNT,
				  &(msg->DATA.u32[count - 1]));
		count++;
	}
}

/*!
 * This function writes a message to an IPC channel.
 *
 * @param[in]     ipc         id of channel to write to
 * @param[in]     data        pointer to message buffer to write
 *
 * This function will block if the outgoing buffer is full.
 */
void sc_ipc_write(sc_ipc_t handle, void *data)
{
	uint32_t *base;
	uint8_t count = 0;
	sc_rpc_msg_t *msg = (sc_rpc_msg_t *) data;

	/* Get MU base associated with IPC channel */
	base = sc_ipc_get_mu_base(gIPCport);

	if ((base == NULL) || (msg == NULL))
		return;

	/* Check size */
	if (msg->size > SC_RPC_MAX_MSG)
		return;

	/* Write first word */
	MU_SendMessage(base, 0, *((uint32_t *) msg));
	count++;

	/* Write remaining words */
	while (count < msg->size) {
		MU_SendMessage(base, count % MU_TR_COUNT, msg->DATA.u32[count - 1]);
		count++;
	}
}

#if 0
long do_imx8_call(int cmd, XEN_GUEST_HANDLE_PARAM(char) buffer)
{
    long rc;
    unsigned int idx, len;

    switch ( cmd )
    {
    case CONSOLEIO_write:
        rc = guest_console_write(buffer, count);
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}
#endif

int imx8_sc_rpc(XEN_GUEST_HANDLE_PARAM(char) x1, unsigned long x2)
{
    sc_bool_t no_resp = (sc_bool_t)x2;
    sc_rpc_msg_t xen_msg;

    if ( copy_from_guest((char *)&xen_msg, x1, sizeof(sc_rpc_msg_t)) )
    {
        printk("Copy msg from Guest to XEN error\n");
	return -EFAULT;
    }

    sc_call_rpc(mu_ipcHandle, &xen_msg, no_resp);
    if (!no_resp)
    {
        if ( copy_to_guest(x1, (char *)&xen_msg, sizeof(sc_rpc_msg_t)) )
        {
            printk("Copy msg from Guest to XEN error\n");
            return -EFAULT;
        }
	    /* Copy msg back to VM */
    }

    return 0;
}

/*Initialization of the MU code. */
int __init imx8_mu_init(void)
{
	struct dt_device_node *np;
	struct dt_device_node *np_tmp;
	struct dt_device_node *available_mus[5];
	unsigned int num_parsed_mus = 0;
	unsigned int num_available_mus = 0;
	unsigned int scu_mu_id = 0;
	u64 size, addr;
	int err;
	sc_err_t sciErr;
	sc_rm_pt_t pt;

	np = dt_find_compatible_node(NULL, NULL, "fsl,imx8qm-mu");
	if (!np)
	{
            /* Kernel version lower than 5.4 use legacy compatible */
	    np = dt_find_compatible_node(NULL, NULL, "fsl,imx8-mu");
	    if (!np) {
	        printk("No MU entry\n");
	        return -ENOENT;
	    }
	} else {
		dt_for_each_compatible_node(NULL, np_tmp, NULL, "fsl,imx8qm-mu") {
			/*
			 * The node marked "xen,no-map" will be used by xen, and
			 * mmio trapped for Dom0. Other nodes that are enabled
			 * and not marked for passthrough will be analyzed later.
			 */
			if (dt_get_property(np_tmp, "xen,no-map", NULL)) {
				np = np_tmp;
			} else if (dt_device_is_available(np_tmp) &&
				   !dt_device_for_passthrough(np_tmp)) {

					available_mus[num_available_mus++] = np_tmp;
			}

			/* No reason to continue if all MUs have already been parsed */
			num_parsed_mus++;
			if (num_parsed_mus >= ARRAY_SIZE(available_mus))
			{
				break;
			}
		}
	}

	err = dt_device_get_address(np, 0, &addr, &size);
	if (err)
	    return -EINVAL;

	scu_mu = xzalloc(struct scu_mu);
	if (!scu_mu)
	    return -ENOMEM;

	scu_mu->base = ioremap_nocache(addr, size);
	if (!scu_mu->base)
	{
	    printk("Unable to map MU\n");
	    xfree(scu_mu);
	    return -ENOMEM;
	}

	if (!dt_property_read_u32(np, "fsl,scu_ap_mu_id", &scu_mu_id)) {
		printk("No fsl,scu_ap_mu_id\n");
		scu_mu_id = 0;
	}

	spin_lock_init(&scu_mu->lock);

	if (!scu_mu_init) {
		uint32_t i;

		/* Init MU */
		MU_Init(scu_mu->base);

		/* Enable all RX interrupts */
		for (i = 0; i < MU_RR_COUNT; i++)
			MU_EnableGeneralInt(scu_mu->base, i);

		gIPCport = scu_mu_id;
		scu_mu_init = true;
	}

	sciErr = sc_ipc_open(&mu_ipcHandle, scu_mu_id);
	if (sciErr != SC_ERR_NONE) {
		printk("Cannot open MU channel to SCU\n");
		return sciErr;
	}

	/* Other MUs might need to be powered ON on init (e.g. for Dom0 usage) */
	sc_rm_get_partition(mu_ipcHandle, &pt);
	for (; num_available_mus > 0; num_available_mus--) {
		u32 resource_id;

		np = available_mus[num_available_mus - 1];

		err = dt_property_read_u32_array(np, "fsl,sc_init_on_rsrc_id",
						 &resource_id, 1);
		if (!err) {
			sc_pm_set_resource_power_mode(-1, resource_id,
						      SC_PM_PW_MODE_ON);
			sc_rm_assign_resource(-1, pt, resource_id);
		} else if (err == -EINVAL) {
			printk(XENLOG_DEBUG "No resource ID for MU at %s\n",
			       np->full_name);
		} else {
			printk(XENLOG_ERR "Failed to get resource ID for MU at %s\n",
			       np->full_name);
		}
	}

	printk("*****Initialized MU\n");
	return 0;
}
