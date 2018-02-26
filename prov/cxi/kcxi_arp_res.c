//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider ARP resolution.
 * Copyright 2019-2021 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <net/neighbour.h>
#include <net/arp.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/timer.h>
#include <linux/version.h>

#include "kcxi_prov.h"

unsigned int res_timeout = 5;
module_param(res_timeout, uint, 0444);
MODULE_PARM_DESC(res_timeout, "Address resolution timeout in seconds");

/* kCXI resolution variables. */
static LIST_HEAD(res_list);
static DEFINE_SPINLOCK(res_lock);
static atomic_t res_count = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(res_queue);

/* kCXI ARP resolution entry. */
struct kcxi_arp_res_entry_priv {
	struct list_head list_entry;
	__be32 src_addr;
	__be32 dest_addr;
	struct net_device *net_dev;
	struct neighbour *neigh;
	bool resolved;
	struct kcxi_arp_res_entry res_entry;

	/* Async variables. */
	struct work_struct work;
	kcxi_arp_res_entry_cb cb;
	int rc;
	struct timer_list timeout_timer;
};

static bool valid_cxi_arp_entry(const struct neighbour *n)
{
	u64 mac_addr;

	if (!n)
		return false;

	mac_addr = ether_addr_to_u64(n->ha);

	return ((n->nud_state & NUD_REACHABLE) && !n->dead &&
		is_locally_admin_mac_addr(mac_addr));
}

static void dump_arp_entry(const struct neighbour *n)
{
	LOG_DEBUG("\tMAC address %pM", n->ha);
	LOG_DEBUG("\tDead %u", n->dead);
	if (n->nud_state & NUD_NONE)
		LOG_DEBUG("\tNUD State: none");
	if (n->nud_state & NUD_INCOMPLETE)
		LOG_DEBUG("\tNUD State: incomplete");
	if (n->nud_state & NUD_REACHABLE)
		LOG_DEBUG("\tNUD State: reachable");
	if (n->nud_state & NUD_STALE)
		LOG_DEBUG("\tNUD State: stale");
	if (n->nud_state & NUD_DELAY)
		LOG_DEBUG("\tNUD State: delay");
	if (n->nud_state & NUD_PROBE)
		LOG_DEBUG("\tNUD State: probe");
	if (n->nud_state & NUD_FAILED)
		LOG_DEBUG("\tNUD State: failed");
	LOG_DEBUG("\tRefcnt %d", ATOMIC_READ(&n->refcnt));
}

/**
 * kcxi_arp_res_entry_free() - Free a resolution entry.
 */
void kcxi_arp_res_entry_free(struct kcxi_arp_res_entry *entry)
{
	struct kcxi_arp_res_entry_priv *entry_priv;

	if (!entry)
		return;

	entry_priv = container_of(entry, struct kcxi_arp_res_entry_priv,
				  res_entry);

	spin_lock(&res_lock);
	if (!entry_priv->resolved) {
		list_del(&entry_priv->list_entry);
		atomic_dec(&res_count);
	}
	spin_unlock(&res_lock);

	del_timer(&entry_priv->timeout_timer);

	neigh_release(entry_priv->neigh);

	dev_put(entry_priv->net_dev);

	kfree(entry_priv);

	LOG_DEBUG("Active resolution count: %u", atomic_read(&res_count));
}

/**
 * kcxi_arp_res_entry_async_wq() - Deferred work queue function used to run
 * users callback.
 * @work: Work struct.
 *
 * If a callback is associated with the ARP resolution entry, resolution is
 * asynchronous and the user's callback will be triggered in the future. The
 * callback is triggered if resolution is successful or a timeout occurs.
 */
static void kcxi_arp_res_entry_async_wq(struct work_struct *work)
{
	struct kcxi_arp_res_entry_priv *entry_priv;

	entry_priv = container_of(work, struct kcxi_arp_res_entry_priv, work);

	dump_arp_entry(entry_priv->neigh);

	entry_priv->cb(&entry_priv->res_entry, entry_priv->rc);
}

/**
 * kcxi_arp_res_entry_alloc() - Allocate a new resolution entry.
 * @src_addr: Source IPv4 address used to identify the local net device.
 * @dest_addr: Destination IPv4 address to be resolved.
 * @cb: Optional callback. If callback is NULL, resolution is synchronous.
 * @context: User context.
 *
 * Return: On success, non-null pointer. On error, negative errno pointer.
 */
struct kcxi_arp_res_entry *kcxi_arp_res_entry_alloc(__be32 src_addr,
						    __be32 dest_addr,
						    kcxi_arp_res_entry_cb cb,
						    void *context)
{
	struct kcxi_arp_res_entry_priv *entry_priv;
	int rc;

	entry_priv = kzalloc(sizeof(*entry_priv), GFP_KERNEL);
	if (!entry_priv) {
		rc = -ENOMEM;
		goto error;
	}

	entry_priv->src_addr = src_addr;
	entry_priv->dest_addr = dest_addr;
	entry_priv->cb = cb;
	entry_priv->res_entry.context = context;

	INIT_WORK(&entry_priv->work, kcxi_arp_res_entry_async_wq);

	/* Lookup the source address net device and take a reference. */
	entry_priv->net_dev = ip_dev_find(&init_net, src_addr);
	if (!entry_priv->net_dev) {
		LOG_ERR("Failed to find net device for src IPv4 address (%pI4)",
			&src_addr);

		rc = -ENODEV;
		goto error_free_entry;
	}

	/* Lookup/create a new ARP cache entry and take a reference. */
	entry_priv->neigh = neigh_lookup(&arp_tbl, &entry_priv->dest_addr,
					 entry_priv->net_dev);
	if (!entry_priv->neigh) {
		entry_priv->neigh = neigh_create(&arp_tbl,
						 &entry_priv->dest_addr,
						 entry_priv->net_dev);
		if (IS_ERR(entry_priv->neigh)) {
			LOG_ERR("Failed to create ARP entry for dest IPv4 address (%pI4)",
				&entry_priv->dest_addr);

			rc = PTR_ERR(entry_priv->neigh);
			goto error_release_net_dev;
		}
	}

	spin_lock(&res_lock);
	list_add_tail(&entry_priv->list_entry, &res_list);
	atomic_inc(&res_count);
	spin_unlock(&res_lock);

	LOG_DEBUG("Active resolution count: %u", atomic_read(&res_count));

	return &entry_priv->res_entry;

error_release_net_dev:
	dev_put(entry_priv->net_dev);
error_free_entry:
	kfree(entry_priv);
error:
	return ERR_PTR(rc);
}

/**
 * kcxi_arp_res_entry_timeout() - Callback associated with the resolution entry
 * timeout timer.
 * @data: Destination IPv4 address.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
static void kcxi_arp_res_entry_timeout(struct timer_list *t)
#else
static void kcxi_arp_res_entry_timeout(unsigned long data)
#endif
{
	__be32 dest_addr;
	struct kcxi_arp_res_entry_priv *p;
	bool found = false;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	struct kcxi_arp_res_entry_priv *entry_priv;

	entry_priv = from_timer(entry_priv, t, timeout_timer);
	dest_addr = entry_priv->dest_addr;
#else
	dest_addr = (__be32)data;
#endif
	/* Since we could be racing against the netfilter hook, search the
	 * resolution list by destination IPv4 address instead of passing the
	 * resolution entry via the data argument. Either this function or the
	 * netfilter hook will process the resolution entry.
	 */
	spin_lock(&res_lock);
	list_for_each_entry(p, &res_list, list_entry) {
		if (p->dest_addr == dest_addr) {
			p->resolved = true;
			p->rc = -ETIMEDOUT;
			list_del(&p->list_entry);
			atomic_dec(&res_count);
			found = true;
			break;
		}
	}
	spin_unlock(&res_lock);

	if (found) {
		del_timer(&p->timeout_timer);

		queue_work(kcxi_wq, &p->work);
	}
}

/**
 * kcxi_arp_res_entry_resolved() - Condition checking if resolution is complete.
 *
 * Return: True is resolution is successful. Otherwise false.
 */
static bool kcxi_arp_res_entry_resolved(struct kcxi_arp_res_entry *entry)
{
	struct kcxi_arp_res_entry_priv *entry_priv;

	if (!entry)
		return false;

	entry_priv = container_of(entry, struct kcxi_arp_res_entry_priv,
				  res_entry);

	return entry_priv->resolved &&
		is_locally_admin_mac_addr(entry->dest_mac_addr);
}

/**
 * kcxi_arp_res_entry_resolve() - Perform resolution.
 * @entry: ARP resolution entry to be resolved.
 *
 * This function uses ARP to perform kCXI resolution.
 *
 * If the resolution entry was configure to be synchronous, this function will
 * block until the entry is resolved or a timeout occurs. If the entry is
 * resolved, the dest_mac_addr field in the resolution entry will be valid.
 *
 * If the resolution entry was configured to be asynchronous, this function will
 * exit once the ARP request is successfully sent. The result of the resolution
 * is returned to the user via the return code argument passed into the user's
 * callback. If the return code is zero, the dest_mac_addr field in the resolution
 * entry will be valid.
 *
 * Return: If synchronous, on successful resolution, zero is return. Else,
 * negative errno value. If asynchronous, if the ARP request is successfully
 * sent, zero is return. Else, negative errno value.
 */
int kcxi_arp_res_entry_resolve(struct kcxi_arp_res_entry *entry)
{
	struct kcxi_arp_res_entry_priv *entry_priv;
	unsigned long timeout;
	int rc;
	u64 mac_addr;
	bool resolved = false;

	if (!entry)
		return -EINVAL;

	entry_priv = container_of(entry, struct kcxi_arp_res_entry_priv,
				  res_entry);

	if (entry_priv->resolved)
		return 0;

	timeout = res_timeout * HZ;

	dump_arp_entry(entry_priv->neigh);

	/* Check ARP cache for valid CXI MAC before issuing an ARP request. */
	if (!valid_cxi_arp_entry(entry_priv->neigh)) {

		LOG_DEBUG("Issuing ARP request for dest IPv4 address (%pI4)",
			  &entry_priv->dest_addr);

		/* Set the timer now if using a async callback. */
		if (entry_priv->cb) {
			LOG_DEBUG("Register timeout timer for dest IPv4 address (%pI4)",
				  &entry_priv->dest_addr);

			entry_priv->timeout_timer.expires = jiffies + timeout;
			entry_priv->timeout_timer.function =
				kcxi_arp_res_entry_timeout;

			KF_TIMER_SETUP(entry_priv->timeout_timer,
				       entry_priv->dest_addr);

			add_timer(&entry_priv->timeout_timer);
		}

		arp_send(ARPOP_REQUEST, ETH_P_ARP, entry_priv->dest_addr,
			 entry_priv->net_dev, entry_priv->src_addr, NULL, NULL,
			 NULL);
	} else {
		/* Mark entry as resolved and remove if from the resolution
		 * list.
		 */
		mac_addr = ether_addr_to_u64(entry_priv->neigh->ha);

		spin_lock(&res_lock);
		entry_priv->res_entry.dest_mac_addr = mac_addr;
		entry_priv->resolved = true;
		list_del(&entry_priv->list_entry);
		atomic_dec(&res_count);
		spin_unlock(&res_lock);

		/* If a callback is register, queue the callback now. */
		if (entry_priv->cb)
			queue_work(kcxi_wq, &entry_priv->work);

		resolved = true;
	}

	/* Block for resolution if not resolved and a callback is not
	 * registered.
	 */
	if (!resolved && !entry_priv->cb) {
		rc = wait_event_timeout(res_queue,
					kcxi_arp_res_entry_resolved(entry),
					timeout);

		dump_arp_entry(entry_priv->neigh);

		if (!rc) {
			entry_priv->rc = -ETIMEDOUT;
			LOG_ERR("Timeout waiting for ARP response");

			return -ETIMEDOUT;
		}
	}

	return 0;
}

/* Ethernet ARP packet structure. */
struct arphdr_eth {
	struct arphdr hdr;
	unsigned char ar_sha[ETH_ALEN];
	unsigned char ar_sip[4];
	unsigned char ar_tha[ETH_ALEN];
	unsigned char ar_tip[4];
};

/**
 * kcxi_arp_res_entry_update() - Netfilter hook function to update a resolution
 * entry.
 * @priv: Private netfilter hook data.
 * @skb: Trapped SKB (ARP packet).
 * @state: Netfilter hook state.
 *
 * This netfilter hook is used to trap Ethernet ARP reply packets in order to
 * progress any blocked kCXI NIC address requests. This function will never drop
 * the SKB (always returns NF_ACCEPT).
 *
 * Returns: NF_ACCEPT.
 */
static unsigned int kcxi_arp_res_entry_update(void *priv, struct sk_buff *skb,
					      const struct nf_hook_state *state)
{
	struct kcxi_arp_res_entry_priv *p;
	bool wakeup = false;
	__be32 dest_addr;
	u64 dest_mac_addr;
	struct arphdr_eth *arp;

	/* All requests need to be posted before an update can be triggered.
	 * Thus, can exit now if nothing is posted.
	 */
	if (!atomic_read(&res_count))
		return NF_ACCEPT;

	arp = (struct arphdr_eth *)arp_hdr(skb);

	/* Only process Ethernet, ARP, IP replies. */
	if (arp->hdr.ar_hrd != htons(ARPHRD_ETHER) ||
	    arp->hdr.ar_op != htons(ARPOP_REPLY) ||
	    arp->hdr.ar_pro != htons(ETH_P_IP))
		return NF_ACCEPT;

	memcpy(&dest_addr, arp->ar_sip, 4);
	dest_mac_addr = ether_addr_to_u64(arp->ar_sha);

	LOG_DEBUG("Process ARP reply from dest IPv4 address (%pI4)", &dest_addr);

	spin_lock(&res_lock);
	list_for_each_entry(p, &res_list, list_entry) {
		if (p->dest_addr == dest_addr) {
			p->res_entry.dest_mac_addr = dest_mac_addr;
			p->resolved = true;
			list_del(&p->list_entry);
			atomic_dec(&res_count);
			wakeup = true;
			break;
		}
	}
	spin_unlock(&res_lock);

	if (wakeup) {
		if (p->cb) {
			del_timer(&p->timeout_timer);

			queue_work(kcxi_wq, &p->work);
		} else {
			wake_up(&res_queue);
		}
	}

	return NF_ACCEPT;
}

/* Netfilter ARP hook. */
static const struct nf_hook_ops arp_hook = {
	.hook = kcxi_arp_res_entry_update,
	.hooknum = NF_ARP_IN,
	.pf = NFPROTO_ARP,
};

/**
 * kcxi_arp_res_init() - Initialize address resolution.
 *
 * This function installs a netfilter hook to trap ARP packets which allows for
 * asynchronous processing of ARP responses. ARP is required to resolve an IPv4
 * address into a NIC address.
 *
 * Return: On success, zero. On error, negative errno.
 */
int kcxi_arp_res_init(void)
{
	int rc;

	rc = nf_register_net_hook(&init_net, &arp_hook);
	if (rc) {
		LOG_ERR("Failed to register ARP hook: rc=%d", rc);

		return rc;
	}

	return 0;
}

/**
 * kcxi_arp_res_fini() - Finish address resolution.
 *
 * Remove the netfilter ARP hook.
 */
void kcxi_arp_res_fini(void)
{
	nf_unregister_net_hook(&init_net, &arp_hook);
}
