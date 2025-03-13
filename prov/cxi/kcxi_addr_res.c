//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider address resolution.
 * Copyright 2019-2025 Hewlett Packard Enterprise Development LP
 */
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>

#include "kcxi_prov.h"

#define MAC_ADDR_TO_NIC_ADDR(mac) ((mac) & 0xFFFFF)

/* Default destination PID is zero. */
#define DEFAULT_DEST_PID 0

/* Default source PID can be any PID. */
#define DEFAULT_SRC_PID C_PID_ANY

static bool valid_cxi_mac(const unsigned char *ha)
{
	u64 mac_addr;

	if (!ha)
		return false;

	if (!is_valid_ether_addr(ha))
		return false;

	mac_addr = ether_addr_to_u64(ha);

	return is_locally_admin_mac_addr(mac_addr);
}

static bool valid_ipv4_address(const char *node)
{
	int rc;
	char octets[INET_ADDRSTRLEN];

	if (!node)
		return false;

	rc = sscanf(node, "%hhx.%hhx.%hhx.%hhx", &octets[3], &octets[2],
		    &octets[1], &octets[0]);

	return rc == 4;
}

/**
 * kcxi_addr_res_node_default() - Default node string resolution.
 * @node: Optional node string
 *
 * If the node string is NULL, the NIC address of the first kCXI interface is
 * returned (if any). Else, the node string is treated as a hex value.
 *
 * Return: On success, non-negative NIC address. On error, negative errno value.
 */
static int kcxi_addr_res_node_default(const char *node)
{
	int rc;
	unsigned int nic;

	/* Return the first registered interface if node string is NULL. */
	if (!node)
		return kcxi_dev_first_nic();

	/* Parse node as a local interface index first. */
	rc = sscanf(node, "cxi%u", &nic);
	if (rc == 1)
		return kcxi_dev_index_to_addr(nic);

	/* Parse node as a base 16 (hex) value. */
	rc = kstrtouint(node, 16, &nic);
	if (rc)
		return rc;

	return nic;
}

/**
 * kcxi_src_to_nic_addr() - Convert a source IPv4 address into a NIC address.
 * @src_addr: Source IPv4 address.
 *
 * Return: On success, non-negative NIC address. On error, negative errno value.
 */
static int kcxi_src_to_nic_addr(__be32 src_addr)
{
	struct net_device *net_dev;
	u64 mac_addr;
	int nic_addr;

	rtnl_lock();

	net_dev = ip_dev_find(&init_net, src_addr);
	if (!net_dev)
		goto error_unlock;

	if (!valid_cxi_mac(net_dev->dev_addr))
		goto error_release_net_dev;

	mac_addr = ether_addr_to_u64(net_dev->dev_addr);

	/* Return net device reference. */
	dev_put(net_dev);

	rtnl_unlock();

	nic_addr = MAC_ADDR_TO_NIC_ADDR(mac_addr);

	LOG_DEBUG("Resolved src IPv4 address (%pI4) to NIC address (%#x)",
		  &src_addr, nic_addr);

	return nic_addr;

error_release_net_dev:
	dev_put(net_dev);
error_unlock:
	rtnl_unlock();

	LOG_ERR("Failed to resolve src IPv4 address (%pI4) to NIC address",
		&src_addr);

	return -ENODEV;
}

/**
 * kcxi_addr_res_ipv4_src() - Resolve local IPv4 address into a local NIC
 * address.
 * @ipv4_addr: Local IPv4 address in dot string format.
 *
 * Return: On success, non-negative NIC address. On error, negative errno value.
 */
static int kcxi_addr_res_ipv4_src(const char *ipv4_addr)
{
	__be32 src_addr;

	if (!ipv4_addr)
		return -EINVAL;

	src_addr = in_aton(ipv4_addr);

	return kcxi_src_to_nic_addr(src_addr);
}

/**
 * kcxi_find_src_addr() - Given a destination IPv4 address, find the source
 * address.
 *
 * Note: Destination IPv4 address MUST be on local area network. Routed
 * destination IPv4 addresses are not supported.
 *
 * Return: On success, zero is returned and src_addr is valid. On error,
 * negative errno is returned and src_addr is invalid.
 */
static int kcxi_find_src_addr(__be32 dest_addr, __be32 *src_addr)
{
	struct net_device *net_dev;
	struct in_device *in_dev;
	bool match = false;
	const struct in_ifaddr *ifa __attribute__((unused));

	if (!src_addr)
		return -EINVAL;

	/* Loop over all IPv4 interfaces looking for a network that the
	 * destination IPv4 address belongs too.
	 */
	rtnl_lock();

	for_each_netdev(&init_net, net_dev) {
		if (!valid_cxi_mac(net_dev->dev_addr))
			continue;

		in_dev = in_dev_get(net_dev);
		if (!in_dev)
			continue;

		FOR_IFA(ifa, in_dev) {
			if ((ifa->ifa_address & ifa->ifa_mask) ==
			    (dest_addr & ifa->ifa_mask)) {
				*src_addr = ifa->ifa_address;
				match = true;
			}
		}
		ENDFOR_IFA(in_dev);

		in_dev_put(in_dev);

		if (match)
			break;
	}

	rtnl_unlock();

	if (!match) {
		LOG_ERR("Failed to find LAN for dest IPv4 address (%pI4)",
			&dest_addr);
		return -ENODEV;
	}

	LOG_DEBUG("Src IPv4 address (%pI4) in same LAN as dest IPv4 address (%pI4)",
		  src_addr, &dest_addr);

	return 0;
}

/**
 * kcxi_addr_res_ipv4_dest() - Resolve destination IPv4 address into a
 * destination NIC address.
 * @ipv4_addr: Local IPv4 address in dot string format.
 *
 * Return: On success, non-negative NIC address. On error, negative errno value.
 */
static int kcxi_addr_res_ipv4_dest(const char *ipv4_addr)
{
	int rc;
	__be32 src_addr;
	__be32 dest_addr;
	int nic_addr;
	struct kcxi_arp_res_entry *res_entry;

	if (!ipv4_addr)
		return -EINVAL;

	dest_addr = in_aton(ipv4_addr);

	/* Use the destination address to find a source address and net device.
	 */
	rc = kcxi_find_src_addr(dest_addr, &src_addr);
	if (rc) {
		LOG_ERR("Failed to find src IPv4 address for dest IPv4 address (%pI4)",
			&dest_addr);

		goto error;
	}

	/* If destination address matches source address, no needed to query the
	 * ARP cache for MAC address. Instead, treat destination address string
	 * as the source address string.
	 */
	if (dest_addr == src_addr) {
		LOG_DEBUG("Dest IPv4 address (%pI4) is loopback", &dest_addr);

		return kcxi_addr_res_ipv4_src(ipv4_addr);
	}

	/* Allocate a resolution entry to resolve destination IPv4 address into
	 * a destination MAC address.
	 */
	res_entry = kcxi_arp_res_entry_alloc(src_addr, dest_addr, NULL, NULL);
	if (IS_ERR(res_entry)) {
		rc = PTR_ERR(res_entry);
		LOG_ERR("Failed to allocate resolution entry: rc=%d", rc);

		goto error;
	}

	rc = kcxi_arp_res_entry_resolve(res_entry);
	if (rc) {
		LOG_ERR("Timeout waiting for ARP response for dest IPv4 address (%pI4)",
			&dest_addr);

		goto error_free_kcxi_arp_res_entry;
	}

	nic_addr = MAC_ADDR_TO_NIC_ADDR(res_entry->dest_mac_addr);

	kcxi_arp_res_entry_free(res_entry);

	LOG_DEBUG("Resolved dest IPv4 address (%pI4) to NIC address (%#x)",
		  &dest_addr, nic_addr);

	return nic_addr;

error_free_kcxi_arp_res_entry:
	kcxi_arp_res_entry_free(res_entry);
error:
	return rc;
}

/**
 * kcxi_addr_res_node_src() - Resolve a source node string into a source NIC
 * address.
 * @node: Node string
 *
 * Attempts to resolve the node string as a source IPv4 address. If this is not
 * successful, default resolution is attempted.
 *
 * Return: On success, non-negative NIC address. On error, negative errno value.
 */
int kcxi_addr_res_node_src(const char *node)
{
	if (valid_ipv4_address(node))
		return kcxi_addr_res_ipv4_src(node);

	return kcxi_addr_res_node_default(node);
}

/**
 * kcxi_addr_res_node_dest() - Resolve a destination node string into a
 * destination NIC address.
 * @node: Node string
 *
 * Attempts to resolve the node string as a destination IPv4 address. If this is
 * not successful, default resolution is attempted.
 *
 * Return: On success, non-negative NIC address. On error, negative errno value.
 */
static int kcxi_addr_res_node_dest(const char *node)
{
	if (valid_ipv4_address(node))
		return kcxi_addr_res_ipv4_dest(node);

	return kcxi_addr_res_node_default(node);
}

/**
 * kcxi_addr_res_service_default() - Default Resolution of a service string into
 * a PID.
 * @service: Service string
 * @pid_granule: Size of the PID space
 *
 * The service string is treated as a 16-bit value.
 *
 * Note: The PID space is significantly smaller than the max 16-bit value. Any
 * value greater than the PID granule will be folded back into the PID space.
 * This can result in PID collision.
 *
 * Return: On success, non-negative errno value. On error, negative errno value.
 */
static int kcxi_addr_res_service_default(const char *service,
					 size_t pid_granule)
{
	int rc;
	uint16_t pid;

	if (!service || pid_granule < 1)
		return -EINVAL;

	rc = kstrtou16(service, 10, &pid);
	if (rc) {
		LOG_ERR("Failed to read PID from service string");

		return rc;
	}

	pid = pid % pid_granule;

	LOG_DEBUG("Resolved PID (%d)", pid);

	return pid;
}

/**
 * kcxi_addr_res_service_src() - Resolve a service string into a local PID.
 * @service: Optional service string
 * @pid_granule: Size of the PID space
 *
 * If service is NULL (which is valid), a default source PID is used.
 *
 * Return: On success, non-negative PID value. On error, negative errno value.
 */
static int kcxi_addr_res_service_src(const char *service, size_t pid_granule)
{
	if (!service)
		return DEFAULT_SRC_PID;

	return kcxi_addr_res_service_default(service, pid_granule);
}

/**
 * kcxi_addr_res_service_dest() - Resolve a remote service string into a local
 * PID.
 * @service: Optional service string
 * @pid_granule: Size of the PID space
 *
 * If service is NULL (which is valid), a default destination PID is used.
 *
 * Return: On success, non-negative PID value. On error, negative errno value.
 */
static int kcxi_addr_res_service_dest(const char *service, size_t pid_granule)
{
	if (!service)
		return DEFAULT_DEST_PID;

	return kcxi_addr_res_service_default(service, pid_granule);
}

/**
 * kcxi_dest_node_to_src_nic() Using a destination node string, find the local
 * source NIC address.
 * @node: Optional node string.
 *
 * Returns: On success, non-negative source NIC address. On error, negative
 * errno.
 */
static int kcxi_dest_node_to_src_nic(const char *node)
{
	int rc;
	uint32_t src_nic;
	__be32 src_addr;
	__be32 dest_addr;

	if (valid_ipv4_address(node)) {
		dest_addr = in_aton(node);

		rc = kcxi_find_src_addr(dest_addr, &src_addr);
		if (rc < 0) {
			LOG_ERR("Failed to find src IPv4 address from dest IPv4 address (%pI4) rc=%d",
				&dest_addr, rc);

			goto error;
		}

		rc = kcxi_src_to_nic_addr(src_addr);
		if (rc < 0) {
			LOG_ERR("Failed to resolve src IPv4 address to NIC address rc=%d",
				rc);

			goto error;
		}

		src_nic = rc;
	} else {
		/* TODO: Using first NIC PID granule only works if the
		 * PID granule for multiple devices is the same.
		 */
		rc = kcxi_dev_first_nic();
		if (rc < 0) {
			LOG_ERR("Failed to find kCXI interface rc=%d", rc);

			goto error;
		}
		src_nic = rc;
	}

	return src_nic;

error:
	return rc;
}

/**
 * kcxi_addr_src_nic_to_pid() - Using a source NIC address, translate the
 * service string to  source or destination PID.
 * @service: Optional service string.
 * @src_nic: Source NIC address.
 * @dest: Service string should be treated as destination PID (default is source
 * PID).
 *
 * Returns: On success, non-negative PID value. On error, negative errno.
 */
static int kcxi_addr_src_nic_to_pid(const char *service, uint32_t src_nic, bool dest)
{
	struct kcxi_dev *dev;
	uint16_t pid;
	int rc;

	/* Lookup the source kCXI interface to get PID granule. */
	dev = kcxi_dev_get(src_nic);
	if (IS_ERR(dev)) {
		rc = PTR_ERR(dev);

		LOG_ERR("Failed to get kCXI device rc=%d", rc);

		goto error;
	}

	/* Resolve the service string into a PID. */
	if (dest)
		rc = kcxi_addr_res_service_dest(service, dev->pid_granule);
	else
		rc = kcxi_addr_res_service_src(service, dev->pid_granule);
	if (rc < 0) {
		LOG_ERR("Failed to resolve service rc=%d", rc);

		goto error_release_dev;
	}
	pid = rc;

	kcxi_dev_put(dev);

	return pid;

error_release_dev:
	kcxi_dev_put(dev);
error:
	return rc;
}

/**
 * kcxi_addr_res_info() - Resolve a node and service string into a local NIC
 * address and PID.
 * @node: Optional node string.
 * @service: Optional service string.
 * @dest: Resolution is for a destination kCXI address.
 * @remote: Node and service string should be treated as remote.
 * @addr: kCXI address to be set on success.
 *
 * Return: On success, zero. In addition, the NIC and PID pointer will be set to
 * valid values. On error, negative errno value.
 */
static int kcxi_addr_res_info(const char *node, const char *service,
			      bool dest, struct kcxi_addr *addr)
{
	int rc;
	uint32_t src_nic;

	if (!addr)
		return -EINVAL;

	/* Resolve the node string into a NIC address. */
	if (dest)
		rc = kcxi_addr_res_node_dest(node);
	else
		rc = kcxi_addr_res_node_src(node);
	if (rc < 0) {
		LOG_ERR("Failed to resolve node string rc=%d", rc);

		goto error;
	}
	addr->nic = rc;

	/* Locate the local NIC in order to find PID granule. */
	if (dest) {
		rc = kcxi_dest_node_to_src_nic(node);
		if (rc < 0) {
			LOG_ERR("Failed to find local source NIC: rc=%d", rc);

			goto error;
		}

		src_nic = rc;
	} else {
		src_nic = addr->nic;
	}

	/* Resolve service string. */
	rc = kcxi_addr_src_nic_to_pid(service, src_nic, dest);
	if (rc < 0) {
		LOG_ERR("Failed to resolve service rc=%d", rc);

		goto error;
	}

	addr->pid = rc;

	if (dest)
		LOG_DEBUG("Resolved dest kCXI address: NIC=%#x PID=%u",
			  addr->nic, addr->pid);
	else
		LOG_DEBUG("Resolved src kCXI address: NIC=%#x PID=%u",
			  addr->nic, addr->pid);

	return 0;

error:
	addr->nic = 0;
	addr->pid = 0;

	if (dest)
		LOG_ERR("Failed to resolve dest kCXI address");
	else
		LOG_ERR("Failed to resolve src kCXI address");

	return rc;
}

/**
 * kcxi_addr_res_src_info() - Resolve a node and service into a source kCXI
 * address.
 * @node: Optional node string.
 * @service: Optional service string.
 * @addr: kCXI address to be set on success.
 *
 * Return: On success, zero is returned and addr pointer is set. Else, negative
 * errno value is returned.
 */
int kcxi_addr_res_src_info(const char *node, const char *service,
			   struct kcxi_addr *addr)
{
	return kcxi_addr_res_info(node, service, false, addr);
}

/**
 * kcxi_addr_res_dest_info() - Resolve a node and service into a destination
 * kCXI address.
 * @node: Optional node string.
 * @service: Optional service string.
 * @addr: kCXI address to be set on success.
 *
 * Return: On success, zero is returned and addr pointer is set. Else, negative
 * errno value is returned.
 */
int kcxi_addr_res_dest_info(const char *node, const char *service,
			    struct kcxi_addr *addr)
{
	return kcxi_addr_res_info(node, service, true, addr);
}

/* kCXI address resolution context used for asynchronous address resolution. */
struct kcxi_addr_res_ctx {
	char *node;
	char *service;
	kcxi_addr_res_async_cb cb;
	void *context;
	uint16_t pid;
	uint32_t nic;
	struct work_struct work;
	struct kcxi_arp_res_entry *res_entry;
};

/**
 * kcxi_addr_res_ctx_alloc() - Allocate a new resolution context.
 * @node: Node string.
 * @service: Service string.
 *
 * The node and service strings are copied into the context.
 *
 * Return: On success, valid pointer. Else, NULL.
 */
static struct kcxi_addr_res_ctx *kcxi_addr_res_ctx_alloc(const char *node,
							 const char *service)
{
	struct kcxi_addr_res_ctx *ctx;
	size_t length;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		goto error;

	/* Copy over the node and service string for async processing. */
	length = strlen(node) + 1;
	ctx->node = kzalloc(length, GFP_KERNEL);
	if (!ctx->node)
		goto error_free_ctx;

	strcpy(ctx->node, node);

	length = strlen(service) + 1;
	ctx->service = kzalloc(length, GFP_KERNEL);
	if (!ctx->service)
		goto error_free_node;

	strcpy(ctx->service, service);

	return ctx;

error_free_node:
	kfree(ctx->node);
error_free_ctx:
	kfree(ctx);
error:
	return NULL;
}

/**
 * kcxi_addr_res_ctx_free() - Free a resolution context.
 * @ctx: Resolution context.
 */
static void kcxi_addr_res_ctx_free(struct kcxi_addr_res_ctx *ctx)
{
	kfree(ctx->service);
	kfree(ctx->node);
	kfree(ctx);
}

/**
 * kcxi_addr_res_dest_cb() - Callback used for ARP resolution.
 * @entry: ARP resolution entry.
 * @rc: Return code from ARP resolution.
 */
static void kcxi_addr_res_dest_cb(struct kcxi_arp_res_entry *entry, int rc)
{
	struct kcxi_addr_res_ctx *ctx;

	ctx = entry->context;

	if (rc) {
		LOG_ERR("ARP resolution failed: rc=%d", rc);

		ctx->cb(0, 0, rc, ctx->context);
	} else {
		ctx->nic = MAC_ADDR_TO_NIC_ADDR(entry->dest_mac_addr);

		LOG_DEBUG("ARP resolution success: nic=%#x", ctx->nic);

		ctx->cb(ctx->nic, ctx->pid, 0, ctx->context);
	}

	kcxi_arp_res_entry_free(ctx->res_entry);

	kcxi_addr_res_ctx_free(ctx);
}

/**
 * kcxi_addr_res_dest_wq() - Deferred work queue function to perform
 * asynchronous destination address resolution.
 * @work: Work struct.
 *
 * Before performing ARP resolution, this function will check to see if the
 * destination address matches a local source. If successful, the users callback
 * is triggered.
 *
 * If ARP resolution needs to occur, an ARP resolution entry is allocated with
 * the kcxi_addr_res_dest_cb() callback. This callback will progress and
 * complete the address resolution.
 */
static void kcxi_addr_res_dest_wq(struct work_struct *work)
{
	struct kcxi_addr_res_ctx *ctx;
	int rc;
	uint32_t src_nic;
	__be32 src_addr;
	__be32 dest_addr;

	ctx = container_of(work, struct kcxi_addr_res_ctx, work);

	LOG_DEBUG("Running asynchronous address resolution for dest (%s)",
		  ctx->node);

	/* Since destination NIC address resolution is the asynchronous portion,
	 * establish destination PID before.
	 */
	rc = kcxi_dest_node_to_src_nic(ctx->node);
	if (rc < 0) {
		LOG_ERR("Failed to find local source NIC: rc=%d", rc);

		goto error;
	}

	src_nic = rc;

	rc = kcxi_addr_src_nic_to_pid(ctx->service, src_nic, true);
	if (rc < 0) {
		LOG_ERR("Failed to resolve service rc=%d", rc);

		goto error;
	}

	ctx->pid = rc;

	/* Attempt to resolve node. Avoid using a resolution entry if possible.
	 */
	if (valid_ipv4_address(ctx->node)) {
		/* Check and see if this IPv4 address is actually a local
		 * address.
		 */
		dest_addr = in_aton(ctx->node);
		rc = kcxi_find_src_addr(dest_addr, &src_addr);
		if (rc) {
			LOG_ERR("Failed to find src IPv4 address for dest IPv4 address (%pI4)",
				&dest_addr);

			goto error;
		}

		if (dest_addr == src_addr) {
			LOG_DEBUG("Dest IPv4 address (%pI4) is loopback", &dest_addr);

			rc = kcxi_addr_res_ipv4_src(ctx->node);
			if (rc < 0) {
				LOG_ERR("Failed to resolve src IPv4 address (%pI4): rc=%d",
					&src_addr, rc);

				goto error;
			}

			/* RC contains the NIC address. */
			goto success;
		}

		/* Allocate a resolution entry and register for a callback. */
		ctx->res_entry =
			kcxi_arp_res_entry_alloc(src_addr, dest_addr,
					     kcxi_addr_res_dest_cb, ctx);
		if (IS_ERR(ctx->res_entry)) {
			rc = PTR_ERR(ctx->res_entry);

			LOG_ERR("Failed to allocate resolution entry: rc=%d",
				rc);

			goto error;
		}

		LOG_DEBUG("Queuing async res request for dest IPv4 address (%pI4)",
			  &dest_addr);

		rc = kcxi_arp_res_entry_resolve(ctx->res_entry);
		if (rc) {
			LOG_ERR("Failed to queue resolution request: rc=%d",
				rc);

			goto error_free_res_entry;

		}

		/* Processing will be completed via the resolution entry
		 * callback.
		 */
		return;
	}

	rc = kcxi_addr_res_node_default(ctx->node);
	if (rc < 0) {
		LOG_ERR("Failed to resolve dest node: rc=%d", rc);

		goto error;
	}

success:
	ctx->nic = rc;

	LOG_DEBUG("Triggering user callback");

	/* Trigger the user's callback with valid NIC address and PID. */
	ctx->cb(ctx->nic, ctx->pid, 0, ctx->context);

	kcxi_addr_res_ctx_free(ctx);

	return;

error_free_res_entry:
	kcxi_arp_res_entry_free(ctx->res_entry);
error:
	ctx->cb(0, 0, rc, ctx->context);

	kcxi_addr_res_ctx_free(ctx);
}

/**
 * kcxi_addr_res_dest_info_async() - Initiate an asynchronous resolution
 * request.
 * @node: Node string.
 * @service: Service string.
 * @cb: Required user callback.
 * @context: User context.
 *
 * Return: If successfully initiated, zero. Else, negative errno value.
 */
int kcxi_addr_res_dest_info_async(const char *node, const char *service,
				  kcxi_addr_res_async_cb cb, void *context)
{
	struct kcxi_addr_res_ctx *ctx;

	if (!cb)
		return -EINVAL;

	ctx = kcxi_addr_res_ctx_alloc(node, service);
	if (!ctx)
		return -ENOMEM;

	/* Finish setting up the resolution context. */
	ctx->cb = cb;
	ctx->context = context;

	INIT_WORK(&ctx->work, kcxi_addr_res_dest_wq);

	LOG_DEBUG("Queuing work for async dest address resolution");

	queue_work(kcxi_wq, &ctx->work);

	return 0;
}
