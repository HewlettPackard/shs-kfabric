/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Cray kfabric KCXI provider header.
 * Copyright 2018-2024 Hewlett Packard Enterprise Development LP
 */

#ifndef _KCXI_PROV_H_
#define _KCXI_PROV_H_

#include <kfabric.h>
#include <kfi_prov.h>
#include <kfi_log.h>
#include <kfi_domain.h>
#include <kfi_eq.h>
#include <kfi_endpoint.h>
#include <kfi_enosys.h>
#include <kfi_errno.h>
#include <kfi_cm.h>
#include <kfi_atomic.h>
#include <kfi_cxi_ext.h>
#include <linux/hpe/cxi/cxi.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/idr.h>
#include <linux/rhashtable.h>
#include <linux/uio.h>
#include <linux/bvec.h>
#include <linux/workqueue.h>
#include <linux/version.h>
#include <linux/timer.h>
#include <linux/pci.h>
#include <linux/debugfs.h>

#include "cxi_prov_hw.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "kfi_cxi"
#define KCXI_PROV_NAME "kcxi"

/* Only bump major version if software wire protocol (i/e match bit usage)
 * changes.
 */
#define KCXI_PROV_MAJOR_VERSION 1U
#define KCXI_PROV_MINOR_VERSION 0U
#define KCXI_PROV_VERSION KFI_VERSION(KCXI_PROV_MAJOR_VERSION, \
				      KCXI_PROV_MINOR_VERSION)

/* Supported kfabric API version. */
#define KCXI_PROV_API_MAJOR_VERSION KFI_MAJOR_VERSION
#define KCXI_PROV_API_MINOR_VERSION KFI_MINOR_VERSION
#define KCXI_PROV_API_VERSION KFI_VERSION(KCXI_PROV_API_MAJOR_VERSION, \
					  KCXI_PROV_API_MINOR_VERSION)

#define KCXI_DOM_IF_DEBUG(dom_if, fmt, ...) \
	LOG_DEBUG("kCXI Domain Interface NIC (%#x) Auth Key (%u) PID (%u): " fmt "", \
		  (dom_if)->kcxi_if->nic_addr, (dom_if)->auth_key, \
		  (dom_if)->pid, ##__VA_ARGS__)

#define KCXI_IF_DEBUG(kcxi_if, fmt, ...) \
	LOG_DEBUG("kCXI Interface Device Index (%u) LNI (%u) NIC (%#x): " fmt "", \
		  (kcxi_if)->dev->index, (kcxi_if)->lni->id, \
		  (kcxi_if)->nic_addr, ##__VA_ARGS__)
#define KCXI_IF_ERR(kcxi_if, fmt, ...) \
	LOG_ERR("kCXI Interface Device Index (%u) LNI (%u) NIC (%#x): " fmt "", \
		(kcxi_if)->dev->index, (kcxi_if)->lni->id, \
		(kcxi_if)->nic_addr, ##__VA_ARGS__)
#define KCXI_IF_INFO(kcxi_if, fmt, ...) \
	LOG_INFO("kCXI Interface Device Index (%u) LNI (%u) NIC (%#x): " fmt "", \
		 (kcxi_if)->dev->index, (kcxi_if)->lni->id, \
		 (kcxi_if)->nic_addr, ##__VA_ARGS__)

#define MR_DOM_DEBUG(mr_dom, fmt, ...) \
	LOG_DEBUG("MR Domain NIC (%#x) PID (%d) Index (%d): " fmt "", \
		  (mr_dom)->ptlte->dom_if->kcxi_if->nic_addr, \
		  (mr_dom)->ptlte->dom_if->pid, (mr_dom)->ptlte->pid_index, \
		  ##__VA_ARGS__)
#define MR_DOM_ERR(mr_dom, fmt, ...) \
	LOG_ERR("MR Domain NIC (%#x) PID (%d) Index (%d): " fmt "", \
		(mr_dom)->ptlte->dom_if->kcxi_if->nic_addr, \
		(mr_dom)->ptlte->dom_if->pid, (mr_dom)->ptlte->pid_index, \
		##__VA_ARGS__)

#define MR_DEBUG(mr, fmt, ...) \
	LOG_DEBUG("MR NIC (%#x) PID (%d) Index (%d) Key (%llx): " fmt "", \
		  (mr)->rx_ctx ? (mr)->rx_ctx->ep_attr->dom_if->kcxi_if->nic_addr : -EINVAL, \
		  (mr)->rx_ctx ? (mr)->rx_ctx->ep_attr->dom_if->pid : -EINVAL, \
		  (mr)->rx_ctx ? (mr)->rx_ctx->rx_id : -EINVAL, \
		  (mr)->mr_fid.key, ##__VA_ARGS__)
#define MR_WARN(mr, fmt, ...) \
	LOG_WARN("MR NIC (%#x) PID (%d) Index (%d) Key (%llx): " fmt "", \
		 (mr)->rx_ctx ? (mr)->rx_ctx->ep_attr->dom_if->kcxi_if->nic_addr : -EINVAL, \
		 (mr)->rx_ctx ? (mr)->rx_ctx->ep_attr->dom_if->pid : -EINVAL, \
		 (mr)->rx_ctx ? (mr)->rx_ctx->rx_id : -EINVAL, \
		 (mr)->mr_fid.key, ##__VA_ARGS__)
#define MR_ERR(mr, fmt, ...) \
	LOG_ERR("MR NIC (%#x) PID (%d) Index (%d) Key (%llx): " fmt "", \
		(mr)->rx_ctx ? (mr)->rx_ctx->ep_attr->dom_if->kcxi_if->nic_addr : -EINVAL, \
		(mr)->rx_ctx ? (mr)->rx_ctx->ep_attr->dom_if->pid : -EINVAL, \
		(mr)->rx_ctx ? (mr)->rx_ctx->rx_id : -EINVAL, \
		(mr)->mr_fid.key, ##__VA_ARGS__)

#define RXC_DEBUG(rx_ctx, fmt, ...) \
	LOG_DEBUG("RX context NIC (%#x) PID (%d) Index (%d): " fmt "", \
		  (rx_ctx)->ep_attr->dom_if->kcxi_if->nic_addr, \
		  (rx_ctx)->ep_attr->dom_if->pid, rx_ctx->rx_id, \
		  ##__VA_ARGS__)
#define RXC_WARN(rx_ctx, fmt, ...) \
	LOG_WARN("RX context NIC (%#x) PID (%d) Index (%d): " fmt "", \
		 (rx_ctx)->ep_attr->dom_if->kcxi_if->nic_addr, \
		 (rx_ctx)->ep_attr->dom_if->pid, rx_ctx->rx_id, \
		 ##__VA_ARGS__)
#define RXC_ERR(rx_ctx, fmt, ...) \
	LOG_ERR("RX context NIC (%#x) PID (%d) Index (%d): " fmt "", \
		(rx_ctx)->ep_attr->dom_if->kcxi_if->nic_addr, \
		(rx_ctx)->ep_attr->dom_if->pid, rx_ctx->rx_id, \
		##__VA_ARGS__)

#define TXC_DEBUG(tx_ctx, fmt, ...) \
	LOG_DEBUG("TX context NIC (%#x) PID (%d) Index (%d): " fmt "", \
		  (tx_ctx)->ep_attr->dom_if->kcxi_if->nic_addr, \
		  (tx_ctx)->ep_attr->dom_if->pid, tx_ctx->tx_id, \
		  ##__VA_ARGS__)
#define TXC_ERR(tx_ctx, fmt, ...) \
	LOG_ERR("TX context NIC (%#x) PID (%d) Index (%d): " fmt "", \
		(tx_ctx)->ep_attr->dom_if->kcxi_if->nic_addr, \
		(tx_ctx)->ep_attr->dom_if->pid, tx_ctx->tx_id, \
		##__VA_ARGS__)
#define TXC_ERR_RL(tx_ctx, fmt, ...) \
	LOG_ERR_RL("TX context NIC (%#x) PID (%d) Index (%d): " fmt "", \
		   (tx_ctx)->ep_attr->dom_if->kcxi_if->nic_addr, \
		   (tx_ctx)->ep_attr->dom_if->pid, tx_ctx->tx_id, \
		   ##__VA_ARGS__)

#define CQ_DEBUG(cq, fmt, ...) \
	LOG_DEBUG("CQ NIC (%#x) EQN (%d): " fmt "", \
		  (cq)->domain->kcxi_if->nic_addr, (cq)->eq->eqn, ##__VA_ARGS__)
#define CQ_ERR(cq, fmt, ...) \
	LOG_ERR("CQ NIC (%#x) EQN (%d): " fmt "", \
		(cq)->domain->kcxi_if->nic_addr, (cq)->eq->eqn, ##__VA_ARGS__)

#define KCXI_DEV_ERR(kcxi_dev, fmt, ...) \
	LOG_ERR("kCXI Device Index (%u) Fabric (%u): " fmt "", \
		(kcxi_dev)->index, (kcxi_dev)->fabric, ##__VA_ARGS__)
#define KCXI_DEV_INFO(kcxi_dev, fmt, ...) \
	LOG_INFO("kCXI Device Index (%u) Fabric (%u): " fmt "", \
		 (kcxi_dev)->index, (kcxi_dev)->fabric, ##__VA_ARGS__)

#define LOCALLY_ADMIN_MAC_MASK 0x30000000000UL
#define LOCALLY_ADMIN_MAC_MATCH 0x20000000000UL
static inline bool is_locally_admin_mac_addr(u64 mac_addr)
{
	return (mac_addr & LOCALLY_ADMIN_MAC_MASK) == LOCALLY_ADMIN_MAC_MATCH;
}

/* Bits 56-63 are reserved for provider versioning forever. */
#define KCXI_PROV_VERSION_MATCH_RANGE 0xFF00000000000000ULL
#define KCXI_PROV_VERSION_BITS(ver) ((uint64_t)(ver) << 56ULL)

/* Reserved match values for provider software wire operations. */
#define KCXI_MSG_MATCH_VALUE 0
#define KCXI_MR_MATCH_VALUE BIT(55)
#define KCXI_TAG_MSG_MATCH_VALUE BIT(54)
#define KCXI_RMA_TAG_MATCH_VALUE BIT(53)
#define KCXI_REMOTE_CQ_DATA_MATCH_VALUE BIT(52)
#define KCXI_MAX_USER_MATCH_VALUE (KCXI_REMOTE_CQ_DATA_MATCH_VALUE - 1)

/* TODO: Various limitations may need to be adjusted */
#define KCXI_EP_DEF_MIN_MULTI_RECV 64
#define KCXI_EP_MAX_CTX_BITS 16
#define KCXI_EQ_DEF_SZ (1 << 16)
#define KCXI_CQ_DEF_SZ 2048
#define KCXI_AV_DEF_SZ (1 << 16)

/* Max IOV limit is set to 256 to accommodate IOV needs for LNet. */
#define KCXI_MAX_IOV 256

/*
 * RX context size is capped at the minimum KCXI device PID granule size (256)
 * divided by two. The reason for the divide by two is the lower half of the PID
 * granule space is used for puts while the upper is used for gets to workaround
 * CAS-3042.
 *
 * TX context limit is such to be symmetric to RX context limit.
 */
#define KCXI_MAX_RX_CTX 128U
#define KCXI_MAX_TX_CTX KCXI_MAX_RX_CTX
#define KCXI_GET_PID_OFFSET KCXI_MAX_RX_CTX

/*
 * Capped the number of endpoints per domain to be the minimum number of KCXI
 * domains that can be allocated for any KCXI device configuration.
 */
#define KCXI_MAX_EP 64

/* KCXI domain attribute defaults and limitations. */
#define KCXI_DOM_THREADING KFI_THREAD_SAFE
#define KCXI_DOM_CONTROL_PROGRESS KFI_PROGRESS_AUTO
#define KCXI_DOM_DATA_PROGRESS KFI_PROGRESS_AUTO
#define KCXI_DOM_RESOURCE_MGMT KFI_RM_DISABLED
#define KCXI_DOM_AV_TYPE KFI_AV_MAP
#define KCXI_DOM_MR_MODE KFI_MR_ENDPOINT
#define KCXI_DOM_MR_KEY_SIZE 7
#define KCXI_DOM_CQ_DATA_SIZE 0
#define KCXI_DOM_CQ_CNT (KCXI_MAX_TX_CTX + KCXI_MAX_RX_CTX)
#define KCXI_DOM_EP_CNT KCXI_MAX_EP
#define KCXI_DOM_TX_CTX_CNT 1
#define KCXI_DOM_RX_CTX_CNT 1
#define KCXI_DOM_MAX_EP_TX_CTX KCXI_MAX_TX_CTX
#define KCXI_DOM_MAX_EP_RX_CTX KCXI_MAX_RX_CTX
#define KCXI_DOM_MAX_EP_STX_CTX 0
#define KCXI_DOM_MAX_EP_SRX_CTX 0
#define KCXI_DOM_CNTR_CNT 0
#define KCXI_DOM_MR_IOV_LIMIT KCXI_MAX_IOV
#define KCXI_DOM_CAPS (KFI_REMOTE_COMM | KFI_LOCAL_COMM)
#define KCXI_DOM_MODE 0
#define KCXI_DOM_AUTH_KEY_SIZE (sizeof(uint32_t))
#define KCXI_DOM_MAX_ERR_DATA 0
#define KCXI_DOM_MR_CNT 2048

#define KCXI_DOM_AC_RES 2
#define KCXI_DOM_AC_MAX 8
#define KCXI_DOM_CQ_RES 16
#define KCXI_DOM_CQ_MAX (KCXI_MAX_RX_CTX * 2)
#define KCXI_DOM_TX_CTX_RES 8
#define KCXI_DOM_TX_CTX_MAX KCXI_MAX_RX_CTX
#define KCXI_DOM_RX_CTX_RES 8
#define KCXI_DOM_RX_CTX_MAX KCXI_MAX_RX_CTX
#define KCXI_DOM_BUF_RES 4096
#define KCXI_DOM_BUF_MAX C_LPE_STS_LIST_ENTRIES_ENTRIES

/*
 * DMA commands use 32 bits for length. This is the upper bound for transfer
 * size.
 */
#define KCXI_MAX_TX_SIZE U32_MAX

/* KCXI endpoint attribute defaults and limitations. */
#define KCXI_EP_TYPE KFI_EP_RDM
#define KCXI_EP_PROTOCOL KFI_PROTO_CXI
#define KCXI_EP_PROTOCOL_VERSION 1
#define KCXI_EP_MAX_MSG_SIZE KCXI_MAX_TX_SIZE
#define KCXI_EP_MSG_PREFIX_SIZE 0
#define KCXI_EP_MAX_ORDER_RAW_SIZE 0
#define KCXI_EP_MAX_ORDER_WAR_SIZE 0
#define KCXI_EP_MAX_ORDER_WAW_SIZE 0
#define KCXI_EP_MEM_TAG_FORMAT 0xAAAAAAAAAAAAAAAAULL
#define KCXI_EP_TX_CTX_CNT KCXI_MAX_TX_CTX
#define KCXI_EP_RX_CTX_CNT KCXI_MAX_RX_CTX

/* KCXI transmit attribute defaults and limitations. */
#define KCXI_TX_CAPS (KFI_MSG | KFI_RMA | KFI_SEND | KFI_READ | KFI_WRITE | \
		      KFI_NAMED_RX_CTX | KFI_TAGGED | KFI_TAGGED_RMA)
#define KCXI_TX_MODE 0
#define KCXI_TX_OP_FLAGS (KFI_TRANSMIT_COMPLETE | KFI_COMPLETION | KFI_MORE)
#define KCXI_TX_MSG_ORDER KFI_ORDER_NONE
#define KCXI_TX_COMP_ORDER KFI_ORDER_NONE
#define KCXI_TX_INJECT_SIZE 0

/* Limit TX context size based on max CQ allocate size and max command size. */
#define KCXI_TX_MAX_CMD_SIZE 256
#define KCXI_TX_MAX_CQ_SIZE (CXI_MAX_CQ_COUNT * C_CQ_CMD_SIZE)
#define KCXI_TX_ALLOC_INCREASE_FACTOR (KCXI_TX_MAX_CMD_SIZE / C_CQ_CMD_SIZE)
#define KCXI_TX_SIZE (KCXI_TX_MAX_CQ_SIZE / KCXI_TX_MAX_CMD_SIZE)

#define KCXI_TX_IOV_LIMIT KCXI_MAX_IOV
#define KCXI_TX_RMA_IOV_LIMIT KCXI_MAX_IOV

/* KCXI receive attribute defaults and limitations. */
#define KCXI_RX_CAPS (KFI_MSG | KFI_RMA | KFI_RECV | KFI_REMOTE_READ | \
		      KFI_REMOTE_WRITE | KFI_MULTI_RECV | KFI_RMA_EVENT | \
		      KFI_SOURCE | KFI_TAGGED | KFI_DIRECTED_RECV)
#define KCXI_RX_MODE 0
#define KCXI_RX_OP_FLAGS (KFI_COMPLETION | KFI_MULTI_RECV | KFI_MORE)
#define KCXI_RX_MSG_ORDER KFI_ORDER_NONE
#define KCXI_RX_COMP_ORDER KFI_ORDER_NONE
#define KCXI_RX_TOTAL_BUFFERED_RECV 0
#define KCXI_RX_SIZE 2048		/* TODO: Tie into CXI service. */
#define KCXI_RX_IOV_LIMIT KCXI_MAX_IOV

/* The primary and secondary capabilities */
#define KCXI_CAPS (KCXI_DOM_CAPS | KCXI_TX_CAPS | KCXI_RX_CAPS)
#define KCXI_EP_RDM_CAP KCXI_CAPS
#define KCXI_MODE 0

#define KCXI_DEF_EAGER_THRESHOLD (1 << 14)
#define KCXI_EP_CQ_BIND_FLAGS (KFI_TRANSMIT | KFI_RECV | \
			      KFI_SELECTIVE_COMPLETION)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)

#define KF_ITER_BVEC ITER_BVEC
#define KF_ITER_KVEC ITER_KVEC

#define FOR_IFA(ifa, in_dev) for_ifa(in_dev)
#define ENDFOR_IFA(in_dev) endfor_ifa(in_dev)

#define ATOMIC_READ atomic_read

#define KF_TIMER_SETUP(timer, addr) timer.data = (unsigned long)addr

#else

#define KF_ITER_BVEC (READ | WRITE)
#define KF_ITER_KVEC (READ | WRITE)

#define FOR_IFA(ifa, in_dev) in_dev_for_each_ifa_rcu(ifa, in_dev)
#define ENDFOR_IFA(in_dev)

#define ATOMIC_READ refcount_read

#define KF_TIMER_SETUP(timer, addr) timer_setup(&timer, timer.function, 0)

#endif

extern unsigned int default_auth_key;
extern unsigned int eager_threshold;
extern unsigned int address_contexts;
extern unsigned int completion_queues;
extern unsigned int transmit_contexts;
extern unsigned int receive_contexts;
extern unsigned int message_buffers;
extern struct workqueue_struct *kcxi_wq;
extern struct dentry *kcxi_debugfs_dir;
extern unsigned long rnr_timeout;
extern unsigned int cq_fill_percent;
extern int md_cache_bufsize;

#define KCXI_ADDR_FLAG_AV_ENTRY_VALID (1 << 0)
#define KCXI_ADDR_AV_ENTRY_VALID(addr) \
	((addr)->flags & KCXI_ADDR_FLAG_AV_ENTRY_VALID)
#define KCXI_ADDR_AV_ENTRY_SET_VALID(addr) \
	((addr)->flags |= KCXI_ADDR_FLAG_AV_ENTRY_VALID)
#define KCXI_ADDR_AV_ENTRY_CLR_VALID(addr) \
	((addr)->flags &= ~KCXI_ADDR_FLAG_AV_ENTRY_VALID)

#define KCXI_ADDR_FLAG_AV_ENTRY_ALLOCATED (1 << 1)
#define KCXI_ADDR_AV_ENTRY_ALLOCATED(addr) \
	((addr)->flags & KCXI_ADDR_FLAG_AV_ENTRY_ALLOCATED)
#define KCXI_ADDR_AV_ENTRY_SET_ALLOCATED(addr) \
	((addr)->flags |= KCXI_ADDR_FLAG_AV_ENTRY_ALLOCATED)
#define KCXI_ADDR_AV_ENTRY_CLR_ALLOCATED(addr) \
	((addr)->flags &= ~KCXI_ADDR_FLAG_AV_ENTRY_ALLOCATED)

/* Needs to be equal to number of bits in target min_free field. */
#define KCXI_MULTI_RECV_BITS 24

/**
 * struct kcxi_dev - kCXI device.
 * @entry: Global list the interface lives on
 * @dev: CXI device
 * @dev_lock: RCU CXI device lock
 * @index: Local system index of the NIC (eg: cxi0 -> idx 0)
 * @fabric: The fabric (slice) the NIC belongs to
 * @pid_granule: Granularity of interface PID space
 * @multi_recv_shift: Shift applied to multi recv value
 * @multi_recv_limit: Max value for multi recv unlink
 * @ref_cnt: Reference count
 *
 * kCXI device is a provider representation of the underlying CXI device.
 */
struct kcxi_dev {
	struct list_head entry;
	struct cxi_dev __rcu *dev;
	struct srcu_struct dev_lock;
	uint32_t index;
	uint32_t fabric;
	uint32_t pid_granule;
	uint32_t pid_bits;
	uint32_t multi_recv_shift;
	size_t multi_recv_limit;
	struct device *device;
	atomic_t ref_cnt;
	struct dentry *dev_debugfs_dir;
};

/**
 * struct kcxi_if - kCXI interface.
 * @dev: kCXI device.
 * @lni: Logical network interface.
 * @cp: Communication profile.
 * @md_cur_count: Current number of allocated MDs.
 * @md_cached_count: Number of cached MDs.
 * @ptlte_list: List of allocated PtlTEs.
 * @ptlte_list_lock: Lock protecting PtlTE list.
 * @cp_list: LRU List of allocated communication profiles.
 * @cp_list_lock: Lock protecting CP list.
 * @cp_cnt: Number of allocated CPs.
 * @phys_lac: LAC used for physically contiguous buffers.
 * @ref_cnt: Reference count.
 * @svc_id: Service id.
 * @addr: NIC fabric address.
 *
 * kCXI interface is a partition of a kCXI device. A kCXI interface is required
 * to allocate underlying CXI device resources.
 */
struct kcxi_if {
	struct kcxi_dev *dev;
	struct cxi_lni *lni;
	atomic_t md_cur_count;
	atomic_t md_cached_count;
	struct list_head ptlte_list;
	spinlock_t ptlte_list_lock;
	uint8_t phys_lac;
	atomic_t ref_cnt;
	struct list_head cp_list;
	struct mutex cp_lock;
	atomic_t cp_cnt;
	int svc_id;
	unsigned int nic_addr;

	/* Software counters. */
	atomic_t md_max_count;

	struct dentry *if_debugfs_dir;
};

/**
 * struct kcxi_cp - kCXI communication profile.
 * @entry: kCXI interface list communication profile lives on.
 * @kcxi_if: kCXI interface the communication profile was allocated against.
 * @cp: CXI communication profile.
 * @ref_cnt: Number of users of the communication profile.
 */
struct kcxi_cp {
	struct list_head entry;
	struct kcxi_if *kcxi_if;
	struct cxi_cp *cp;
	atomic_t ref_cnt;
};


/**
 * struct kcxi_domain_if - kCXI domain interface
 * @kcxi_if: kCXI interface the domain interface was allocated against
 * @dom: CXI core domain
 * @pid: Portal table ID
 * @auth_key: Authorization key (VNI)
 * @index_bitmap: Bitmap of used PID indexes
 * @ref_cnt: Reference counter
 * @lock: Domain interface lock
 */
struct kcxi_domain_if {
	struct kcxi_if *kcxi_if;
	struct cxi_domain *dom;
	uint32_t pid;
	uint32_t auth_key;
	size_t max_index;
	unsigned long *index_bitmap;
	atomic_t ref_cnt;
	struct mutex lock;
	struct dentry *dom_if_debugfs_dir;
};

/**
 * struct kcxi_md - Memory descriptor.
 * @dma_addr: Address used for DMA commands.
 * @user_addr: User provided address.
 * @len: Length of the memory descriptor.
 * @lac: Local address context used for DMA commands.
 * @kcxi_if: Interface memory descriptor was allocated against.
 * @kcxi_cq: Completion queue memory descriptor was allocated against.
 * @mapped_md: Mapped memory descriptor.
 * @page_mapped: Buffer mapped with dma_map_page().
 * @mapped_dma_addr: DMA address used for unmapping.
 * @mapped_dma_len: DMA mapped length used for unmapping.
 * @calling_cpu: CPU ID MD allocation occurred on.
 * @entry: Memory descriptor cache list entry.
 * @is_cacheable: This memory descriptor is cachable.
 * @sgt: Scatter gather table info for cachable memory descriptors.
 */
struct kcxi_md {
	dma_addr_t dma_addr;
	uint64_t user_addr;
	size_t len;
	uint8_t lac;
	struct kcxi_if *kcxi_if;
	struct kcxi_cq *kcxi_cq;
	struct cxi_md *mapped_md;
	bool page_mapped;
	dma_addr_t mapped_dma_addr;
	size_t mapped_dma_len;
	int calling_cpu;
	struct list_head entry;
	bool is_cacheable;
	struct sg_table sgt;
};

/**
 * struct kcxi_md_cache - Memory descriptor cache.
 * @md_cache_list: List of cleared memory descriptors
 * @md_cache_list_lock: Lock protecting md cache list
 * @md_cache_entries: Number of cached memory descriptor entries
 * @md_cache_bufsize: Max buffer size of a cached memory descriptor
 * @md_cached_count: Number of cached memory descriptors allocated
 * @md_cached_avail: Number of cached memory descriptors unused
 * @md_cached_max: Max number of cached memory descriptors used
 *
 */
struct kcxi_md_cache {
	struct list_head md_cache_list;
	spinlock_t md_cache_list_lock;
	size_t md_cache_entries;
	size_t md_cache_bufsize;
	atomic_t md_cached_count;
	atomic_t md_cached_avail;

	/* Software counters. */
	atomic_t md_cached_max;
};

/**
 * struct kcxi_fabric - The kCXI fabric structure
 * @kfid_fabric: Kfabric fabric structure
 * @entry: List the kCXI fabric lives on
 * @domain_list: List of kCXI domains allocated against this fabric
 * @domain_lock: Lock protecting the domain list
 * @ref_cnt: Number of EQs and domains allocated against this fabric
 * @fabric_id: Fabric (slice) ID
 *
 * All open kfabric domains are listed on domain_list.
 */
struct kcxi_fabric {
	struct kfid_fabric fab_fid;
	struct list_head entry;
	struct list_head domain_list;
	struct mutex domain_lock;
	atomic_t ref_cnt;
	uint32_t fabric_id;
	bool dynamic_rsrc_alloc;
};

/**
 * struct kcxi_eq_entry - A kCXI event queue entry
 * @entry: List the entry list on
 * @len: The length of the entry
 * @type: The type of the entry if it is an event
 * @event: Event entry contents
 * @error: Error entry contents
 */
struct kcxi_eq_entry {
	struct list_head entry;
	size_t len;
	union {
		struct {
			uint32_t type;
			struct kfi_eq_entry event;
		};
		struct kfi_eq_err_entry error;
	};
};

struct kcxi_eq;
typedef int (*eq_report_event)(struct kcxi_eq *cxi_eq, uint32_t type,
			       const struct kfi_eq_entry *event);
typedef int (*eq_report_error)(struct kcxi_eq *cxi_eq,
			       const struct kfi_eq_err_entry *error);
typedef void (*eq_raise_handler)(struct kcxi_eq *cxi_eq);


/**
 * struct kcxi_eq - The kCXI event queue
 * @eq: The user facing kfabric event queue
 * @attr: The user defined attributes
 * @cxi_fab: The kCXI fabric the EQ was allocated against
 * @entries: Array of EQ entries
 * @entry: The fabric EQ list this EQ lives on
 * @event_list: List of events
 * @error_list: List of errors
 * @free_list: List of free entries
 * @entry_list_lock: Lock protecting event and error lists
 * @entry_free_list_lock: Lock protecting entry_free_list
 * @error_cnt: Number of errors on the error_list
 * @overrun: Number of overruns that have occurred
 * @ref_cnt: Number of kfabric objects using this EQ
 * @report_event: Function to report events
 * @report_error: Function to report errors
 * @raise_handler: Raise the user defined handler
 * @armed: Whether or not EQ comp handler should be triggered
 */
struct kcxi_eq {
	struct kfid_eq eq;
	struct kfi_eq_attr attr;
	struct kcxi_fabric *fab;
	struct kcxi_eq_entry *entries;
	struct list_head entry;
	struct list_head event_list;
	struct list_head error_list;
	struct list_head free_list;
	spinlock_t entry_list_lock;
	spinlock_t entry_free_list_lock;
	atomic_t error_cnt;
	atomic_t overrun;
	atomic_t ref_cnt;
	eq_report_event report_event;
	eq_report_error report_error;
	eq_raise_handler raise_handler;
	bool armed;
};

/**
 * struct kcxi_domain - kCXI provider domain.
 * @dom_fid: Kfabric user object.
 * @attr: Domain specific attributes.
 * @fab: The kCXI fabric the domain was allocated against.
 * @kcxi_if: kCXI interface the domain uses.
 * @eq: EQ to be used for domain.
 * @mr_eq: EQ to be used for MR events.
 * @entry: The list the domain lives on.
 * @default_auth_key: Default authorization key used for EPs.
 * @ref_cnt: Number of endpoints and AVs allocated against this domain.
 */
struct kcxi_domain {
	struct kfid_domain dom_fid;
	struct kfi_domain_attr attr;
	struct kcxi_fabric *fab;
	struct kcxi_if *kcxi_if;
	struct kcxi_eq *eq;
	struct kcxi_eq *mr_eq;
	struct list_head entry;
	uint32_t def_auth_key;
	atomic_t ref_cnt;
};

/**
 * struct kcxi_av_table_hdr - Header for the AV table
 * @size: Current size of the table
 * @stored: Number of entries stored in the table
 *
 * Note: When items are removed from the table, the stored value is not
 * changed. Removal of items in the table will cause gaps. In order for the
 * table to grow, the number stored must be equal to size, and there must be
 * zero gaps.
 */
struct kcxi_av_table_hdr {
	uint64_t size;
	uint64_t stored;
};

/**
 * struct kcxi_av - The kCXI address vector
 * @av_fid: The user's kfabric AV
 * @attr: The AV attributes
 * @domain: The domain the AV was allocated against
 * @eq: The EQ bound to this AV
 * @mask: Bit mask represent RX CTX bits
 * @table_hdr: Table header
 * @table: The table of resolved kCXI addresses
 * @table_lock: Lock protecting the table
 * @ref_cnt: Number of endpoints using this AV
 */
struct kcxi_av {
	struct kfid_av av_fid;
	struct kfi_av_attr attr;
	struct kcxi_domain *domain;
	struct kcxi_eq *eq;
	uint64_t mask;
	struct kcxi_av_table_hdr *table_hdr;
	struct kcxi_addr *table;
	rwlock_t table_lock;
	atomic_t ref_cnt;
};

#define KCXI_AV_TABLE_SZ(count) (sizeof(struct kcxi_av_table_hdr) + \
				(count * sizeof(struct kcxi_addr)))

struct kcxi_req_state;
struct kcxi_cq;
typedef int (*kcxi_req_cb)(struct kcxi_cq *cq, struct kcxi_req_state *req,
			   const union c_event *event);
typedef struct kcxi_eq *(*kcxi_mr_link_cb)(struct kcxi_req_state *req,
					   const union c_event *event);
typedef void (*kcxi_mr_unlink_cb)(struct kcxi_req_state *req,
				  const union c_event *event);

struct kcxi_req_state {
	void *buf;
	size_t data_len;
	void *context;
	uint64_t tag;
	uint64_t flags;
	uint64_t data;
	kcxi_req_cb cb;
	kcxi_mr_link_cb mr_link_cb;
	kcxi_mr_unlink_cb mr_unlink_cb;
};

typedef ssize_t (*cq_report_completion)(struct kcxi_cq *cq,
					kfi_addr_t src_addr,
					struct kcxi_req_state *req);
typedef ssize_t (*cq_report_error)(struct kcxi_cq *cq,
				   struct kcxi_req_state *req, size_t olen,
				   int err, int prov_errno);
typedef int (*cq_buffer_id_map)(struct kcxi_cq *cq, struct kcxi_req_state *req);
typedef void (*cq_buffer_id_unmap)(struct kcxi_cq *cq, unsigned int buffer_id);


struct kcxi_cq_entry {
	struct list_head entry;
	bool overflow;
	union {
		struct kfi_cq_entry context;
		struct kfi_cq_msg_entry msg;
		struct kfi_cq_data_entry data;
		struct kfi_cq_tagged_entry tagged;
		struct kfi_cq_err_entry error;
	} event;
	kfi_addr_t src_addr;
};

#define MAX_CQ_OVERFLOW_ENTRY_CNT 2000000
#define MAX_BUFFER_ID (1 << 16)
#define MIN_MD_CACHE_BUFSIZE 8192
#define MAX_MD_CACHE_BUFSIZE 131072

/**
 * struct kcxi_cq - kCXI completion queue
 * @cq_fid: User kfabric completion queue
 * @attr: Completion queue attributes
 * @cq_entry_size: Size of the completion entry
 * @eq: Backing Cassini event queue
 * @priority_entries: Array of CQ priority entries
 * @event_list: List of valid completion events
 * @error_list: List of valid error events
 * @entry_free_list: List of free kcxi_cq_entry's
 * @entry_list_lock: Lock protecting event and error lists
 * @entry_free_list_lock: Lock protecting entry_free_list
 * @priority_entry_cnt: Number of priority CQ entries allocated
 * @overflow_entry_cnt: Number of overflow CQ entries allocated
 * @overrun_cnt: Greater than zero if queue was overrun
 * @active_operation_cnt: Number of active operations using this CQ
 * @ref_cnt: Number of endpoints using this CQ
 * @report_completion: Function to report completion events
 * @report_error: Function to report error events
 * @buffer_id_alloc: Function to allocate a buffer ID
 * @buffer_id_free: Function to free buffer ID
 * @buffer_id_table: Table mapping buffer IDs to kCXI request states
 * @table_lock: Serializing access to the buffer ID table
 * @armed: Whether or not CQ comp handler should be triggered
 *
 * For target events (excluding PtlTE state change), the kCXI request state
 * must be mapped to a buffered ID within the kCXI CQ. Else, events cannot
 * be properly processed. Transmit events can provided the kCXI request state
 * as a user pointer (do not need a buffer ID).
 */
struct kcxi_cq {
	struct kfid_cq cq_fid;
	struct kfi_cq_attr attr;
	ssize_t cq_entry_size;
	struct kcxi_domain *domain;
	void *queue;
	size_t queue_len;
	struct kcxi_md *queue_md;
	struct cxi_eq *eq;
	struct kcxi_cq_entry *priority_entries;
	struct list_head event_list;
	struct list_head error_list;
	struct list_head entry_free_list;
	spinlock_t entry_list_lock;
	spinlock_t entry_free_list_lock;
	atomic_t priority_entry_cnt;
	atomic_t overflow_entry_cnt;
	atomic_t overrun_cnt;
	atomic_t ref_cnt;
	cq_report_completion report_completion;
	cq_report_error report_error;
	cq_buffer_id_map buffer_id_map;
	cq_buffer_id_unmap buffer_id_unmap;
	struct idr buffer_id_table;
	spinlock_t table_lock;
	bool armed;
	struct work_struct work;
	struct mutex processing_eq_lock;
	struct c_eq_status prev_eq_status;
	bool eq_saturated;
	struct kcxi_md_cache md_cache;
};

#define KCXI_PTLTE_INDEX(ptlte) ((ptlte)->pte->id)

/**
 * struct kcxi_ptlte - Portal table entry
 * @entry: PtlTE list entry
 * @dom_if: kCXI domain interface PtlTE was allocated against
 * @pid_index: Index of the PtlTE
 * @ptn: PtlTE entry id
 * @put_pt_index: Put command PtlTE index
 * @get_pt_index: Get command PtlTE index
 * @pte: Core PtlTE
 * @state: State of the PtlTE
 */
struct kcxi_ptlte {
	struct list_head entry;
	struct kcxi_domain_if *dom_if;
	unsigned int pid_index;
	unsigned int put_pt_index;
	unsigned int get_pt_index;
	struct cxi_pte *pte;
	enum c_ptlte_state state;
};

/**
 * struct kcxi_cmdq - Target and transmit command queue
 * @kcxi_if: kCXI interface command queue was allocated against
 * @cmdq: The hardware command queue
 * @lock: Lock protecting the hardware command queue
 */
struct kcxi_cmdq {
	struct kcxi_if *kcxi_if;
	struct kcxi_cp *cp;
	struct cxi_cq *cmdq;
	spinlock_t lock;
};

static inline void kcxi_cmdq_lock(struct kcxi_cmdq *cq)
{
	spin_lock(&cq->lock);
}

static inline void kcxi_cmdq_unlock(struct kcxi_cmdq *cq)
{
	spin_unlock(&cq->lock);
}

static inline int kcxi_cmdq_emit_dma_lockless(struct kcxi_cmdq *transmit,
					      struct c_full_dma_cmd *cmd)
{
	return cxi_cq_emit_dma(transmit->cmdq, cmd);
}

static inline void kcxi_cmdq_ring_lockless(struct kcxi_cmdq *cq)
{
	cxi_cq_ring(cq->cmdq);
}

struct kcxi_ep_attr;

/**
 * struct kcxi_mr_domain - MR domain.
 * @cq: MR completion queue.
 * @target: MR target command queue.
 * @ptlte: PtlTE for MRs.
 * @with_remote_rma_events: Whether or not completion queue remote RMA events
 * should be generated.
 * @with_mr_events: Whether or not MR events, match, put, and get should be
 * generated.
 * @mr_hash: Hashtable of registered MRs.
 *
 * MR domains are use to enforce MR key uniqueness on a per MR domain basis. In
 * addition, MR domains provide the interface to register and deregister MRs
 * with the NIC.
 */
struct kcxi_mr_domain {
	struct kcxi_cq *cq;
	struct kcxi_cmdq *target;
	struct kcxi_ptlte *ptlte;
	bool with_remote_rma_events;
	bool with_mr_events;
	struct rhashtable mr_hash;
};

/**
 * struct kcxi_rx_ctx - kCXI RX context
 * @ctx: RX context OFI endpoint
 * @attr: The rx attributes
 * @rx_id: Index into SEP RX context array
 * @enabled: RX CTX is enabled for data transfer operations
 * @suppress_events: Selectively acknowledge events
 * @rendezvous_enabled: Use rendezvous operations
 * @num_left: Number of recv buffers that can be posted
 * @min_multi_recv: Minimum size of multi recv buffers
 * @ep_attr: SEP attributes
 * @recv_cq: Completion queue bound to the RX context
 * @target: Target side commands
 * @ptlte: Portal table entry
 * @lock: Lock protecting context
 * @mr_domain: MRs enabled against an RX context
 * @ref_cnt: Reference/bind counter
 * @posted_rx_list: List of post recv descriptors
 * @posted_rx_cnt: Number of posted receive buffers
 * @post_rx_lock: Lock protecting posted recv list
 */
struct kcxi_rx_ctx {
	struct kfid_ep ctx;
	struct kfi_rx_attr attr;
	unsigned int rx_id;
	bool enabled;
	bool suppress_events;
	bool rendezvous_enabled;
	bool directed_recv;
	size_t num_left;
	size_t min_multi_recv;
	struct kcxi_ep_attr *ep_attr;
	struct kcxi_cq *recv_cq;
	struct kcxi_cmdq *target;
	struct kcxi_ptlte *ptlte;
	struct mutex lock;
	struct kcxi_mr_domain *mr_domain;
	atomic_t ref_cnt;

	/* TODO: Look into RCU to avoid locks? */
	struct list_head posted_rx_list;
	atomic_t posted_rx_cnt;
	spinlock_t post_rx_lock;

	/* Software counters. */
	atomic64_t command_queue_full;
	atomic64_t completion_queue_saturated;

	struct dentry *rxc_debugfs_dir;
};

/**
 * struct kcxi_tx_ctx - kCXI TX context
 * @ctx: TX context OFI endpoint
 * @attr: The tx attributes
 * @tx_id: Index into SEP TX context array
 * @enabled: TX CTX is enabled for data transfer operations
 * @suppress_events: Selectively acknowledge events
 * @rendezvous_enabled: Use rendezvous operations
 * @ep_attr: SEP attributes
 * @send_cq: Completion queue bound to the TX context
 * @transmit: Transmit commands
 * @lock: Lock protecting TX context
 * @posted_tx_cnt: Number of post transmit operations
 */
struct kcxi_tx_ctx {
	struct kfid_ep ctx;
	struct kfi_tx_attr attr;
	unsigned int tx_id;
	bool enabled;
	bool suppress_events;
	bool rendezvous_enabled;
	struct kcxi_ep_attr *ep_attr;
	struct kcxi_cq *send_cq;
	struct kcxi_cmdq *transmit;
	struct mutex lock;
	atomic_t posted_tx_cnt;

	/* Software counters. */
	atomic64_t command_queue_full;
	atomic64_t completion_queue_saturated;
	atomic64_t rnr_retries;
	atomic64_t rnr_retries_send;
	atomic64_t rnr_retries_rma;

	struct dentry *txc_debugfs_dir;
};

/**
 * struct kcxi_ep_attr - SEP attributes
 * @av: AV bound to SEP
 * @domain: Domain the SEP was allocated against
 * @ps: The port space the SEP is utilizing
 * @rx_array: Array of RX contexts
 * @tx_array: Array of TX contexts
 * @num_rx_ctx: Number of allocated RX contexts
 * @num_tx_ctx: Number of allocated TX contexts
 * @info: Info structure
 * @attr: EP attributes
 * @addr: The kCXI address this SEP is using
 * @is_enabled: Whether or not the SEP is enabled
 * @lock: Lock protecting SEP attributes
 * @auth_key: Endpoint authorization key
 */
struct kcxi_ep_attr {
	struct kcxi_av *av;
	struct kcxi_domain *domain;
	struct kcxi_domain_if *dom_if;
	struct kcxi_rx_ctx **rx_array;
	struct kcxi_tx_ctx **tx_array;
	atomic_t num_rx_ctx;
	atomic_t num_tx_ctx;
	uint64_t caps;
	struct kfi_ep_attr attr;
	bool is_enabled;
	struct mutex lock;
	uint32_t auth_key;
};

/**
 * struct kcxi_ep - SEP
 * @ep: OFI SEP
 * @ep_attr: SEP attributes
 * @tx_attr: TX attributes
 * @rx_attr: RX attributes
 */
struct kcxi_ep {
	struct kfid_ep ep;
	struct kcxi_ep_attr ep_attr;
	struct kfi_tx_attr tx_attr;
	struct kfi_rx_attr rx_attr;
};

enum kcxi_mr_state {
	MR_LINKED = 1,
	MR_UNLINKED,
	MR_ERROR
};

/**
 * struct kcxi_mr - kCXI memory region.
 * @node: MR node in MR domain hashtable.
 * @mr_fid: Kfabric user fid.
 * @req: MR request state used for MR event processing.
 * @dom: Domain MR was allocate against.
 * @rx_ctx: RX context MR is bound to.
 * @md: CXI memory descriptor.
 * @eq: Event queue used for async registration events.
 * @len: Length of MR.
 * @access: Kfabric access flags.
 * @buffer_id: BUffer ID the req was mapped into.
 * @state: The state of the MR.
 * @match_event_count: Number match events for this MR.
 * @rma_event_count: Number of RMA events for this MR.
 * @enabled: MR is enabled/disabled.
 *
 * The kCXI provider requires MRs to be bound to a RX context. Only once bound,
 * can the MR be enabled.
 */
struct kcxi_mr {
	struct rhash_head node;
	struct kfid_mr mr_fid;
	struct kcxi_req_state req;
	struct kcxi_domain *dom;
	struct kcxi_rx_ctx *rx_ctx;
	struct kcxi_md *md;
	struct kcxi_eq *eq;
	uint64_t access;
	unsigned int buffer_id;
	enum kcxi_mr_state state;
	atomic_t match_event_count;
	atomic_t rma_event_count;
	bool enabled;
};

/**
 * struct kcxi_tx_desc - Transmit descriptor
 * @tx_ctx: Transmit context
 * @md: Memory descriptor
 * @tx_len: Transmit length
 * @suppress_events: Suppress kfabric events
 * @req: Request state
 */
struct kcxi_tx_desc {
	struct kcxi_tx_ctx *tx_ctx;
	struct kcxi_md *md;
	size_t tx_len;
	bool suppress_events;
	struct kcxi_req_state req;
	struct kcxi_addr peer;
	uint32_t offset;
	uint64_t match_bits;
	uint64_t header_data;
	size_t remote_offset;
	ktime_t timeout;
	atomic64_t retries;
	struct work_struct retry;
};

/**
 * kkcxi_rx_ctx_offset() - Get the RX context offset from KFI addr
 * @addr: KFI addr
 * @av: Address vector KFI addr belongs to
 *
 * Return: RX context offset.
 */
static inline unsigned int kcxi_rx_ctx_offset(kfi_addr_t addr,
					      struct kcxi_av *av)
{
	return (addr >> (64 - av->attr.rx_ctx_bits));
}

/**
 * struct kcxi_rx_desc - Receive descriptor
 * @entry: In-flight RX list this descriptor lives on
 * @rx_ctx: Receive context
 * @md: Memory descriptor
 * @buffer_id: Buffer ID
 * @suppress_events: Suppress kfabric events
 * @canceled: Cancel request posted
 * @multi_recv: RX desc is used for a multi recv buffer
 * @rx_byte_count: Received byte count
 * @unlink_byte_count: Unlink byte count
 * @req: Request state
 * @unlinked: Unlink event has occurred
 */
struct kcxi_rx_desc {
	struct list_head entry;
	struct kcxi_rx_ctx *rx_ctx;
	struct kcxi_md *md;
	int buffer_id;
	bool suppress_events;
	bool canceled;
	bool multi_recv;
	size_t rx_byte_count;
	size_t unlink_byte_count;
	struct kcxi_req_state req;
	bool unlinked;
};

/* Functions in kcxi_fabric.c */
char *kcxi_get_domain_name(const struct kcxi_addr *src_addr);
int kcxi_validate_domain_name(const char *name);
int kcxi_verify_info(const struct kfi_info *hints,
		     const struct kcxi_addr *src_addr);
struct kfi_info *kcxi_kfi_info(const struct kfi_info *hints,
			       const struct kcxi_addr *src_addr,
			       const struct kcxi_addr *dest_addr);
int kcxi_getinfo(uint32_t version, const char *node, const char *service,
		 uint64_t flags, struct kfi_info *hints,
		 struct kfi_info **info);
int kcxi_fabric(struct kfi_fabric_attr *attr, struct kfid_fabric **fabric,
		void *context);
int kcxi_get_src_addr(struct kcxi_addr *dest_addr, struct kcxi_addr *src_addr);

/* Functions in kcxi_domain.c */
bool kcxi_valid_domain_src_addr(struct kcxi_domain *dom,
				struct kcxi_addr *addr);
int kcxi_set_domain_attr(const struct kfid_fabric *fabric,
			 const struct kcxi_addr *src_addr,
			 struct kfi_domain_attr *attr, uint64_t caps);
int kcxi_verify_domain_attr(const struct kfid_fabric *fabric,
			    const struct kcxi_addr *src_addr,
			    const struct kfi_domain_attr *attr, uint64_t caps);
int kcxi_domain(struct kfid_fabric *fabric, struct kfi_info *info,
		struct kfid_domain **dom, void *context);

/* Functions in kcxi_ep_rdm.c */
int kcxi_rdm_kfi_info(const struct kcxi_addr *src_addr,
		      const struct kcxi_addr *dest_addr,
		      const struct kfi_info *hints, struct kfi_info **info);
int kcxi_rdm_verify_ep_attr(const struct kfi_ep_attr *ep_attr,
			    const struct kfi_tx_attr *tx_attr,
			    const struct kfi_rx_attr *rx_attr, uint64_t caps);
int kcxi_rdm_sep(struct kfid_domain *domain, struct kfi_info *info,
		 struct kfid_ep **sep, void *context);
void kcxi_rdm_set_rx_attr(struct kfi_rx_attr *attr, uint64_t caps);
int kcxi_rdm_verify_rx_attr(const struct kfi_rx_attr *attr, uint64_t caps);
void kcxi_rdm_set_tx_attr(struct kfi_tx_attr *attr, uint64_t caps);
int kcxi_rdm_verify_tx_attr(const struct kfi_tx_attr *attr, uint64_t caps);

/* Functions in cxi_eq.c */
int kcxi_eq_report_event(struct kcxi_eq *cxi_eq, uint32_t type,
			 const struct kfi_eq_entry *event);
int kcxi_eq_report_error(struct kcxi_eq *cxi_eq,
			 const struct kfi_eq_err_entry *error);
int kcxi_eq_open(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
		 struct kfid_eq **eq, kfi_event_handler event_handler,
		 void *context);
void kcxi_eq_raise_handler(struct kcxi_eq *eq);

/* Functions in kcxi_av.c */
kfi_addr_t kcxi_av_reverse_lookup(struct kcxi_av *av, uint32_t nic,
				  uint16_t pid);
int kcxi_av_open(struct kfid_domain *domain, struct kfi_av_attr *attr,
		 struct kfid_av **av, void *context);

/* Functions in kcxi_cq.c */
bool kcxi_cq_saturated(struct kcxi_cq *cq);
int kcxi_cq_init_cache(void);
void kcxi_cq_destroy_cache(void);
int kcxi_cq_buffer_id_map(struct kcxi_cq *cq, struct kcxi_req_state *req);
void kcxi_cq_buffer_id_unmap(struct kcxi_cq *cq, unsigned int buffer_id);
int kcxi_cq_open(struct kfid_domain *domain, struct kfi_cq_attr *attr,
		 struct kfid_cq **cq, kfi_comp_handler comp_handler,
		 void *context);

/* Functions in kcxi_ep.c */
int kcxi_ep_alloc(struct kfid_domain *domain, struct kfi_info *info,
		  struct kfi_ep_attr *ep_attr, struct kfi_tx_attr *tx_attr,
		  struct kfi_rx_attr *rx_attr, struct kcxi_ep **ep,
		  void *context, size_t fclass);
void kcxi_ep_release_tx_index(struct kcxi_ep_attr *ep_attr,
			      unsigned int index);
void kcxi_ep_release_rx_index(struct kcxi_ep_attr *ep_attr,
			      unsigned int index);

/* Functions in kcxi_rx_ctx.c */
kfi_addr_t kcxi_rx_ctx_src_addr(struct kcxi_rx_ctx *rx_ctx, uint32_t initiator);
struct kcxi_rx_ctx *kcxi_rx_ctx_alloc(const struct kfi_rx_attr *attr,
				      unsigned int index,
				      struct kcxi_ep_attr *ep_attr,
				      void *context);
int kcxi_rx_ctx_bind_mr(struct kcxi_rx_ctx *rx_ctx, struct kcxi_mr *mr);
void kcxi_rx_ctx_unbind_mr(struct kcxi_rx_ctx *rx_ctx, struct kcxi_mr *mr);

/* Functions in kcxi_tx_ctx.c */
struct kcxi_tx_ctx *kcxi_tx_ctx_alloc(const struct kfi_tx_attr *attr,
				      unsigned int index,
				      struct kcxi_ep_attr *ep_attr,
				      void *context);

/* Functions in kcxi_ptlte.c */
void kcxi_ptlte_set_state(struct kcxi_if *kcxi_if, unsigned int ptn,
			  enum c_ptlte_state state);
void kcxi_ptlte_free(struct kcxi_ptlte *ptlte);
struct kcxi_ptlte *kcxi_ptlte_alloc(struct kcxi_domain_if *dom_if,
				    struct kcxi_cq *cq, unsigned int pid_offset,
				    struct cxi_pt_alloc_opts *opts);
int kcxi_ptlte_enable(struct kcxi_ptlte *ptlte, struct kcxi_cmdq *target);
int kcxi_ptlte_disable(struct kcxi_ptlte *ptlte, struct kcxi_cmdq *target);

/* Functions in cxi_cmdq.c */
void kcxi_cmdq_free(struct kcxi_cmdq *cxi_cmdq);
struct kcxi_cmdq *kcxi_cmdq_transmit_alloc(struct kcxi_if *kcxi_if,
					   unsigned int count,
					   unsigned int auth_key,
					   enum cxi_traffic_class tc,
					   int numa_node);
struct kcxi_cmdq *kcxi_cmdq_target_alloc(struct kcxi_if *kcxi_if,
					 unsigned int count,
					 int numa_node);
int kcxi_cmdq_emit_target(struct kcxi_cmdq *target, const void *cmd);
int kcxi_cmdq_emit_dma(struct kcxi_cmdq *transmit, struct c_full_dma_cmd *cmd);
void kcxi_cmdq_ring(struct kcxi_cmdq *cq);

/* Functions in kcxi_mr_domain.c */
void kcxi_mr_domain_wake_up(void);
int kcxi_mr_domain_unlink(struct kcxi_mr_domain *mr_domain, struct kcxi_mr *mr);
int kcxi_mr_domain_link(struct kcxi_mr_domain *mr_domain, struct kcxi_mr *mr);
int kcxi_mr_domain_register(struct kcxi_mr_domain *mr_domain,
			    struct kcxi_mr *mr);
void kcxi_mr_domain_deregister(struct kcxi_mr_domain *mr_domain,
			       struct kcxi_mr *mr);
int kcxi_mr_domain_buffer_id_map(struct kcxi_mr_domain *mr_domain,
				 struct kcxi_req_state *req);
void kcxi_mr_domain_buffer_id_unmap(struct kcxi_mr_domain *mr_domain,
				    unsigned int buffer_id);
struct kcxi_mr_domain *kcxi_mr_domain_alloc(struct kcxi_cq *cq,
					    struct kcxi_cmdq *target,
					    struct kcxi_ptlte *ptlte,
					    bool with_remote_rma_events,
					    bool with_match_events,
					    size_t table_size);
int kcxi_mr_domain_free(struct kcxi_mr_domain *mr_domain);

/* Functions in kcxi_mr.c */
int kcxi_mr_regsgl(struct kfid *fid, const struct scatterlist *sgl, size_t count,
		  uint64_t access, uint64_t offset, uint64_t requested_key,
		  uint64_t flags, struct kfid_mr **mr, void *context);
int kcxi_mr_regbv(struct kfid *fid, const struct bio_vec *biov, size_t count,
		  uint64_t access, uint64_t offset, uint64_t requested_key,
		  uint64_t flags, struct kfid_mr **mr, void *context);
int kcxi_mr_regv(struct kfid *fid, const struct kvec *iov, size_t count,
		 uint64_t access, uint64_t offset, uint64_t requested_key,
		 uint64_t flags, struct kfid_mr **mr, void *context);
int kcxi_mr_reg(struct kfid *fid, const void *buf, size_t len, uint64_t access,
		uint64_t offset, uint64_t requested_key, uint64_t flags,
		struct kfid_mr **mr, void *context);

/* Functions in kcxi_md.c */
void kcxi_md_free(struct kcxi_md *md);
void kcxi_md_cache_populate(struct kcxi_cq *kcxi_cq);
void kcxi_md_cache_flush(struct kcxi_cq *kcxi_cq);
struct kcxi_md *kcxi_md_sgl_alloc(struct kcxi_if *kcxi_if,
				  struct kcxi_cq *kcxi_cq,
				  const struct scatterlist *sgl, size_t count,
				  uint64_t offset, uint32_t flags);
struct kcxi_md *kcxi_md_biov_alloc(struct kcxi_if *kcxi_if,
				   struct kcxi_cq *kcxi_cq,
				   const struct bio_vec *biov, size_t count,
				   uint64_t offset, uint32_t flags);
struct kcxi_md *kcxi_md_iov_alloc(struct kcxi_if *kcxi_if,
				  struct kcxi_cq *kcxi_cq,
				  const struct kvec *iov, size_t count,
				  uint64_t offset, uint32_t flags);
struct kcxi_md *kcxi_md_alloc(struct kcxi_if *kcxi_if,
			      struct kcxi_cq *kcxi_cq, const void *buf,
			      size_t len, uint64_t offset, uint32_t flags,
			      bool cacheable, bool force_cxi_map);
void *kcxi_md_to_va(struct kcxi_md *md, dma_addr_t cur_addr);
int kcxi_md_init_cache(void);
void kcxi_md_destroy_cache(void);

/* Functions in kcxi_rma_ops.c */
ssize_t kcxi_rma_writemsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
			  uint64_t flags);
ssize_t kcxi_rma_readmsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
			 uint64_t flags);
ssize_t kcxi_rma_writesgl(struct kfid_ep *ep, const struct scatterlist *sgl,
			 void **desc, size_t count, kfi_addr_t dest_addr,
			 uint64_t addr, uint64_t key, void *context);
ssize_t kcxi_rma_readsgl(struct kfid_ep *ep, const struct scatterlist *sgl,
			void **desc, size_t count, kfi_addr_t src_addr,
			uint64_t addr, uint64_t key, void *context);
ssize_t kcxi_rma_writebv(struct kfid_ep *ep, const struct bio_vec *biov,
			 void **desc, size_t count, kfi_addr_t dest_addr,
			 uint64_t addr, uint64_t key, void *context);
ssize_t kcxi_rma_readbv(struct kfid_ep *ep, const struct bio_vec *biov,
			void **desc, size_t count, kfi_addr_t src_addr,
			uint64_t addr, uint64_t key, void *context);
ssize_t kcxi_rma_writev(struct kfid_ep *ep, const struct kvec *iov, void **desc,
			size_t count, kfi_addr_t dest_addr, uint64_t addr,
			uint64_t key, void *context);
ssize_t kcxi_rma_readv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
		       size_t count, kfi_addr_t src_addr, uint64_t addr,
		       uint64_t key, void *context);
ssize_t kcxi_rma_write(struct kfid_ep *ep, const void *buf, size_t len,
		       void *desc, kfi_addr_t dest_addr, uint64_t addr,
		       uint64_t key, void *context);
ssize_t kcxi_rma_read(struct kfid_ep *ep, void *buf, size_t len, void *desc,
		      kfi_addr_t src_addr, uint64_t addr, uint64_t key,
		      void *context);

/* Functions in kcxi_dev.c */
int kcxi_dev_first_nic(void);
int kcxi_dev_fabric(unsigned int nic);
int kcxi_dev_index_to_addr(unsigned int index);
int kcxi_dev_index(unsigned int nic);
bool kcxi_dev_nic_exists(unsigned int nic);
bool kcxi_dev_fabric_exists(unsigned int fabric);
bool kcxi_dev_index_exists(unsigned int index);
bool kcxi_dev_ready(struct kcxi_dev *kdev);

/* Functions in kcxi_prov.c */
ssize_t kcxi_dev_nic_array(unsigned int **nic_array);
int kcxi_dev_add(struct cxi_dev *cdev);
void kcxi_dev_remove(struct cxi_dev *cdev);
struct kcxi_dev *kcxi_dev_get(unsigned int nic);
void kcxi_dev_put(struct kcxi_dev *kdev);
void kcxi_async_event(struct cxi_dev *cdev, enum cxi_async_event event);

/* Functions in kcxi_if.c */
struct kcxi_if *kcxi_if_alloc(unsigned int nic, const struct kfid_fabric *fabric, const struct kfi_info *info);
int kcxi_if_free(struct kcxi_if *kcxi_if);

/* Functions in kcxi_domain_if.c */
int kcxi_domain_if_index_reserve(struct kcxi_domain_if *dom_if,
				 unsigned int index);
void kcxi_domain_if_index_release(struct kcxi_domain_if *dom_if,
				  unsigned int index);
struct kcxi_domain_if *kcxi_domain_if_alloc(struct kcxi_if *kcxi_if,
					    unsigned int auth_key,
					    unsigned int pid);
int kcxi_domain_if_free(struct kcxi_domain_if *cxi_dom_if);

/* Functions in kcxi_recv_ops.c */
ssize_t kcxi_msg_recvmsg(struct kfid_ep *ep, const struct kfi_msg *msg,
			 uint64_t flags);
ssize_t kcxi_msg_recvsgl(struct kfid_ep *ep, const struct scatterlist *sgl,
			void **desc, size_t count, kfi_addr_t src_addr,
			void *context);
ssize_t kcxi_msg_recvbv(struct kfid_ep *ep, const struct bio_vec *biov,
			void **desc, size_t count, kfi_addr_t src_addr,
			void *context);
ssize_t kcxi_msg_recvv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
		       size_t count, kfi_addr_t src_addr, void *context);
ssize_t kcxi_msg_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
		      kfi_addr_t src_addr, void *context);
ssize_t kcxi_tagged_recvmsg(struct kfid_ep *ep,
			    const struct kfi_msg_tagged *msg, uint64_t flags);
ssize_t kcxi_tagged_recvsgl(struct kfid_ep *ep, const struct scatterlist *sgl,
			   void **desc, size_t count, kfi_addr_t src_addr,
			   uint64_t tag, uint64_t ignore, void *context);
ssize_t kcxi_tagged_recvbv(struct kfid_ep *ep, const struct bio_vec *biov,
			   void **desc, size_t count, kfi_addr_t src_addr,
			   uint64_t tag, uint64_t ignore, void *context);
ssize_t kcxi_tagged_recvv(struct kfid_ep *ep, const struct kvec *iov,
			  void **desc, size_t count, kfi_addr_t src_addr,
			  uint64_t tag, uint64_t ignore, void *context);
ssize_t kcxi_tagged_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
			 kfi_addr_t src_addr, uint64_t tag, uint64_t ignore,
			 void *context);

/* Functions in kcxi_send_ops.c */
ssize_t kcxi_msg_sendmsg(struct kfid_ep *ep, const struct kfi_msg *msg,
			 uint64_t flags);
ssize_t kcxi_msg_sendsgl(struct kfid_ep *ep, const struct scatterlist *sgl,
			void **desc, size_t count, kfi_addr_t dest_addr,
			void *context);
ssize_t kcxi_msg_sendbv(struct kfid_ep *ep, const struct bio_vec *biov,
			void **desc, size_t count, kfi_addr_t dest_addr,
			void *context);
ssize_t kcxi_msg_sendv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
		       size_t count, kfi_addr_t dest_addr, void *context);
ssize_t kcxi_msg_send(struct kfid_ep *ep, const void *buf, size_t len,
		      void *desc, kfi_addr_t dest_addr, void *context);
ssize_t kcxi_tagged_sendmsg(struct kfid_ep *ep,
			    const struct kfi_msg_tagged *msg, uint64_t flags);
ssize_t kcxi_tagged_sendsgl(struct kfid_ep *ep, const struct scatterlist *sgl,
			   void **desc, size_t count, kfi_addr_t dest_addr,
			   uint64_t tag, void *context);
ssize_t kcxi_tagged_sendbv(struct kfid_ep *ep, const struct bio_vec *biov,
			   void **desc, size_t count, kfi_addr_t dest_addr,
			   uint64_t tag, void *context);
ssize_t kcxi_tagged_sendv(struct kfid_ep *ep, const struct kvec *iov,
			  void **desc, size_t count, kfi_addr_t dest_addr,
			  uint64_t tag, void *context);
ssize_t kcxi_tagged_send(struct kfid_ep *ep, const void *buf, size_t len,
			 void *desc, kfi_addr_t dest_addr, uint64_t tag,
			 void *context);
ssize_t kcxi_tagged_senddata(struct kfid_ep *ep, const void *buf, size_t len,
			     void *desc, uint64_t data, kfi_addr_t dest_addr,
			     uint64_t tag, void *context);

/* Functions in kcxi_addr_res.c */
typedef void (*kcxi_addr_res_async_cb)(uint32_t nic, uint16_t pid, int rc,
				       void *context);

int kcxi_addr_res_node_src(const char *node);
int kcxi_addr_res_src_info(const char *node, const char *service,
			   struct kcxi_addr *addr);
int kcxi_addr_res_dest_info(const char *node, const char *service,
			    struct kcxi_addr *addr);
int kcxi_addr_res_dest_info_async(const char *node, const char *service,
				  kcxi_addr_res_async_cb cb, void *context);

/* Functions in kcxi_res_entry.c */
struct kcxi_arp_res_entry {
	u64 dest_mac_addr;
	void *context;
};

typedef void (*kcxi_arp_res_entry_cb) (struct kcxi_arp_res_entry *entry,
				       int rc);

struct kcxi_arp_res_entry *kcxi_arp_res_entry_alloc(__be32 src_addr,
						    __be32 dest_addr,
						    kcxi_arp_res_entry_cb cb,
						    void *context);
void kcxi_arp_res_entry_free(struct kcxi_arp_res_entry *entry);
int kcxi_arp_res_entry_resolve(struct kcxi_arp_res_entry *entry);
int kcxi_arp_res_init(void);
void kcxi_arp_res_fini(void);

/* Functions in kcxi_tx_desc.c */
void kcxi_tx_desc_free(struct kcxi_tx_desc *tx_desc);
struct kcxi_tx_desc *kcxi_tx_desc_alloc(struct kcxi_tx_ctx *tx_ctx);
int kcxi_tx_desc_init_cache(void);
void kcxi_tx_desc_destroy_cache(void);

/* Functions in kcxi_rx_desc.c */
void kcxi_rx_desc_free(struct kcxi_rx_desc *rx_desc);
struct kcxi_rx_desc *kcxi_rx_desc_alloc(struct kcxi_rx_ctx *rx_ctx);
int kcxi_rx_desc_init_cache(void);
void kcxi_rx_desc_destroy_cache(void);

/* Functions in kcxi_cp.c */
struct kcxi_cp *kcxi_cp_alloc(struct kcxi_if *kcxi_if, unsigned int auth_key,
			      enum cxi_traffic_class tc);
void kcxi_cp_free(struct kcxi_cp *cp);

#endif /* _KCXI_PROV_H_ */
