/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021-2023 Hewlett Packard Enterprise Development LP */

#ifndef _KFI_CXI_EXT_H_
#define _KFI_CXI_EXT_H_

#define KFI_CXI_FAB_OPS_1 "cxi_fab_ops_v1"

struct kfi_cxi_fabric_ops
{
	/* Enable dynamic resource allocation mode during domain allocation.
	 *
	 * When disabled (default) the parameter based resource limits are
	 * reserved for the domain.
	 *
	 * When enabled the parameter based resource limits are overridden
	 * by values provided by the kfi_domain_attr of kfi_info and reserved
	 * for the domain.
	 */
	int (*enable_dynamic_rsrc_alloc)(struct kfid *fid, bool enable);
};

#define KFI_CXI_DOM_OPS_1 "cxi_dom_ops_v1"

struct kfi_cxi_domain_ops
{
	/* Get the basic Linux device associated with this domain.
	 *
	 * fid: Domain FID
	 * device: Output variable for device pointer
	 */
	int (*get_device)(struct kfid *fid, struct device **device);
};

/**
 * struct kcxi_addr - The kCXI addr format
 * @pid: NIC PID
 * @nic: NIC addr
 * @flags: Internal provider flags
 */
struct kcxi_addr {
	union {
		struct {
			uint64_t pid:12;
			uint64_t nic:20;
			uint64_t flags:10;
		};
		uint64_t qw;
	};
};

#endif /* _KFI_CXI_EXT_H_ */
