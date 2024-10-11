/*
 * Copyright (c) 2013-2016 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _KFI_DOMAIN_H_
#define _KFI_DOMAIN_H_

#include <kfabric.h>
#include <kfi_eq.h>

/*
 * AV = Address Vector
 * Maps and stores transport/network addresses.
 */

#define KFI_SYMMETRIC		(1ULL << 59)
#define KFI_SYNC_ERR		(1ULL << 58)

struct kfi_av_attr {
	enum kfi_av_type	type;
	int			rx_ctx_bits;
	size_t			count;
	size_t			ep_per_node;
	const char		*name;
	void			*map_addr;
	uint64_t		flags;
};

struct kfi_ops_av {
	size_t	size;
	int	(*insert)(struct kfid_av *av, const void *addr, size_t count,
			  kfi_addr_t *kfi_addr, uint64_t flags, void *context);
	int	(*insertsvc)(struct kfid_av *av, const char *node,
			     const char *service, kfi_addr_t *kfi_addr,
			     uint64_t flags, void *context);
	int	(*insertsym)(struct kfid_av *av, const char *node,
			     size_t nodecnt, const char *service, size_t svccnt,
			     kfi_addr_t *kfi_addr, uint64_t flags,
			     void *context);
	int	(*remove)(struct kfid_av *av, kfi_addr_t *kfi_addr,
			  size_t count, uint64_t flags);
	int	(*lookup)(struct kfid_av *av, kfi_addr_t kfi_addr, void *addr,
			  size_t *addrlen);
	const char * (*straddr)(struct kfid_av *av, const void *addr,
				char *buf, size_t *len);
};

struct kfid_av {
	struct kfid		fid;
	struct kfi_ops_av	*ops;
};


/*
 * MR = Memory Region
 * Tracks registered memory regions, primarily for remote access,
 * but also for local access until we can remove that need.
 */
struct kfid_mr {
	struct kfid		fid;
	void			*mem_desc;
	uint64_t		key;
	uint64_t		iova;
};

struct kfi_mr_attr {
	enum kfi_iov_type	type;
	union {
		const struct kvec	*mr_iov;
		const struct bio_vec	*mr_biov;
	};
	size_t			iov_count;
	uint64_t		access;
	uint64_t		offset;
	uint64_t		requested_key;
	void			*context;
	size_t			auth_key_size;
	uint8_t			*auth_key;
};

struct kfi_mr_modify {
	uint64_t		flags;
	struct kfi_mr_attr	attr;
};

enum kfi_datatype {
	KFI_INT8,
	KFI_UINT8,
	KFI_INT16,
	KFI_UINT16,
	KFI_INT32,
	KFI_UINT32,
	KFI_INT64,
	KFI_UINT64,
	KFI_FLOAT,
	KFI_DOUBLE,
	KFI_FLOAT_COMPLEX,
	KFI_DOUBLE_COMPLEX,
	KFI_LONG_DOUBLE,
	KFI_LONG_DOUBLE_COMPLEX,
	KFI_DATATYPE_LAST
};

enum kfi_op {
	KFI_MIN,
	KFI_MAX,
	KFI_SUM,
	KFI_PROD,
	KFI_LOR,
	KFI_LAND,
	KFI_BOR,
	KFI_BAND,
	KFI_LXOR,
	KFI_BXOR,
	KFI_ATOMIC_READ,
	KFI_ATOMIC_WRITE,
	KFI_CSWAP,
	KFI_CSWAP_NE,
	KFI_CSWAP_LE,
	KFI_CSWAP_LT,
	KFI_CSWAP_GE,
	KFI_CSWAP_GT,
	KFI_MSWAP,
	KFI_ATOMIC_OP_LAST
};

struct kfi_atomic_attr;
struct kfi_cq_attr;
struct kfi_cntr_attr;


struct kfi_ops_domain {
	size_t	size;
	int	(*av_open)(struct kfid_domain *domain, struct kfi_av_attr *attr,
			struct kfid_av **av, void *context);
	int	(*cq_open)(struct kfid_domain *domain, struct kfi_cq_attr *attr,
			struct kfid_cq **cq, kfi_comp_handler comp_handler,
			void *context);
	int	(*endpoint)(struct kfid_domain *domain, struct kfi_info *info,
			struct kfid_ep **ep, void *context);
	int	(*scalable_ep)(struct kfid_domain *domain,
			struct kfi_info *info, struct kfid_ep **sep,
			void *context);
	int	(*cntr_open)(struct kfid_domain *domain,
			struct kfi_cntr_attr *attr, struct kfid_cntr **cntr,
			void *context);
	int	(*poll_open)(struct kfid_domain *domain,
			struct kfi_poll_attr *attr, struct kfid_poll **pollset);
	int	(*stx_ctx)(struct kfid_domain *domain,
			struct kfi_tx_attr *attr, struct kfid_stx **stx,
			void *context);
	int	(*srx_ctx)(struct kfid_domain *domain,
			struct kfi_rx_attr *attr, struct kfid_ep **rx_ep,
			void *context);
	int	(*query_atomic)(struct kfid_domain *domain,
			enum kfi_datatype datatype, enum kfi_op op,
			struct kfi_atomic_attr *attr, uint64_t flags);
};

struct kfi_ops_mr {
	size_t	size;
	int	(*reg)(struct kfid *fid, const void *buf, size_t len,
			uint64_t access, uint64_t offset,
			uint64_t requested_key, uint64_t flags,
			struct kfid_mr **mr, void *context);
	int	(*regv)(struct kfid *fid, const struct kvec *iov,
			size_t count, uint64_t access,
			uint64_t offset, uint64_t requested_key,
			uint64_t flags, struct kfid_mr **mr, void *context);
	int	(*regbv)(struct kfid *fid, const struct bio_vec *biov,
			 size_t count, uint64_t access,
			 uint64_t offset, uint64_t requested_key,
			 uint64_t flags, struct kfid_mr **mr, void *context);
	int	(*regattr)(struct kfid *fid, const struct kfi_mr_attr *attr,
			uint64_t flags, struct kfid_mr **mr);
};

/* Domain bind flags */
#define KFI_REG_MR	(1ULL << 59)

struct kfid_domain {
	struct kfid		fid;
	struct kfi_ops_domain	*ops;
	struct kfi_ops_mr	*mr;
};


#ifndef KFABRIC_DIRECT

static inline int
kfi_domain(struct kfid_fabric *fabric, struct kfi_info *info,
	   struct kfid_domain **domain, void *context)
{
	return fabric->ops->domain(fabric, info, domain, context);
}

static inline int
kfi_domain_bind(struct kfid_domain *domain, struct kfid *fid, uint64_t flags)
{
	return domain->fid.ops->bind(&domain->fid, fid, flags);
}

static inline int
kfi_cq_open(struct kfid_domain *domain, struct kfi_cq_attr *attr,
	   struct kfid_cq **cq, kfi_comp_handler comp_handler, void *context)
{
	return domain->ops->cq_open(domain, attr, cq, comp_handler, context);
}

static inline int
kfi_cntr_open(struct kfid_domain *domain, struct kfi_cntr_attr *attr,
	      struct kfid_cntr **cntr, void *context)
{
	return domain->ops->cntr_open(domain, attr, cntr, context);
}

static inline int
kfi_wait_open(struct kfid_fabric *fabric, struct kfi_wait_attr *attr,
	      struct kfid_wait **waitset)
{
	return fabric->ops->wait_open(fabric, attr, waitset);
}

static inline int
kfi_poll_open(struct kfid_domain *domain, struct kfi_poll_attr *attr,
	      struct kfid_poll **pollset)
{
	return domain->ops->poll_open(domain, attr, pollset);
}

static inline int
kfi_mr_reg(struct kfid_domain *domain, const void *buf, size_t len,
	   uint64_t access, uint64_t offset, uint64_t requested_key,
	   uint64_t flags, struct kfid_mr **mr, void *context)
{
	return domain->mr->reg(&domain->fid, buf, len, access, offset,
			       requested_key, flags, mr, context);
}

static inline int
kfi_mr_regv(struct kfid_domain *domain, const struct kvec *iov, size_t count,
	    uint64_t access, uint64_t offset, uint64_t requested_key,
	    uint64_t flags, struct kfid_mr **mr, void *context)
{
	return domain->mr->regv(&domain->fid, iov, count, access, offset,
				requested_key, flags, mr, context);
}

static inline int
kfi_mr_regbv(struct kfid_domain *domain, const struct bio_vec *biov,
	     size_t count, uint64_t access, uint64_t offset,
	     uint64_t requested_key, uint64_t flags, struct kfid_mr **mr,
	     void *context)
{
	return domain->mr->regbv(&domain->fid, biov, count, access, offset,
				requested_key, flags, mr, context);
}

static inline int
kfi_mr_regattr(struct kfid_domain *domain, const struct kfi_mr_attr *attr,
	       uint64_t flags, struct kfid_mr **mr)
{
	return domain->mr->regattr(&domain->fid, attr, flags, mr);
}

static inline void *kfi_mr_desc(struct kfid_mr *mr)
{
	return mr->mem_desc;
}

static inline uint64_t kfi_mr_key(struct kfid_mr *mr)
{
	return mr->key;
}

static inline int
kfi_mr_raw_attr(struct kfid_mr *mr, uint64_t *base_addr,
		uint8_t *raw_key, size_t *key_size, uint64_t flags)
{
	struct kfi_mr_raw_attr attr = {
		.flags = flags,
		.base_addr = base_addr,
		.raw_key = raw_key,
		.key_size = key_size
	};
	return mr->fid.ops->control(&mr->fid, KFI_GET_RAW_MR, &attr);
}

static inline int
kfi_mr_map_raw(struct kfid_domain *domain, uint64_t base_addr,
	       uint8_t *raw_key, size_t key_size, uint64_t *key, uint64_t flags)
{
	struct kfi_mr_map_raw map = {
		.flags = flags,
		.base_addr = base_addr,
		.raw_key = raw_key,
		.key_size = key_size,
		.key = key
	};
	return domain->fid.ops->control(&domain->fid, KFI_MAP_RAW_MR, &map);
}

static inline int
kfi_mr_unmap_key(struct kfid_domain *domain, uint64_t key)
{
	return domain->fid.ops->control(&domain->fid, KFI_UNMAP_KEY, &key);
}

static inline int kfi_mr_bind(struct kfid_mr *mr, struct kfid *bfid,
			      uint64_t flags)
{
	return mr->fid.ops->bind(&mr->fid, bfid, flags);
}

static inline int
kfi_mr_refresh(struct kfid_mr *mr, const struct kvec *iov, size_t count,
	       uint64_t flags)
{
	struct kfi_mr_modify modify = {};

	modify.flags = flags;
	modify.attr.mr_iov = iov;
	modify.attr.iov_count = count;
	return mr->fid.ops->control(&mr->fid, KFI_REFRESH, &modify);
}

static inline int kfi_mr_enable(struct kfid_mr *mr)
{
	return mr->fid.ops->control(&mr->fid, KFI_ENABLE, NULL);
}

static inline int
kfi_av_open(struct kfid_domain *domain, struct kfi_av_attr *attr,
	   struct kfid_av **av, void *context)
{
	return domain->ops->av_open(domain, attr, av, context);
}

static inline int
kfi_av_bind(struct kfid_av *av, struct kfid *fid, uint64_t flags)
{
	return av->fid.ops->bind(&av->fid, fid, flags);
}

static inline int
kfi_av_insert(struct kfid_av *av, const void *addr, size_t count,
	      kfi_addr_t *kfi_addr, uint64_t flags, void *context)
{
	return av->ops->insert(av, addr, count, kfi_addr, flags, context);
}

static inline int
kfi_av_insertsvc(struct kfid_av *av, const char *node, const char *service,
		 kfi_addr_t *kfi_addr, uint64_t flags, void *context)
{
	return av->ops->insertsvc(av, node, service, kfi_addr, flags, context);
}

static inline int
kfi_av_insertsym(struct kfid_av *av, const char *node, size_t nodecnt,
		 const char *service, size_t svccnt,
		 kfi_addr_t *kfi_addr, uint64_t flags, void *context)
{
	return av->ops->insertsym(av, node, nodecnt, service, svccnt,
			kfi_addr, flags, context);
}

static inline int
kfi_av_remove(struct kfid_av *av, kfi_addr_t *kfi_addr, size_t count,
	     uint64_t flags)
{
	return av->ops->remove(av, kfi_addr, count, flags);
}

static inline int
kfi_av_lookup(struct kfid_av *av, kfi_addr_t kfi_addr, void *addr,
	      size_t *addrlen)
{
	return av->ops->lookup(av, kfi_addr, addr, addrlen);
}

static inline const char *
kfi_av_straddr(struct kfid_av *av, const void *addr, char *buf, size_t *len)
{
	return av->ops->straddr(av, addr, buf, len);
}

static inline kfi_addr_t
kfi_rx_addr(kfi_addr_t kfi_addr, int rx_index, int rx_ctx_bits)
{
	return (kfi_addr_t)
		(((uint64_t) rx_index << (64 - rx_ctx_bits)) | kfi_addr);
}


#else /* KFABRIC_DIRECT */
#include <kfi_direct_domain.h>
#endif

#endif /* _KFI_DOMAIN_H_ */
