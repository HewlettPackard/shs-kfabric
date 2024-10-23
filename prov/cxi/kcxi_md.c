//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider memory descriptor functions.
 * Copyright 2019-2024 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/module.h>

#include "kcxi_prov.h"

static bool md_caching = true;
module_param(md_caching, bool, 0444);
MODULE_PARM_DESC(md_caching,
		 "Enable hardware caching of memory descriptor translations. Default is enabled.");
static bool md_cache_enable = true;
module_param(md_cache_enable, bool, 0444);
MODULE_PARM_DESC(md_cache_enable,
		 "Enable software caching of memory descriptors. Default is enabled.");
int md_cache_bufsize = MAX_MD_CACHE_BUFSIZE;
module_param(md_cache_bufsize, int, 0444);
MODULE_PARM_DESC(md_cache_bufsize,
		 "Max size of buffer in md cache. Default is 65536.");

static struct kmem_cache *md_cache;
static int kcxi_md_cache_insert_md(struct kcxi_md *md);

/**
 * kcxi_md_init_cache() - Initialize the memory descriptor cache.
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_md_init_cache(void)
{
	md_cache = kmem_cache_create("kcxi_mds",
				     sizeof(struct kcxi_md), 0,
				     SLAB_HWCACHE_ALIGN, NULL);
	if (!md_cache)
		return -ENOMEM;

	return 0;
}

/**
 * kcxi_md_destroy_cache() - Destroy the memory descriptor cache.
 */
void kcxi_md_destroy_cache(void)
{
	kmem_cache_destroy(md_cache);
}

/**
 * kcxi_md_to_va() - Translate a kCXI memory descriptor into a virtual address.
 * @md: kCXI memory descriptor.
 * @cur_addr: Current address with the kCXI memory descriptor.
 *
 * The current address must be within the allocated kCXI memory descriptor
 * range.
 *
 * Note: If the kCXI memory descriptor was allocated with multiple IOVs, this
 * function will return NULL.
 *
 * Return: On success, valid pointer. Else, NULL.
 */
void *kcxi_md_to_va(struct kcxi_md *md, uint64_t cur_addr)
{
	if (!md || cur_addr > (md->addr + md->len) || md->len == 0)
		return NULL;

	/* Mapped MD is not allocated, use the user_addr to calculate VA. The
	 * user_addr is the in the VA space. cur_addr and md->addr are in the
	 * IOVA space. The offset of the cur_addr and md->addr determines the
	 * offset in the VA space.
	 */
	if (!md->mapped_md)
		return (void *)(md->user_addr + (cur_addr - md->addr));

	/* VA is only set for non-IOV mapping. */
	if (!md->mapped_md->va)
		return NULL;

	return (void *)CXI_IOVA_TO_VA(md->mapped_md, cur_addr);
}

/**
 * kcxi_md_free() - Free a memory descriptor
 * @md: Memory descriptor to be freed
 */
void kcxi_md_free(struct kcxi_md *md)
{
	int rc;

	if (!md)
		return;

	/* Mapped MD is not allocated for kmalloc buffers. */
	if (md->mapped_md) {
		if (kcxi_md_cache_insert_md(md) == 0) // successfully cached
			return;
		rc = cxi_unmap(md->mapped_md);
		if (rc)
			LOG_ERR("Failed to unmap buffer: rc=%d", rc);
	}

	atomic_dec(&md->kcxi_if->md_cur_count);

	KCXI_IF_DEBUG(md->kcxi_if, "addr=%llx len=%lu lac=%u md_cnt=%u",
		      md->addr, md->len, md->lac,
		      atomic_read(&md->kcxi_if->md_cur_count));

	kmem_cache_free(md_cache, md);
}

/**
 * kcxi_md_align_buffer() - Helper function to page align a buffer
 * @buf: Buffer to be aligned
 * @va: Page aligned virtual address to be set
 * @va_offset: Byte offset between buf and va to be set
 */
static void kcxi_md_align_buffer(const void *buf, uintptr_t *va,
				 uint64_t *va_offset)
{
	*va = (uintptr_t)buf & PAGE_MASK;
	*va_offset = (uintptr_t)buf - *va;
}

/**
 * kcxi_md_init() - Initialize MD fields
 * @md: MD
 * @kcxi_if: kCXI interface
 * @kcxi_cq: kCXI completion queue
 * @len: MD length
 * @offset: Offset into MD
 */
static void kcxi_md_init(struct kcxi_md *md, struct kcxi_if *kcxi_if,
			 struct kcxi_cq *kcxi_cq,
			 uint64_t aligned_user_addr, uint64_t aligned_dma_addr,
			 size_t len, uint64_t offset, uint8_t lac, bool cacheable)
{
	int count;
	int max;

	md->kcxi_if = kcxi_if;
	md->kcxi_cq = kcxi_cq;
	md->len = len;
	md->addr = aligned_dma_addr + offset;
	md->lac = lac;
	md->user_addr = aligned_user_addr + offset;
	md->calling_cpu = smp_processor_id();
	md->is_cacheable = cacheable;

	count = atomic_inc_return(&kcxi_if->md_cur_count);

	do {
		max = atomic_read(&md->kcxi_if->md_max_count);
		if (max >= count)
			break;
	} while (atomic_cmpxchg(&md->kcxi_if->md_max_count, max, count) != max);
}

/**
 * kcxi_md_cache_insert_md() - Insert a cleared memory descriptor into the software cache
 * @md: Memory descriptor to be inserted
 */
static int kcxi_md_cache_insert_md(struct kcxi_md *md)
{
	int rc;

	if (!md_cache_enable)
		return -EINVAL;

	if (!md->is_cacheable)
		return -EINVAL;

	if (!md->kcxi_cq)
		return -EINVAL;

	if (md->mapped_md && md->mapped_md->iova) {
		rc = cxi_clear_md(md->mapped_md);
		if (rc) {
			atomic_dec(&md->kcxi_cq->md_cache.md_cached_count);
			atomic_dec(&md->kcxi_cq->domain->kcxi_if->md_cached_count);
			md->is_cacheable = false;
			/* caller will free md */
			CQ_ERR(md->kcxi_cq, "Failed to clear cached md: rc=%d", rc);
			return rc;
		}
	}

	spin_lock(&md->kcxi_cq->md_cache.md_cache_list_lock);
	list_add(&md->entry, &md->kcxi_cq->md_cache.md_cache_list);
	atomic_inc(&md->kcxi_cq->md_cache.md_cached_avail);
	spin_unlock(&md->kcxi_cq->md_cache.md_cache_list_lock);

	CQ_DEBUG(md->kcxi_cq, "addr=%llx len=%lu lac=%u cached_avail=%u", md->addr,
		      md->len, md->lac,
		      atomic_read(&md->kcxi_cq->md_cache.md_cached_avail));

	return 0;
}

/**
 * kcxi_md_cache_remove_md() - Remove a memory descriptor from the software cache and
 * update it for re-use.
 * @kcxi_cq: kCXI completion queue
 * @iter: List of virtual addresses to map - supports ITER_KVEC and ITER_BVEC
 * @len: MD length
 * @offset: Offset into MD
 *
 * Return: Valid pointer on success. Else, error pointer.
 */
static struct kcxi_md *kcxi_md_cache_remove_md(struct kcxi_cq *kcxi_cq,
					struct iov_iter *iter, size_t len, uint64_t offset)
{
	struct kcxi_md *md;
	int rc;
	int cur;
	int max;

	if (!kcxi_cq)
		return ERR_PTR(-EINVAL);

	if (len > kcxi_cq->md_cache.md_cache_bufsize)
		return ERR_PTR(-EINVAL);

	spin_lock(&kcxi_cq->md_cache.md_cache_list_lock);
	md = list_first_entry_or_null(&kcxi_cq->md_cache.md_cache_list, struct kcxi_md, entry);
	if (md) {
		list_del(&md->entry);
		atomic_dec(&kcxi_cq->md_cache.md_cached_avail);
	}
	spin_unlock(&kcxi_cq->md_cache.md_cache_list_lock);

	if (md == NULL)
		return ERR_PTR(-ENOMEM);

	rc = cxi_update_iov(md->mapped_md, iter);
	if (rc) {
		atomic_dec(&md->kcxi_cq->md_cache.md_cached_count);
		atomic_dec(&md->kcxi_cq->domain->kcxi_if->md_cached_count);
		md->is_cacheable = false;
		kcxi_md_free(md);
		CQ_ERR(kcxi_cq, "Failed to update IOV, freeing cached md: rc=%d", rc);
		return 	ERR_PTR(rc);
	}

	/* re-initialize md members that change with update */
	md->len = len;
	md->addr = md->mapped_md->iova + offset;
	md->user_addr = 0; /* set to 0 since md cache is only for kernel iova */
	md->calling_cpu = smp_processor_id();

	cur = atomic_read(&md->kcxi_cq->md_cache.md_cached_count) -
			atomic_read(&md->kcxi_cq->md_cache.md_cached_avail);
	do {
		max = atomic_read(&md->kcxi_cq->md_cache.md_cached_max);
		if (max >= cur)
			break;
	} while (atomic_cmpxchg(&md->kcxi_cq->md_cache.md_cached_max, max, cur) != max);

	CQ_DEBUG(kcxi_cq, "addr=%llx len=%lu lac=%u cached_avail=%u cached_max=%u",
		      md->addr, md->len, md->lac,
		      atomic_read(&md->kcxi_cq->md_cache.md_cached_avail),
		      atomic_read(&md->kcxi_cq->md_cache.md_cached_max));

	return md;
}

/**
 * kcxi_md_cache_alloc_md() - Allocate a memory descriptor and insert it in the software cache
 * @kcxi_cq: kCXI completion queue
 */
static int kcxi_md_cache_alloc_md(struct kcxi_cq *kcxi_cq)
{
	int rc = 0;
	size_t len = kcxi_cq->md_cache.md_cache_bufsize;
	struct kcxi_md *md;
	uint32_t flags = 0;

	if (!md_cache_enable)
		return -EPERM;

	/* Allow cached md's to be read or write */
	flags |= CXI_MAP_READ | CXI_MAP_WRITE;
	/* For small cached mds always disable IOTLB, ignoring md_caching parameter */
	flags |= CXI_MAP_NOCACHE;
	/* Alloc the md without a buffer */
	flags |= CXI_MAP_ALLOC_MD;

	md = kcxi_md_alloc(kcxi_cq->domain->kcxi_if, kcxi_cq, 0, len, 0, flags, true);
	if (IS_ERR(md)) {
		rc = PTR_ERR(md);
		goto err;
	}

	atomic_inc(&kcxi_cq->md_cache.md_cached_count);
	atomic_inc(&kcxi_cq->domain->kcxi_if->md_cached_count);

	rc = kcxi_md_cache_insert_md(md);
	if (rc) {
		kcxi_md_free(md);
		goto err;
	}

	return rc;

err:
	CQ_ERR(kcxi_cq, "Failed to allocate md for cache: rc=%d", rc);
	return rc;
}

/**
 * kcxi_md_cache_populate() - Populate the memory descriptor software cache
 * @kcxi_cq: kCXI completion queue
 */
void kcxi_md_cache_populate(struct kcxi_cq *kcxi_cq)
{
	int i;
	int rc;

	atomic_set(&kcxi_cq->md_cache.md_cached_count, 0);
	atomic_set(&kcxi_cq->md_cache.md_cached_avail, 0);
	atomic_set(&kcxi_cq->md_cache.md_cached_max, 0);
	kcxi_cq->md_cache.md_cache_entries = (kcxi_cq->attr.size * cq_fill_percent) / 100;
	kcxi_cq->md_cache.md_cache_bufsize = md_cache_bufsize;

	INIT_LIST_HEAD(&kcxi_cq->md_cache.md_cache_list);
	spin_lock_init(&kcxi_cq->md_cache.md_cache_list_lock);

	if (!md_cache_enable)
		return;

	for (i = 0; i < kcxi_cq->md_cache.md_cache_entries; i++) {
		rc = kcxi_md_cache_alloc_md(kcxi_cq);
		if (rc)
			break;
	}

	CQ_DEBUG(kcxi_cq, "cached_alloc=%i cached_avail=%i, cached_max=%i",
		atomic_read(&kcxi_cq->md_cache.md_cached_count),
		atomic_read(&kcxi_cq->md_cache.md_cached_avail),
		atomic_read(&kcxi_cq->md_cache.md_cached_max));
}

/**
 * kcxi_md_cache_flush() - Flush the memory descriptor software cache
 * @kcxi_cq: kCXI completion queue
 */
void kcxi_md_cache_flush(struct kcxi_cq *kcxi_cq)
{
	struct kcxi_md *position;
	struct kcxi_md *next;

	CQ_DEBUG(kcxi_cq, "cached_alloc=%i cached_avail=%i, cached_max=%i",
		atomic_read(&kcxi_cq->md_cache.md_cached_count),
		atomic_read(&kcxi_cq->md_cache.md_cached_avail),
		atomic_read(&kcxi_cq->md_cache.md_cached_max));

	list_for_each_entry_safe(position, next, &kcxi_cq->md_cache.md_cache_list, entry) {
		list_del(&position->entry);
		atomic_dec(&position->kcxi_cq->md_cache.md_cached_count);
		atomic_dec(&position->kcxi_cq->md_cache.md_cached_avail);
		position->is_cacheable = false;
		kcxi_md_free(position);
	}
}

/**
 * kcxi_md_biov_alloc() - Map a bvec buffer.
 * @kcxi_if: kCXI interface
 * @kcxi_cq: kCXI completion queue
 * @biov: Bvec to be mapped
 * @count: Number of bvecs
 * @offset: Offset into the bvecs
 * @flags: Mapping flags
 *
 * Note: cxi_map_iov() will ensure that gaps do not exist in the biov.
 *
 * Return: Valid pointer on success. Else, error pointer.
 */
struct kcxi_md *kcxi_md_biov_alloc(struct kcxi_if *kcxi_if,
				   struct kcxi_cq *kcxi_cq,
				   const struct bio_vec *biov, size_t count,
				   uint64_t offset, uint32_t flags)
{
	int i;
	int rc;
	struct iov_iter iter;
	struct kcxi_md *md;
	size_t nob;
	void *va;
	size_t md_len;
	uint64_t md_offset;

	if (!kcxi_if || (!biov && count) || (biov && !count) ||
	    (!biov && !count && offset)) {
		rc = -EINVAL;
		goto err;
	}

	/* If IOV count is one or less, use kcxi_md_alloc(). */
	if (count == 0) {
		return kcxi_md_alloc(kcxi_if, kcxi_cq, NULL, 0, offset, flags, false);
	} else if (count == 1) {
		va = page_to_virt(biov[0].bv_page) + biov[0].bv_offset;
		md_len = biov[0].bv_len;
		return kcxi_md_alloc(kcxi_if, kcxi_cq, va, md_len, offset, flags, false);
	}

	nob = 0;
	for (i = 0; i < count; i++)
		nob += biov[i].bv_len;

	if (offset > nob) {
		KCXI_IF_ERR(kcxi_if, "offset exceeded number of bytes");
		rc = -EINVAL;
		goto err;
	} else if (!nob) {
		/* If no bytes, treat as zero byte MD. */
		return kcxi_md_alloc(kcxi_if, kcxi_cq, NULL, 0, offset, flags, false);
	}

	iov_iter_bvec(&iter, KF_ITER_BVEC, biov, count, nob);

	/* Only the first biov (page) can have an offset. */
	md_len = nob - offset;
	md_offset = biov[0].bv_offset + offset;

	md = kcxi_md_cache_remove_md(kcxi_cq, &iter, md_len, md_offset);
	if (!IS_ERR(md))
		return md;

	md = kmem_cache_zalloc(md_cache, GFP_NOWAIT);
	if (!md) {
		KCXI_IF_ERR(kcxi_if, "Failed to allocate MD");
		rc = -ENOMEM;
		goto err;
	}

	if (!md_caching)
		flags |= CXI_MAP_NOCACHE;

	md->mapped_md = cxi_map_iov(kcxi_if->lni, &iter, flags);
	if (IS_ERR(md->mapped_md)) {
		rc = PTR_ERR(md->mapped_md);
		KCXI_IF_ERR(kcxi_if, "Failed to map IOV: rc=%d", rc);
		goto err_free_md;
	}

	kcxi_md_init(md, kcxi_if, kcxi_cq, 0, md->mapped_md->iova, md_len, md_offset,
		     md->mapped_md->lac, false);

	KCXI_IF_DEBUG(kcxi_if, "addr=%llx len=%lu lac=%u md_cnt=%u cacheable=%s", md->addr,
		      md->len, md->lac,
		      atomic_read(&md->kcxi_if->md_cur_count),
		      md->is_cacheable ? "true" : "false");

	return md;

err_free_md:
	kmem_cache_free(md_cache, md);
err:
	KCXI_IF_ERR(kcxi_if, "Failed to map buffer: rc=%d", rc);
	return ERR_PTR(rc);
}

/**
 * kcxi_md_iov_alloc() - Map a kvec buffer.
 * @kcxi_if: kCXI interface
 * @kcxi_cq: kCXI completion queue
 * @iov: Kvec to be mapped
 * @count: Number of kvecs
 * @offset: Offset into the kvecs
 * @flags: Mapping flags
 *
 * Note: cxi_map_iov() will ensure that gaps do not exist in the iov.
 *
 * Return: Valid pointer on success. Else, error pointer.
 */
struct kcxi_md *kcxi_md_iov_alloc(struct kcxi_if *kcxi_if,
				  struct kcxi_cq *kcxi_cq,
				  const struct kvec *iov, size_t count,
				  uint64_t offset, uint32_t flags)
{
	int i;
	int rc;
	struct iov_iter iter;
	struct kcxi_md *md;
	uintptr_t va;
	uint64_t va_offset;
	size_t nob;
	size_t md_len;
	uint64_t md_offset;

	if (!kcxi_if || (!iov && count) || (iov && !count) ||
	    (!iov && !count && offset)) {
		rc = -EINVAL;
		goto err;
	}

	/* If IOV count is one or less, use kcxi_md_alloc(). */
	if (count == 0) {
		return kcxi_md_alloc(kcxi_if, kcxi_cq, NULL, 0, offset, flags, false);
	} else if (count == 1) {
		va = (uintptr_t)iov[0].iov_base;
		md_len =  iov[0].iov_len;
		return kcxi_md_alloc(kcxi_if, kcxi_cq, (void *)va, md_len, offset,
				     flags, false);
	}

	nob = 0;
	for (i = 0; i < count; i++)
		nob += iov[i].iov_len;

	if (offset > nob) {
		KCXI_IF_ERR(kcxi_if, "offset exceeded number of bytes");
		rc = -EINVAL;
		goto err;
	} else if (!nob) {
		/* If no bytes, treat as zero byte MD. */
		return kcxi_md_alloc(kcxi_if, kcxi_cq, NULL, 0, offset, flags, false);
	}

	iov_iter_kvec(&iter, KF_ITER_KVEC, iov, count, nob);

	kcxi_md_align_buffer(iov[0].iov_base, &va, &va_offset);

	md_len = nob - offset;
	md_offset = va_offset + offset;

	md = kcxi_md_cache_remove_md(kcxi_cq, &iter, md_len, md_offset);
	if (!IS_ERR(md))
		return md;

	md = kmem_cache_zalloc(md_cache, GFP_NOWAIT);
	if (!md) {
		KCXI_IF_ERR(kcxi_if, "Failed to allocate MD");
		rc = -ENOMEM;
		goto err;
	}

	if (!md_caching)
		flags |= CXI_MAP_NOCACHE;

	md->mapped_md = cxi_map_iov(kcxi_if->lni, &iter, flags);
	if (IS_ERR(md->mapped_md)) {
		rc = PTR_ERR(md->mapped_md);
		KCXI_IF_ERR(kcxi_if, "Failed to map IOV: rc=%d", rc);
		goto err_free_md;
	}

	kcxi_md_init(md, kcxi_if, kcxi_cq, 0, md->mapped_md->iova, md_len, md_offset,
		     md->mapped_md->lac, false);

	KCXI_IF_DEBUG(kcxi_if, "addr=%llx len=%lu lac=%u md_cnt=%u cacheable=%s", md->addr,
		      md->len, md->lac,
		      atomic_read(&md->kcxi_if->md_cur_count),
		      md->is_cacheable ? "true" : "false");

	return md;

err_free_md:
	kmem_cache_free(md_cache, md);
err:
	KCXI_IF_ERR(kcxi_if, "Failed to map buffer: rc=%d", rc);
	return ERR_PTR(rc);
}

/**
 * kcxi_md_alloc() - Allocate a memory descriptor
 * @kcxi_if: kCXI interface
 * @kcxi_cq: kCXI completion queue
 * @buf: Buffer the memory descriptor is associated with
 * @len: Length of buffer
 * @offset: Offset into the buffer
 * @flags: CXI mapping flags
 *
 * Return: Valid pointer on success. Else, error pointer.
 */
struct kcxi_md *kcxi_md_alloc(struct kcxi_if *kcxi_if,
			      struct kcxi_cq *kcxi_cq, const void *buf,
			      size_t len, uint64_t offset, uint32_t flags, bool cacheable)
{
	struct kcxi_md *md;
	uintptr_t va;
	uint64_t va_offset;
	size_t iova_len;
	uint64_t md_offset;
	int rc;

	if (!kcxi_if || offset > len || (flags & CXI_MAP_USER_ADDR)) {
		rc = -EINVAL;
		goto err;
	}

	md = kmem_cache_zalloc(md_cache, GFP_NOWAIT);
	if (!md) {
		KCXI_IF_ERR(kcxi_if, "Failed to allocate MD");
		rc = -ENOMEM;
		goto err;
	}

	/* Only need to map if vmalloc address.
	 * TODO: This is actually incorrect. If a IOMMU domain is allocated for
	 * the PCIe device and the PCIe device is not passed through to a VM,
	 * physical addresses cannot be used for DMA. The correct DMA address
	 * needs to be retrieved used the DMA API. But, the struct device for
	 * the PCIe device needs to be known. This is not exposed to the kCXI
	 * provider.
	 */
	if (len) {
		if (buf == NULL && flags & CXI_MAP_ALLOC_MD) {
				md->mapped_md = cxi_map(kcxi_if->lni, 0,
							len, flags, NULL);
				if (IS_ERR(md->mapped_md)) {
					rc = PTR_ERR(md->mapped_md);
					KCXI_IF_ERR(kcxi_if,
						    "Failed to map IOV: rc=%d",
						    rc);
					goto err_free_md;
				}

				kcxi_md_init(md, kcxi_if, kcxi_cq, 0,
					     md->mapped_md->iova, len,
					     0, md->mapped_md->lac, cacheable);
		} else if (is_vmalloc_addr(buf)) {
			kcxi_md_align_buffer(buf, &va, &va_offset);

			md_offset = offset + va_offset;
			iova_len = len + md_offset;

			/* IOVA length is page aligned. Since cxi_map is
			 * expensive, only call this function if the address
			 * spans multiple pages.
			 */
			if (iova_len <= PAGE_SIZE) {
				/* TODO: Use DMA map API. */
				kcxi_md_init(md, kcxi_if, kcxi_cq, va,
					     PFN_PHYS(vmalloc_to_pfn(buf)), len,
					     md_offset, kcxi_if->phys_lac, false);
			} else {
				if (!md_caching)
					flags |= CXI_MAP_NOCACHE;

				md->mapped_md = cxi_map(kcxi_if->lni, va,
							iova_len, flags, NULL);
				if (IS_ERR(md->mapped_md)) {
					rc = PTR_ERR(md->mapped_md);
					KCXI_IF_ERR(kcxi_if,
						    "Failed to map IOV: rc=%d",
						    rc);
					goto err_free_md;
				}

				kcxi_md_init(md, kcxi_if, kcxi_cq, va,
					     md->mapped_md->iova, len,
					     md_offset, md->mapped_md->lac, cacheable);
			}
		} else {
			kcxi_md_init(md, kcxi_if, kcxi_cq, (uint64_t)buf,
				     virt_to_phys((void *)buf), len, offset,
				     kcxi_if->phys_lac, false);
		}
	} else {
		kcxi_md_init(md, kcxi_if, kcxi_cq, 0, 0, 0, 0, kcxi_if->phys_lac, false);
	}

	KCXI_IF_DEBUG(kcxi_if, "addr=%llx len=%lu lac=%u md_cnt=%u cacheable=%s", md->addr,
		      md->len, md->lac,
		      atomic_read(&md->kcxi_if->md_cur_count),
		      md->is_cacheable ? "true" : "false");

	return md;

err_free_md:
	kmem_cache_free(md_cache, md);
err:
	KCXI_IF_ERR(kcxi_if, "Failed to map buffer: rc=%d", rc);
	return ERR_PTR(rc);
}