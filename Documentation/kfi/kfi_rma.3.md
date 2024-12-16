---
layout: page
title: kfi_rma(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_rma - Remote memory access operations

kfi_read / kfi_readv / kfi_readbv / kfi_readsgl / kfi_readmsg
:   Initiates a read from remote memory

kfi_write / kfi_writev / kfi_writebv / kfi_writesgl / kfi_writemsg /
kfi_inject_write / kfi_writedata
:   Initiate a write to remote memory

# SYNOPSIS

```C

#include <kfi_rma.h>

ssize_t
kfi_read(struct kfid_ep *ep, void *buf, size_t len, void *desc,
	 kfi_addr_t src_addr, uint64_t addr, uint64_t key, void *context)

ssize_t
kfi_readv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	  size_t count, kfi_addr_t src_addr, uint64_t addr, uint64_t key,
	  void *context)

ssize_t
kfi_readbv(struct kfid_ep *ep, const struct bio_vec *biov, void **desc,
	   size_t count, kfi_addr_t src_addr, uint64_t addr, uint64_t key,
	   void *context)

ssize_t
kfi_readsgl(struct kfid_ep *ep, const struct scatterlist *sgl, void **desc,
	   size_t count, kfi_addr_t src_addr, uint64_t addr, uint64_t key,
	   void *context)

ssize_t
kfi_write(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
	  kfi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)

ssize_t
kfi_writev(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	   size_t count, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
	   void *context)

ssize_t
kfi_writebv(struct kfid_ep *ep, const struct bio_vec *biov, void **desc,
	    size_t count, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
	    void *context)

ssize_t
kfi_writesgl(struct kfid_ep *ep, const struct scatterlist *sgl, void **desc,
	    size_t count, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
	    void *context)

ssize_t
kfi_inject_write(struct kfid_ep *ep, const void *buf, size_t len,
		 kfi_addr_t dest_addr, uint64_t addr, uint64_t key)

ssize_t
kfi_writedata(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
	      uint64_t data, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
	      void *context)

```

# ARGUMENTS

*ep*
: Kfabric endpoint on which to initiate read or write operation.

*buf*
: Local data buffer to read into (read target) or write from (write
  source)

*len*
: Length of data to read or write, specified in bytes.  Valid
  transfers are from 0 bytes up to the endpoint's max_msg_size.

*iov / biov / sgl*
: Vectored data buffer.

*count*
: Count of vectored data entries.

*addr*
: Address of remote memory to access.

*key*
: Protection key associated with the remote memory.

*desc*
: Descriptor associated with the local data buffer

*data*
: Remote CQ data to transfer with the operation.

*dest_addr*
: Destination address for connectionless write transfers.  Ignored
  for connected endpoints.

*src_addr*
: Source address to read from for connectionless transfers.  Ignored
  for connected endpoints.

*msg*
: Message descriptor for read and write operations.

*flags*
: Additional flags to apply for the read or write operation.

*context*
: User specified pointer to associate with the operation.

# DESCRIPTION

RMA (remote memory access) operations are used to transfer data
directly between a local data buffer and a remote data buffer.  RMA
transfers occur on a byte level granularity, and no message boundaries
are maintained.

The write functions -- kfi_write, kfi_writev, kfi_writebv,
kfi_writesgl, kfi_writemsg, kfi_inject_write, and kfi_writedata --
are used to transmit data into a remote memory buffer.  The main
difference between write functions are the number and type of
parameters that they accept as input.  Otherwise, they perform the
same general function.

The read functions -- kfi_read, kfi_readv, kfi_readbv, kfi_readsgl
and kfi_readmsg -- are used to transfer data from a remote memory
region into local data buffer(s).  Similar to the write operations,
read operations operate asynchronously.  Users should not touch the
posted data buffer(s) until the read operation has completed.

Completed RMA operations are reported to the user through one or more
completion queues associated with the endpoint.  Users provide context
which are associated with each operation, and is returned to the user
as part of the completion.  See kfi_cq for completion event details.

By default, the remote endpoint does not generate an event or notify
the user when a memory region has been accessed by an RMA read or
write operation.  However, immediate data may be associated with an
RMA write operation.  RMA writes with immediate data will generate a
completion entry at the remote endpoint, so that the immediate data
may be delivered.

## kfi_write

The call kfi_write transfers the data contained in the user-specified
data buffer to a remote memory region.  The local endpoint must be
connected to a remote endpoint or destination before kfi_write is
called.  Unless the endpoint has been configured differently, the data
buffer passed into kfi_write must not be touched by the application
until the kfi_write call completes asynchronously.

## kfi_writev / kfi_writebv / kfi_writesgl

The kfi_writev, kfi_writebv and kfi_writesgl calls add support for a
scatter-gather list to kfi_write.  The calls transfer the set of data
buffers referenced by the iov, biov or sgl parameter to the remote memory
region.  The kfi_writesgl call requires the scatterlist to be DMA mapped.

## kfi_writemsg

The kfi_writemsg call supports data transfers over both connected and
unconnected endpoints, with the ability to control the write operation
per call through the use of flags.  The kfi_writemsg function takes a
`struct kfi_msg_rma` as input.  The `msg_sgl` scatterlist must be DMA
mapped.

```C

struct kfi_rma_iov {
	uint64_t		addr;
	size_t			len;
	uint64_t		key;
};

struct kfi_msg_rma {
	enum kfi_iov_type	 type;
	union {
		const struct kvec	 *msg_iov;
		const struct bio_vec	 *msg_biov;
		const struct scatterlist	 *msg_sgl;
	};
	void			 **desc;
	size_t			 iov_count;
	kfi_addr_t		 addr;
	const struct kfi_rma_iov *rma_iov;
	size_t			 rma_iov_count;
	void			 *context;
	uint64_t		 data;
};

```

## kfi_inject_write

The write inject call is an optimized version of kfi_write.  The
kfi_inject_write function behaves as if the KFI_INJECT transfer flag
were set, and KFI_COMPLETION were not.  That is, the data buffer is
available for reuse immediately on returning from from
kfi_inject_write, and no completion event will be generated for this
write.  The completion event will be suppressed even if the endpoint
has not been configured with KFI_COMPLETION.  See the flags discussion
below for more details.

## kfi_writedata

The write data call is similar to kfi_write, but allows for the sending
of remote CQ data (see KFI_REMOTE_CQ_DATA flag) as part of the
transfer.

## kfi_read

The kfi_read call requests that the remote endpoint transfer data from
the remote memory region into the local data buffer.  The local
endpoint must be connected to a remote endpoint or destination before
kfi_read is called.

## kfi_readv / kfi_readbv / kfi_readsgl

The kfi_readv, kfi_readbv and kfi_readsgl calls add support for a
scatter-gather list to kfi_read.  The calls transfer data from the remote
memory region into the set of data buffers referenced by the iov, biov,
or sgl parameter.  The kfi_readsgl call requires the scatterlist to be DMA
mapped.

## kfi_readmsg

The kfi_readmsg call supports data transfers over both connected and
unconnected endpoints, with the ability to control the read operation
per call through the use of flags.  The kfi_readmsg function takes a
`struct kfi_msg_rma` as input.  The `msg_sgl` scatterlist must be DMA
mapped.

# FLAGS

The kfi_readmsg and kfi_writemsg calls allow the user to specify flags
which can change the default data transfer operation.  Flags specified
with kfi_readmsg / kfi_writemsg override most flags previously
configured with the endpoint, except where noted (see kfi_endpoint).
The following list of flags are usable with kfi_readmsg and/or
kfi_writemsg.

*KFI_REMOTE_CQ_DATA*
: Applies to kfi_writemsg and kfi_writedata.  Indicates
  that remote CQ data is available and should be sent as part of the
  request.  See kfi_getinfo for additional details on
  KFI_REMOTE_CQ_DATA.

*KFI_COMPLETION*
: Indicates that a completion entry should be generated for the
  specified operation.  The endpoint must be bound to an event queue
  with KFI_COMPLETION that corresponds to the specified operation, or
  this flag is ignored.

*KFI_MORE*
: Indicates that the user has additional requests that will
  immediately be posted after the current call returns.  Use of this
  flag may improve performance by enabling the provider to optimize
  its access to the fabric hardware.

*KFI_INJECT*
: Applies to kfi_writemsg.  Indicates that the outbound data buffer
   should be returned to user immediately after the write call
   returns, even if the operation is handled asynchronously.  This may
   require that the underlying provider implementation copy the data
   into a local buffer and transfer out of that buffer.

*KFI_FENCE*
: Indicates that the requested operation, also
  known as the fenced operation, be deferred until all previous operations
  targeting the same target endpoint have completed.

# RETURN VALUE

Returns 0 on success. On error, a negative value corresponding to kfabric
errno is returned. Kfabric errno values are defined in
`kfi_errno.h`.

# ERRORS

*-KFI_EAGAIN*
: Indicates that the underlying provider currently lacks the resources
  needed to initiate the requested operation.  This may be the result
  of insufficient internal buffering, in the case of KFI_INJECT,
  or processing queues are full.  The operation may be retried after
  additional provider resources become available, usually through the
  completion of currently outstanding operations.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_eq`(3)](kfi_eq.3.html)
