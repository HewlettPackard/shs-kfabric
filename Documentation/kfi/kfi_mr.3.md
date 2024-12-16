---
layout: page
title: kfi_mr(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_mr \- Memory region operations

kfi_mr_reg / kfi_mr_regv / kfi_mr_regbv / kfi_mr_sgl / kfi_mr_regattr
: Register local memory buffers for direct fabric access

kfi_close
: Deregister registered memory buffers.

kfi_mr_desc
: Return a local descriptor associated with a registered memory region

kfi_mr_key
: Return the remote key needed to access a registered memory region

kfi_mr_bind
: Associate a registered memory region with a completion queue or counter.

# SYNOPSIS

```C

#include <kfi_domain.h>

int
kfi_mr_reg(struct kfid_domain *domain, const void *buf, size_t len,
	   uint64_t access, uint64_t offset, uint64_t requested_key,
	   uint64_t flags, struct kfid_mr **mr, void *context)

int
kfi_mr_regv(struct kfid_domain *domain, const struct kvec *iov,
	    size_t count, uint64_t access, uint64_t offset, uint64_t requested_key,
	    uint64_t flags, struct kfid_mr **mr, void *context)

int
kfi_mr_regbv(struct kfid_domain *domain, const struct bio_vec *biov,
	    size_t count, uint64_t access, uint64_t offset, uint64_t requested_key,
	    uint64_t flags, struct kfid_mr **mr, void *context)

int
kfi_mr_regsgl(struct kfid_domain *domain, const struct scatterlist *sgl,
	    size_t count, uint64_t access, uint64_t offset, uint64_t requested_key,
	    uint64_t flags, struct kfid_mr **mr, void *context)

int
kfi_mr_regattr(struct kfid_domain *domain, const struct kfi_mr_attr *attr,
	    uint64_t flags, struct kfid_mr **mr)

int
kfi_close(struct kfid *fid)

void *
kfi_mr_desc(struct kfid_mr *mr)

uint64_t
kfi_mr_key(struct kfid_mr *mr)

int
kfi_mr_bind(struct kfid_mr *mr, struct kfid *bfid,
	    uint64_t flags)

```

# ARGUMENTS

*domain*
: Resource domain

*mr*
: Memory region

*bfid*
: Fabric identifier of an associated resource.

*context*
: User specified context associated with the memory region.

*buf*
: Memory buffer to register with the fabric hardware

*len*
: Length of memory buffer to register

*iov / biov / sgl*
: Vectored memory buffer.

*count*
: Count of vectored buffer entries.

*access*
: Memory access permissions associated with registration

*offset*
: Optional specified offset for accessing specified registered buffers.
  This parameter is reserved for future use and must be 0.

*requested_key*
: Optional requested remote key associated with registered buffers.

*attr*
: Memory region attributes

*flags*
: Additional flags to apply to the operation.

# DESCRIPTION

Registered memory regions associate memory buffers with permissions
granted for access by fabric resources.  A memory buffer must be
registered with a resource domain before it can be used as the target
of a remote RMA or atomic data transfer.  Additionally, a fabric
provider may require that data buffers be registered before being used
in local transfers.

A provider may hide local registration requirements from applications
by making use of an internal registration cache or similar mechanisms.
Such mechanisms, however, may negatively impact performance for some
applications, notably those which manage their own network buffers.
In order to support as broad range of applications as possible,
without unduly affecting their performance, applications that wish to
manage their own local memory registrations may do so by using the
memory registration calls.  Applications may use the KFI_LOCAL_MR
domain mode bit as a guide.

When the KFI_LOCAL_MR mode bit is set, applications must register all
data buffers that will be accessed by the local hardware and provide
a valid mem_desc parameter into applicable data transfer operations.
When KFI_LOCAL_MR is zero, applications are not required to register
data buffers before using them for local operations (e.g. send and
receive data buffers), and the mem_desc parameter into data transfer
operations is ignored.

The registrations functions -- kfi_mr_reg, kfi_mr_regv, kfi_mr_regbv,
kfi_mr_regsgl and kfi_mr_regattr -- are used to register one or more
memory buffers with fabric resources.  The main difference between
registration functions are the number and type of parameters that they
accept as input.  Otherwise, they perform the same general function.

By default, memory registration completes synchronously.  I.e. the
registration call will not return until the registration has
completed.  Memory registration can complete asynchronous by binding
the resource domain to an event queue using the KFI_REG_MR flag.  See
kfi_domain_bind.  When memory registration is asynchronous, in order to
avoid a race condition between the registration call returning and the
corresponding reading of the event from the EQ, the mr output
parameter will be written before any event associated with the
operation may be read by the application.  An asynchronous event will
not be generated unless the registration call returns success (0).

## kfi_mr_reg

The kfi_mr_reg call registers the user-specified memory buffer with
the resource domain.  The buffer is enabled for access by the fabric
hardware based on the provided access permissions.  Supported access
permissions are the bitwise OR of the following:

*KFI_SEND*
: The memory buffer may be used in outgoing message data transfers.  This
  includes kfi_msg and kfi_tagged operations.

*KFI_RECV*
: The memory buffer may be used to receive inbound message transfers.
  This includes kfi_msg and kfi_tagged operations.

*KFI_READ*
: The memory buffer may be used as the result buffer for RMA read
  and atomic operations on the initiator side.

*KFI_WRITE*
: The memory buffer may be used as the source buffer for RMA write
  and atomic operations on the initiator side.

*KFI_REMOTE_READ*
: The memory buffer may be used as the source buffer of an RMA read
  operation on the target side.

*KFI_REMOTE_WRITE*
: The memory buffer may be used as the target buffer of an RMA write
  or atomic operation.

Registered memory is associated with a local memory descriptor and,
optionally, a remote memory key.  A memory descriptor is a provider
specific identifier associated with registered memory.  Memory
descriptors often map to hardware specific indices or keys associated
with the memory region.  Remote memory keys provide limited protection
against unwanted access by a remote node.  Remote accesses to a memory
region must provide the key associated with the registration.

The offset parameter is reserved for future use and must be 0.

For asynchronous memory registration requests, the result will be
reported to the user through an event queue associated with the
resource domain.  If successful, the allocated memory region structure
will be returned to the user through the mr parameter.  The mr address
must remain valid until the registration operation completes.  The
context specified with the registration request is returned with the
completion event.

## kfi_mr_regv / kfi_mr_regbv / kfi_mr_regsgl

The kfi_mr_reg, kfi_mr_regbv and kfi_mr_regsgl calls add support for
a scatter-gather list to kfi_mr_reg.  Multiple memory buffers are
registered as a single memory region.  Otherwise, the operation is the
same.  The kfi_mr_regsgl call requires the scatterlist to be DMA mapped.

## kfi_mr_regattr

The kfi_mr_regattr call is a more generic, extensible registration call
that allows the user to specify the registration request using a
struct kfi_mr_attr.  The `mr_sgl` scatterlist must be DMA mapped.

```C

struct kfi_mr_attr {
	enum kfi_iov_type	type;
	union {
		const struct kvec	*mr_iov;
		const struct bio_vec	*mr_biov;
		const struct scatterlist	*mr_sgl;
	};
	size_t			iov_count;
	uint64_t		access;
	uint64_t		offset;
	uint64_t		requested_key;
	void			*context;
	size_t			auth_key_size;
	uint8_t			*auth_key;
};

```

## kfi_close

kfi_close is used to release all resources associated with a
registering a memory region.  Once unregistered, further access to the
registered memory is not guaranteed.

When closing the MR, there must be no opened endpoints or counters associated
with the MR.  If resources are still associated with the MR when attempting to
close, the call will return -KFI_EBUSY.

## kfi_mr_desc / kfi_mr_key

The local memory descriptor and remote protection key associated with
a MR may be obtained by calling kfi_mr_desc and kfi_mr_key,
respectively.  The memory registration must have completed
successfully before invoking these calls.

## kfi_mr_bind

The kfi_mr_bind function associates a memory region with a
counter, for providers that support the generation of completions
based on fabric operations.  The type of events tracked against the
memory region is based on the bitwise OR of the following flags.

*KFI_REMOTE_WRITE*
: Generates an event whenever a remote RMA write or atomic operation
  modify the memory region.

# RETURN VALUES

Returns 0 on success.  On error, a negative value corresponding to
kfabric errno is returned.

Kfabric errno values are defined in
`kfi_errno.h`.

# ERRORS

*-KFI_ENOKEY*
: The requested_key is already in use.

*-KFI_EKEYREJECTED*
: The requested_key is not available.  They key may be out of the
  range supported by the provider, or the provider may not support
  user-requested memory registration keys.

*-KFI_ENOSYS*
: Returned by kfi_mr_bind if the provider does not support reporting
  events based on access to registered memory regions.

*-KFI_EBADFLAGS*
: Returned if the specified flags are not supported by the provider.

*-KFI_EINVAL*
: Indicates that an invalid argument was supplied by the user.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_rma`(3)](kfi_rma.3.html),
[`kfi_msg`(3)](kfi_msg.3.html),
[`kfi_atomic`(3)](kfi_atomic.3.html)
