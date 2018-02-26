---
layout: page
title: kfi_atomic(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_atomic - Remote atomic functions

kfi_atomic / kfi_atomicv / kfi_atomicmsg / kfi_inject_atomic
: Initiates an atomic operation to remote memory

kfi_fetch_atomic / kfi_fetch_atomicv / kfi_fetch_atomicmsg
: Initiates an atomic operation to remote memory, retrieving the initial
  value.

kfi_compare_atomic / kfi_compare_atomicv / kfi_compare_atomicmsg
: Initiates an atomic compare-operation to remote memory, retrieving
  the initial value.

kfi_atomic_valid / kfi_fetch_atomic_valid / kfi_compare_atomic_valid
: Indicates if a provider supports a specific atomic operation

# SYNOPSIS

{% highlight c %}
#include <kfi_atomic.h>

ssize_t
kfi_atomic(struct kfid_ep *ep, const void *buf, size_t count, void *desc,
	   kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
	   enum kfi_datatype datatype, enum kfi_op op, void *context)

ssize_t
kfi_atomicv(struct kfid_ep *ep, const struct kfi_ioc *iov, void **desc,
	    size_t count, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
	    enum kfi_datatype datatype, enum kfi_op op, void *context)

ssize_t
kfi_atomicmsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
	      uint64_t flags)

ssize_t
kfi_inject_atomic(struct kfid_ep *ep, const void *buf, size_t count,
		  kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
		  enum kfi_datatype datatype, enum kfi_op op)

ssize_t
kfi_fetch_atomic(struct kfid_ep *ep,
		 const void *buf, size_t count, void *desc,
		 void *result, void *result_desc,
		 kfi_addr_t dest_addr,
		 uint64_t addr, uint64_t key,
		 enum kfi_datatype datatype, enum kfi_op op, void *context)

ssize_t
kfi_fetch_atomicv(struct kfid_ep *ep, const struct kfi_ioc *iov, void **desc,
		  size_t count, struct kfi_ioc *resultv, void **result_desc,
		   size_t result_count, kfi_addr_t dest_addr, uint64_t addr,
		   uint64_t key, enum kfi_datatype datatype,
		   enum kfi_op op, void *context)

ssize_t
kfi_fetch_atomicmsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
		    struct kfi_ioc *resultv, void **result_desc,
		    size_t result_count, uint64_t flags)

ssize_t
kfi_compare_atomic(struct kfid_ep *ep, const void *buf, size_t count,
		   void *desc, const void *compare, void *compare_desc,
		   void *result, void *result_desc, kfi_addr_t dest_addr,
		   uint64_t addr, uint64_t key, enum kfi_datatype datatype,
		   enum kfi_op op, void *context)

ssize_t
kfi_compare_atomicv(struct kfid_ep *ep, const struct kfi_ioc *iov, void **desc,
		    size_t count, const struct kfi_ioc *comparev,
		    void **compare_desc, size_t compare_count,
		    struct kfi_ioc *resultv, void **result_desc,
		    size_t result_count, kfi_addr_t dest_addr, uint64_t addr,
		    uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
		    void *context)

ssize_t
kfi_compare_atomicmsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
		      const struct kfi_ioc *comparev, void **compare_desc,
		      size_t compare_count, struct kfi_ioc *resultv,
		      void **result_desc, size_t result_count, uint64_t flags)

int
kfi_atomicvalid(struct kfid_ep *ep, enum kfi_datatype datatype,
		enum kfi_op op, size_t *count)

int
kfi_fetch_atomicvalid(struct kfid_ep *ep, enum kfi_datatype datatype,
		      enum kfi_op op, size_t *count)

int
kfi_compare_atomicvalid(struct kfid_ep *ep, enum kfi_datatype datatype,
			enum kfi_op op, size_t *count)

{% endhighlight %}

# ARGUMENTS

*ep*
: Kfabric endpoint on which to initiate atomic operation.

*buf*
: Local data buffer that specifies first operand of atomic operation

*iov / comparev / resultv*
: Vectored data buffer(s).

*count / compare_count / result_count*
: Count of vectored data entries.

*addr*
: Address of remote memory to access.

*key*
: Protection key associated with the remote memory.

*datatype*
: Datatype associated with atomic operands

*op*
: Atomic operation to perform

*compare*
: Local compare buffer, containing comparison data.

*result*
: Local data buffer to store initial value of remote buffer

*desc / compare_desc / result_desc*
: Data descriptor associated with the local data buffer, local compare
  buffer, and local result buffer, respectively.

*dest_addr*
: Destination address for connectionless atomic operations.  Ignored for
  connected endpoints.

*msg*
: Message descriptor for atomic operations

*flags*
: Additional flags to apply for the atomic operation

*context*
: User specified pointer to associate with the operation.

# DESCRIPTION

Atomic transfers are used to read and update data located in remote
memory regions in an atomic fashion.  Conceptually, they are similar
to local atomic operations of a similar nature (e.g. atomic increment,
compare and swap, etc.).  Updates to remote data involve one of
several operations on the data, and act on specific types of data, as
listed below.  As such, atomic transfers have knowledge of the format
of the data being accessed.  A single atomic function may operate
across an array of data applying an atomic operation to each entry,
but the atomicity of an operation is limited to a single datatype or
entry.

## Atomic Data Types

Atomic functions may operate on one of the following identified data
types.  A given atomic function may support any datatype, subject to
provider implementation constraints.

*KFI_INT8*
: Signed 8-bit integer.

*KFI_UINT8*
: Unsigned 8-bit integer.

*KFI_INT16*
: Signed 16-bit integer.

*KFI_UINT16*
: Unsigned 16-bit integer.

*KFI_INT32*
: Signed 32-bit integer.

*KFI_UINT32*
: Unsigned 32-bit integer.

*KFI_INT64*
: Signed 64-bit integer.

*KFI_UINT64*
: Unsigned 64-bit integer.

*KFI_FLOAT*
: A single-precision floating point value (IEEE 754).

*KFI_DOUBLE*
: A double-precision floating point value (IEEE 754).

*KFI_FLOAT_COMPLEX*
: An ordered pair of single-precision floating point values (IEEE
  754), with the first value representing the real portion of a
  complex number and the second representing the imaginary portion.

*KFI_DOUBLE_COMPLEX*
: An ordered pair of double-precision floating point values (IEEE
  754), with the first value representing the real portion of a
  complex number and the second representing the imaginary portion.

*KFI_LONG_DOUBLE*
: A double-extended precision floating point value (IEEE 754).

*KFI_LONG_DOUBLE_COMPLEX*
: An ordered pair of double-extended precision floating point values
  (IEEE 754), with the first value representing the real portion of
  a complex number and the second representing the imaginary
  portion.

## Atomic Operations

The following atomic operations are defined.  An atomic operation
often acts against a target value in the remote memory buffer and
source value provided with the atomic function.  It may also carry
source data to replace the target value in compare and swap
operations.  A conceptual description of each operation is provided.

*KFI_MIN*
: Minimum
{% highlight c %}
if (buf[i] < addr[i])
    addr[i] = buf[i]
{% endhighlight %}

*KFI_MAX*
: Maximum
{% highlight c %}
if (buf[i] > addr[i])
    addr[i] = buf[i]
{% endhighlight %}

*KFI_SUM*
: Sum
{% highlight c %}
addr[i] = addr[i] + buf[i]
{% endhighlight %}

*KFI_PROD*
: Product
{% highlight c %}
addr[i] = addr[i] * buf[i]
{% endhighlight %}

*KFI_LOR*
: Logical OR
{% highlight c %}
addr[i] = (addr[i] || buf[i])
{% endhighlight %}

*KFI_LAND*
: Logical AN
{% highlight c %}
addr[i] = (addr[i] && buf[i])
{% endhighlight %}

*KFI_BOR*
: Bitwise OR
{% highlight c %}
addr[i] = addr[i] | buf[i]
{% endhighlight %}

*KFI_BAND*
: Bitwise AND
{% highlight c %}
addr[i] = addr[i] & buf[i]
{% endhighlight %}

*KFI_LXOR*
: Logical exclusive-OR (XOR)
{% highlight c %}
addr[i] = ((addr[i] && !buf[i]) || (!addr[i] && buf[i]))
{% endhighlight %}

*KFI_BXOR*
: Bitwise exclusive-OR (XOR)
{% highlight c %}
addr[i] = addr[i] ^ buf[i]
{% endhighlight %}

*KFI_ATOMIC_READ*
: Read data atomically
{% highlight c %}
buf[i] = addr[i]
{% endhighlight %}

*KFI_ATOMIC_WRITE*
: Write data atomically
{% highlight c %}
addr[i] = buf[i]
{% endhighlight %}

*KFI_CSWAP*
: Compare values and if equal swap with data
{% highlight c %}
if (addr[i] == compare[i])
    addr[i] = buf[i]
{% endhighlight %}

*KFI_CSWAP_NE*
: Compare values and if not equal swap with data
{% highlight c %}
if (addr[i] != compare[i])
    addr[i] = buf[i]
{% endhighlight %}

*KFI_CSWAP_LE*
: Compare values and if less than or equal swap with data
{% highlight c %}
if (addr[i] <= compare[i])
    addr[i] = buf[i]
{% endhighlight %}

*KFI_CSWAP_LT*
: Compare values and if less than swap with data
{% highlight c %}
if (addr[i] < compare[i])
    addr[i] = buf[i]
{% endhighlight %}

*KFI_CSWAP_GE*
: Compare values and if greater than or equal swap with data
{% highlight c %}
if (addr[i] >= compare[i])
    addr[i] = buf[i]
{% endhighlight %}

*KFI_CSWAP_GT*
: Compare values and if greater than swap with data
{% highlight c %}
if (addr[i] > compare[i])
    addr[i] = buf[i]
{% endhighlight %}

*KFI_MSWAP*
: Swap masked bits with data
{% highlight c %}
addr[i] = (buf[i] & compare[i]) | (addr[i] & ~compare[i])
{% endhighlight %}

## Base Atomic Functions

The base atomic functions -- kfi_atomic, kfi_atomicv,
kfi_atomicmsg -- are used to transmit data to a remote node, where the
specified atomic operation is performed against the target data.  The
result of a base atomic function is stored at the remote memory
region.  The main difference between atomic functions are the number
and type of parameters that they accept as input.  Otherwise, they
perform the same general function.

The call kfi_atomic transfers the data contained in the user-specified
data buffer to a remote node.  For unconnected endpoints, the destination
endpoint is specified through the dest_addr parameter.  Unless
the endpoint has been configured differently, the data buffer passed
into kfi_atomic must not be touched by the application until the
kfi_atomic call completes asynchronously.  The target buffer of a base
atomic operation must allow for remote read an/or write access, as
appropriate.

The kfi_atomicv call adds support for a scatter-gather list to
kfi_atomic.  The kfi_atomicv transfers the set of data buffers
referenced by the ioc parameter to the remote node for processing.

The kfi_inject_atomic call is an optimized version of kfi_atomic.  The
kfi_inject_atomic function behaves as if the KFI_INJECT transfer flag
were set, and KFI_COMPLETION were not.  That is, the data buffer is
available for reuse immediately on returning from from
kfi_inject_atomic, and no completion event will be generated for this
atomic.  The completion event will be suppressed even if the endpoint
has not been configured with KFI_COMPLETION.  See the flags discussion
below for more details.

The kfi_atomicmsg call supports atomic functions over both connected
and unconnected endpoints, with the ability to control the atomic
operation per call through the use of flags.  The kfi_atomicmsg
function takes a struct kfi_msg_atomic as input.

{% highlight c %}
struct kfi_msg_atomic {
	const struct kfi_ioc		*msg_iov;
	void				**desc;
	size_t				iov_count;
	kfi_addr_t			addr;
	const struct kfi_rma_ioc	*rma_iov;
	size_t				rma_iov_count;
	enum kfi_datatype		datatype;
	enum kfi_op			op;
	void				*context;
	uint64_t			data;
};

struct kfi_rma_ioc {
	uint64_t                addr;
	size_t                  count;
	uint64_t                key;
};
{% endhighlight %}

## Fetch-Atomic Functions

The fetch atomic functions -- kfi_fetch_atomic, kfi_fetch_atomicv,
and kfi_fetch atomicmsg -- behave similar to the
equivalent base atomic function.  The difference between the fetch and
base atomic calls are the fetch atomic routines return the initial
value that was stored at the target to the user.  The initial value is
read into the user provided result buffer.  The target buffer of
fetch-atomic operations must be enabled for remote read access.

The following list of atomic operations are usable with both the base
atomic and fetch atomic operations: KFI_MIN, KFI_MAX, KFI_SUM, KFI_PROD,
KFI_LOR, KFI_LAND, KFI_BOR, KFI_BAND, KFI_LXOR, KFI_BXOR, KFI_ATOMIC_READ,
and KFI_ATOMIC_WRITE.

## Compare-Atomic Functions

The compare atomic functions -- kfi_compare_atomic, kfi_compare_atomicv,
and kfi_compare atomicmsg -- are used for
operations that require comparing the target data against a value
before performing a swap operation.  The compare atomic functions
support: KFI_CSWAP, KFI_CSWAP_NE, KFI_CSWAP_LE, KFI_CSWAP_LT, KFI_CSWAP_GE,
KFI_CSWAP_GT, and KFI_MSWAP.

## Atomic Valid Functions

The atomic valid functions -- kfi_atomicvalid, kfi_fetch_atomicvalid,
and kfi_compare_atomicvalid --indicate which operations the local
provider supports.  Needed operations not supported by the provider
must be emulated by the application.  Each valid call corresponds to a
set of atomic functions.  kfi_atomicvalid checks whether a provider
supports a specific base atomic operation for a given datatype and
operation.  kfi_fetch_atomicvalid indicates if a provider supports a
specific fetch-atomic operation for a given datatype and operation.
And kfi_compare_atomicvalid checks if a provider supports a specified
compare-atomic operation for a given datatype and operation.

If an operation is supported, an atomic valid call will return 0,
along with a count of atomic data units that a single function call
will operate on.

## Completions

Completed atomic operations are reported to the user through one or
more event collectors associated with the endpoint.  Users provide
context which are associated with each operation, and is returned to
the user as part of the event completion.  See kfi_eq for completion
event details.

Updates to the target buffer of an atomic operation are visible to
processes running on the target system either after a completion has
been generated, or after the completion of an operation initiated
after the atomic call with a fencing operation occurring in between.
For example, the target process may be notified by the initiator
sending a message after the atomic call completes, or sending a fenced
message immediately after initiating the atomic operation.

# FLAGS

The kfi_atomicmsg, kfi_fetch_atomicmsg, and kfi_compare_atomicmsg calls
allow the user to specify flags which can change the default data
transfer operation.  Flags specified with atomic message operations
override most flags previously configured with the endpoint, except
where noted (see kfi_control).  The following list of flags are usable
with atomic message calls.

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

*KFI_REMOTE_SIGNAL*
: Indicates that a completion event at the target process should be
  generated for the given operation.  The remote endpoint must be
  configured with KFI_REMOTE_SIGNAL, or this flag will be ignored by
  the target.

*KFI_INJECT*
: Indicates that the outbound non-const data buffers (buf and compare
  parameters) should be returned to user immediately after the call
  returns, even if the operation is handled asynchronously.  This may
  require that the underlying provider implementation copy the data
  into a local buffer and transfer out of that buffer.  The use of
  output result buffers are not affected by this flag.

*KFI_FENCE*
: Indicates that the requested operation, also
  known as the fenced operation, be deferred until all previous operations
  targeting the same target endpoint have completed.

# RETURN VALUE

Returns 0 on success. On error, a negative value corresponding to kfabric
errno is returned. Kfabric errno values are defined in
`kfi_errno.h`.

# ERRORS

*-KFI_EOPNOTSUPP*
: The requested atomic operation is not supported on this endpoint.

*-KFI_EMSGSIZE*
: The number of atomic operations in a single request exceeds that
  supported by the underlying provider.

# NOTES


# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_eq`(3)](kfi_eq.3.html),
[`kfi_rma`(3)](kfi_rma.3.html)
