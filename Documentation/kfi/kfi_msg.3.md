---
layout: page
title: kfi_msg(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_msg - Message data transfer operations

kfi_recv / kfi_recvv / kfi_recvmsg
:   Post a buffer to receive an incoming message

kfi_send / kfi_sendv / kfi_sendmsg
kfi_inject / kfi_senddata
:   Initiate an operation to send a message

# SYNOPSIS

{% highlight c %}
#include <kfi_endpoint.h>

ssize_t
kfi_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
	 kfi_addr_t src_addr, void *context)

ssize_t
kfi_recvv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	 size_t count, kfi_addr_t src_addr, void *context)

ssize_t
kfi_recvmsg(struct kfid_ep *ep, const struct kfi_msg *msg, uint64_t flags)

ssize_t
kfi_send(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
	 kfi_addr_t dest_addr, void *context)

ssize_t
kfi_sendv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	  size_t count, kfi_addr_t dest_addr, void *context)

ssize_t
kfi_sendmsg(struct kfid_ep *ep, const struct kfi_msg *msg, uint64_t flags)

ssize_t
kfi_inject(struct kfid_ep *ep, const void *buf, size_t len,
	   kfi_addr_t dest_addr)

ssize_t
kfi_senddata(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
	     uint64_t data, kfi_addr_t dest_addr, void *context)
{% endhighlight %}

# ARGUMENTS

*ep*
: Kfabric endpoint on which to initiate send or post receive buffer.

*buf*
: Data buffer to send or receive.

*len*
: Length of data buffer to send or receive, specified in bytes.  Valid
  transfers are from 0 bytes up to the endpoint's max_msg_size.

*iov*
: Vectored data buffer.

*count*
: Count of vectored data entries.

*desc*
: Descriptor associated with the data buffer

*data*
: Remote CQ data to transfer with the sent message.

*dest_addr*
: Destination address for connectionless transfers.  Ignored for
  connected endpoints.

*src_addr*
: Source address to receive from for connectionless transfers.  Applies
  only to connectionless endpoints with the KFI_DIRECTED_RECV capability
  enabled, otherwise this field is ignored.  If set to KFI_ADDR_UNSPEC,
  any source address may match.

*msg*
: Message descriptor for send and receive operations.

*flags*
: Additional flags to apply for the send or receive operation.

*context*
: User specified pointer to associate with the operation.

# DESCRIPTION

The send functions -- kfi_send, kfi_sendv, kfi_sendmsg,
kfi_inject, and kfi_senddata -- are used to
transmit a message from one endpoint to another endpoint.  The main
difference between send functions are the number and type of
parameters that they accept as input.  Otherwise, they perform the
same general function.  Messages sent using kfi_msg operations are
received by a remote endpoint into a buffer posted to receive such
messages.

The receive functions -- kfi_recv, kfi_recvv, kfi_recvmsg --
post a data buffer to an endpoint to receive inbound messages.
Similar to the send operations, receive operations operate
asynchronously.  Users should not touch the posted data buffer(s)
until the receive operation has completed.

Completed message operations are reported to the user through one or
more event collectors associated with the endpoint.  Users provide
context which are associated with each operation, and is returned to
the user as part of the event completion.  See kfi_eq for completion
event details.

## kfi_send

The call kfi_send transfers the data contained in the user-specified
data buffer to a remote endpoint, with message boundaries being
maintained.  The local endpoint must be connected to a remote endpoint
or destination before kfi_send is called.  Unless the endpoint has been
configured differently, the data buffer passed into kfi_send must not
be touched by the application until the kfi_send call completes
asynchronously.

## kfi_sendv

The kfi_sendv call adds support for a scatter-gather list to kfi_send.
The kfi_sendv transfers the set of data buffers
referenced by the iov parameter to a remote endpoint as a single
message.

## kfi_sendmsg

The kfi_sendmsg call supports data transfers over both connected and
unconnected endpoints, with the ability to control the send operation
per call through the use of flags.  The kfi_sendmsg function takes a
`struct kfi_msg` as input.

{% highlight c %}
struct kfi_msg {
	enum kfi_iov_type	type;
	union {
		const struct kvec	*msg_iov;
		const struct bio_vec	*msg_biov;
	};
	void			**desc;
	size_t			iov_count;
	kfi_addr_t		addr;
	void			*context;
	uint64_t		data;
};
{% endhighlight %}

## kfi_inject

The send inject call is an optimized version of kfi_send.  The
kfi_inject function behaves as if the KFI_INJECT transfer flag were
set, and KFI_COMPLETION were not.  That is, the data buffer is
available for reuse immediately on returning from from kfi_inject, and
no completion event will be generated for this send.  The completion
event will be suppressed even if the endpoint has not been configured
with KFI_COMPLETION.  See the flags discussion below for more details.

## kfi_senddata

The send data call is similar to kfi_send, but allows for the sending
of remote CQ data (see KFI_REMOTE_CQ_DATA flag) as part of the
transfer.

## kfi_recv

The kfi_recv call posts a data buffer to the receive queue of the
corresponding endpoint.  Posted receives are searched in the order in
which they were posted in order to match sends.
Message boundaries are maintained.  The order in which
the receives complete is dependent on
the endpoint type and protocol.  For unconnected endpoints, the
src_addr parameter can be used to indicate that a buffer should be
posted to receive incoming data from a specific remote endpoint.

## kfi_recvv

The kfi_recvv call adds support for a scatter-gather list to kfi_recv.
The kfi_recvv posts the set of data buffers referenced by the iov
parameter to a receive incoming data.

## kfi_recvmsg

The kfi_recvmsg call supports posting buffers over both connected and
unconnected endpoints, with the ability to control the receive
operation per call through the use of flags.  The kfi_recvmsg function
takes a struct kfi_msg as input.

# FLAGS

The kfi_recvmsg and kfi_sendmsg calls allow the user to specify flags
which can change the default message handling of the endpoint.  Flags
specified with kfi_recvmsg / kfi_sendmsg override most flags previously
configured with the endpoint, except where noted (see kfi_endpoint).
The following list of flags are usable with kfi_recvmsg and/or
kfi_sendmsg.

*KFI_REMOTE_CQ_DATA*
: Applies to kfi_sendmsg and kfi_senddata.  Indicates
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
: Applies to kfi_sendmsg.  Indicates that the outbound data buffer
  should be returned to user immediately after the send call returns,
  even if the operation is handled asynchronously.  This may require
  that the underlying provider implementation copy the data into a
  local buffer and transfer out of that buffer.

*KFI_MULTI_RECV*
: Applies to posted receive operations.  This flag allows the user to
  post a single buffer that will receive multiple incoming messages.
  Received messages will be packed into the receive buffer until the
  buffer has been consumed.  Use of this flag may cause a single
  posted receive operation to generate multiple events as messages are
  placed into the buffer.  The placement of received data into the
  buffer may be subjected to provider specific alignment restrictions.
  The buffer will be freed from the endpoint when the available buffer
  space falls below the network's MTU size (see
  KFI_OPT_MIN_MULTI_RECV).

*KFI_FENCE*
: Applies to transmits.  Indicates that the requested operation, also
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
