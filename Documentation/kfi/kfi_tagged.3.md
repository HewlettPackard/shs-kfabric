---
layout: page
title: kfi_tagged(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_tagged \- Tagged data transfer operations

kfi_trecv / kfi_trecvv / kfi_trecvmsg
:   Post a buffer to receive an incoming message

kfi_tsend / kfi_tsendv / kfi_tsendmsg
kfi_tinject / kfi_tsenddata
:   Initiate an operation to send a message

kfi_tsearch
:   Initiate a search operation for a buffered receive matching a given tag

# SYNOPSIS

{% highlight c %}
#include <kfi_tagged.h>

ssize_t
kfi_trecv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
	  kfi_addr_t src_addr, uint64_t tag, uint64_t ignore, void *context)

ssize_t
kfi_trecvv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	   size_t count, kfi_addr_t src_addr, uint64_t tag, uint64_t ignore,
	   void *context)

ssize_t
kfi_trecvmsg(struct kfid_ep *ep, const struct kfi_msg_tagged *msg,
	     uint64_t flags)

ssize_t
kfi_tsend(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
	  kfi_addr_t dest_addr, uint64_t tag, void *context)

ssize_t
kfi_tsendv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	   size_t count, kfi_addr_t dest_addr, uint64_t tag, void *context)

ssize_t
kfi_tsendmsg(struct kfid_ep *ep, const struct kfi_msg_tagged *msg,
	     uint64_t flags)

ssize_t
kfi_tinject(struct kfid_ep *ep, const void *buf, size_t len,
	    kfi_addr_t dest_addr, uint64_t tag)

ssize_t
kfi_tsenddata(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
	      uint64_t data, kfi_addr_t dest_addr, uint64_t tag, void *context)

{% endhighlight %}

# ARGUMENTS

*fid*
: Kfabric endpoint on which to initiate tagged communication operation.

*buf*
: Data buffer to send or receive.

*len*
: Length of data buffer to send or receive.

*iov*
: Vectored data buffer.

*count*
: Count of vectored data entries.

*tag*
: Tag associated with the message.

*ignore*
: Mask of bits to ignore applied to the tag for receive operations.

*desc*
: Memory descriptor associated with the data buffer

*data*
: Remote CQ data to transfer with the sent data.

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

Tagged messages are data transfers which carry a key or tag with the
message buffer.  The tag is used at the receiving endpoint to match
the incoming message with a corresponding receive buffer.  Message
tags match when the receive buffer tag is the same as the send buffer
tag with the ignored bits masked out.  This can be stated as:

{% highlight c %}
send_tag & ~ignore == recv_tag & ~ignore
{% endhighlight %}

In general, message tags are checked against receive buffers in the
order in which messages have been posted to the endpoint.  See the
ordering discussion below for more details.

The send functions -- kfi_tsend, kfi_tsendv, kfi_tsendmsg,
kfi_tinject, and kfi_tsenddata -- are used
to transmit a tagged message from one endpoint to another endpoint.
The main difference between send functions are the number and type of
parameters that they accept as input.  Otherwise, they perform the
same general function.

The receive functions -- kfi_trecv, kfi_trecvv, kfi_recvmsg
-- post a data buffer to an endpoint to receive inbound tagged
messages.  Similar to the send operations, receive operations operate
asynchronously.  Users should not touch the posted data buffer(s)
until the receive operation has completed.  Posted receive buffers are
matched with inbound send messages based on the tags associated with
the send and receive buffers.

Completed message operations are reported to the user through one or
more event collectors associated with the endpoint.  Users provide
context which are associated with each operation, and is returned to
the user as part of the event completion.  See kfi_eq for completion
event details.

## kfi_tsend

The call kfi_tsend transfers the data contained in the user-specified
data buffer to a remote endpoint, with message boundaries being
maintained.  The local endpoint must be connected to a remote endpoint
or destination before kfi_tsend is called.  Unless the endpoint has
been configured differently, the data buffer passed into kfi_tsend must
not be touched by the application until the kfi_tsend call completes
asynchronously.

## kfi_tsendv

The kfi_tsendv call adds support for a scatter-gather list to kfi_tsend.
The kfi_sendv transfers the set of data buffers
referenced by the iov parameter to a remote endpoint as a single
message.

## kfi_tsendmsg

The kfi_tsendmsg call supports data transfers over both connected and
unconnected endpoints, with the ability to control the send operation
per call through the use of flags.  The kfi_tsendmsg function takes a
struct kfi_msg_tagged as input.

{% highlight c %}
struct kfi_msg_tagged {
	enum kfi_iov_type	type;
	union {
		const struct kvec	*msg_iov;
		const struct bio_vec	*msg_biov;
	};
	void			**desc;
	size_t			iov_count;
	kfi_addr_t		addr;
	uint64_t		tag;
	uint64_t		ignore;
	void			*context;
	uint64_t		data;
};
{% endhighlight %}

## kfi_tinject

The tagged inject call is an optimized version of kfi_tsend.  The
kfi_tinject function behaves as if the KFI_INJECT transfer flag were
set, and KFI_COMPLETION were not.  That is, the data buffer is
available for reuse immediately on returning from from kfi_tinject, and
no completion event will be generated for this send.  The completion
event will be suppressed even if the endpoint has not been configured
with KFI_COMPLETION.  See the flags discussion below for more details.

## kfi_tsenddata

The tagged send data call is similar to kfi_tsend, but allows for the
sending of remote CQ data (see KFI_REMOTE_CQ_DATA flag) as part of the
transfer.

## kfi_trecv

The kfi_trecv call posts a data buffer to the receive queue of the
corresponding endpoint.  Posted receives are searched in the order in
which they were posted in order to match sends.  Message boundaries are
maintained.  The order in which the receives complete is dependent on
the endpoint type and protocol.

## kfi_trecvv

The kfi_trecvv call adds support for a scatter-gather list to kfi_trecv.
The kfi_trecvv posts the set of data buffers referenced by the iov
parameter to a receive incoming data.

## kfi_trecvmsg

The kfi_trecvmsg call supports posting buffers over both connected and
unconnected endpoints, with the ability to control the receive
operation per call through the use of flags.  The kfi_trecvmsg function
takes a struct kfi_msg_tagged as input.

# FLAGS

The kfi_trecvmsg and kfi_tsendmsg calls allow the user to specify flags
which can change the default message handling of the endpoint.  Flags
specified with kfi_trecvmsg / kfi_tsendmsg override most flags
previously configured with the endpoint, except where noted (see
kfi_endpoint).  The following list of flags are usable with kfi_trecvmsg
and/or kfi_tsendmsg.

*KFI_REMOTE_CQ_DATA*
: Applies to kfi_tsendmsg and kfi_tsenddata.  Indicates
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
: Applies to kfi_tsendmsg.  Indicates that the outbound data buffer
  should be returned to user immediately after the send call returns,
  even if the operation is handled asynchronously.  This may require
  that the underlying provider implementation copy the data into a
  local buffer and transfer out of that buffer.

*KFI_REMOTE_COMPLETE*
: Applies to kfi_tsendmsg.  Indicates that a completion should not be
  generated until the operation has completed on the remote side.

*KFI_FENCE*
: Applies to transmits.  Indicates that the requested operation, also
  known as the fenced operation, be deferred until all previous operations
  targeting the same target endpoint have completed.

# RETURN VALUE

The tagged send and receive calls return 0 on success.  On error, a
negative value corresponding to kfabric _errno _ is returned. Kfabric
errno values are defined in `kfi_errno.h`.


# ERRORS

*-KFI_EAGAIN*
: Indicates that the underlying provider currently lacks the resources
  needed to initiate the requested operation.  This may be the result
  of insufficient internal buffering, in the case of KFI_INJECT,
  or processing queues are full.  The operation may be retried after
  additional provider resources become available, usually through the
  completion of currently outstanding operations.

*-KFI_EINVAL*
: Indicates that an invalid argument was supplied by the user.

*-KFI_EOTHER*
: Indicates that an unspecified error occurred.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_eq`(3)](kfi_eq.3.html)
