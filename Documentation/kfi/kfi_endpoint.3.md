---
layout: page
title: kfi_endpoint(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_endpoint \- Kfabric endpoint operations

kfi_endpoint / kfi_scalable_ep / kfi_passive_ep / kfi_close
:   Allocate or close an endpoint.

kfi_ep_bind
:   Associate an endpoint with an event queue, completion queue,
    counter, address vector, or memory region

kfi_scalable_ep_bind
:   Associate a scalable endpoint with an address vector

kfi_pep_bind
:   Associate a passive endpoint with an event queue

kfi_enable
:   Transitions an endpoint into an active state.

kfi_cancel
:   Cancel a pending asynchronous data transfer

kfi_alias
:   Create an alias to the endpoint

kfi_control
:   Control endpoint operation.

kfi_getopt / kfi_setopt
:   Get or set endpoint options.

kfi_rx_context / kfi_tx_context / kfi_srx_context  / kfi_stx_context
:   Open a transmit or receive context.

# SYNOPSIS

{% highlight c %}
#include <kfabric.h>

#include <kfi_endpoint.h>

int
kfi_endpoint(struct kfid_domain *domain, struct kfi_info *info,
	     struct kfid_ep **ep, void *context)

int
kfi_scalable_ep(struct kfid_domain *domain, struct kfi_info *info,
		struct kfid_ep **sep, void *context)

int
kfi_passive_ep(struct kfid_fabric *fabric, struct kfi_info *info,
	       struct kfid_pep **pep, void *context)

int
kfi_tx_context(struct kfid_ep *ep, int index, struct kfi_tx_attr *attr,
	       struct kfid_ep **tx_ep, void *context)

int
kfi_rx_context(struct kfid_ep *ep, int index, struct kfi_rx_attr *attr,
	       struct kfid_ep **rx_ep, void *context)

int
kfi_stx_context(struct kfid_domain *domain, struct kfi_tx_attr *attr,
		struct kfid_stx **stx, void *context)

int
kfi_srx_context(struct kfid_domain *domain, struct kfi_rx_attr *attr,
		struct kfid_ep **rx_ep, void *context)

int
kfi_close(struct kfid *fid)

int
kfi_ep_bind(struct kfid_ep *ep, struct kfid *bfid, uint64_t flags)

int
kfi_scalable_ep_bind(struct kfid_ep *sep, struct kfid *bfid, uint64_t flags)

int
kfi_pep_bind(struct kfid_pep *pep, struct kfid *bfid, uint64_t flags)

int
kfi_enable(struct kfid_ep *ep)

ssize_t
kfi_cancel(struct kfid *fid, void *context)

int kfi_alias(struct kfid *fid, struct kfid **alias_fid,
			   uint64_t flags)

int
kfi_control(struct kfid *fid, int command, void *arg)

int
kfi_getopt(struct kfid *fid, int level, int optname, void *optval,
	   size_t *optlen)

int
kfi_setopt(struct kfid *fid, int level, int optname, const void *optval,
	   size_t optlen)

{% endhighlight %}

# ARGUMENTS

*fid*
: On creation, specifies a kfabric or access domain.  On bind,
  identifies the event queue, completion queue or address vector to
  bind to the endpoint.

*info*
: Details about the fabric interface endpoint to be opened, obtained
  from kfi_getinfo.

*ep*
: A kfabric endpoint.

*sep*
: A scalable kfabric endpoint.

*pep*
: A passive kfabric endpoint.

*fid*
: Kfabric identifier of an associated resource.

*context*
: Context associated with the endpoint or asynchronous operation.

*flags*
: Additional flags to apply to the operation.

*command*
: Command of control operation to perform on endpoint.

*arg*
: Optional control argument

*level*
: Protocol level at which the desired option resides.

*optname*
: The protocol option to read or set.

*optval*
: The option value that was read or to set.

*optlen*
: The size of the optval buffer.

# DESCRIPTION

Endpoints are transport level communication portals.  There are two
types of endpoints: active and passive.  Passive endpoints belong to a
fabric domain and are used to listen for incoming connection requests.
Active endpoints belong to access domains and can perform data
transfers.

Active endpoints may be connection-oriented or connectionless, and may
provide data reliability.  The data transfer interfaces -- messages (kfi_msg),
tagged messages (kfi_tagged), RMA (kfi_rma), and atomics (kfi_atomic) --
are associated with active endpoints.  In basic configurations, an
active endpoint has transmit and receive queues.  In general, operations
that generate traffic on the fabric are posted to the transmit queue.
This includes all RMA and atomic operations, along with sent messages and
sent tagged messages.  Operations that post buffers for receiving incoming
data are submitted to the receive queue.

Active endpoints are created in the disabled state.  They must
transition into an enabled state before accepting data transfer
operations, including posting of receive buffers.  The kfi_enable call
is used to transition an endpoint into an active enabled state.  The
kfi_connect and kfi_accept calls will also transition an endpoint into
the enabled state, if it is not already active.

In order to transition an endpoint into an enabled state, it must be
bound to one or more fabric resources.  An endpoint that will generate
asynchronous completions, either through data transfer operations or
communication establishment events, must be bound to the appropriate
completion queues or event queues before being enabled.

Once an endpoint has been activated, it may be associated with memory
regions and address vectors.  Receive buffers may be posted to it, and
calls may be made to connection establishment routines.
Connectionless endpoints may also perform data transfers.

The behavior of an endpoint may be adjusted by setting its control
data and protocol options.  This allows the underlying provider to
redirect function calls to implementations optimized to meet the
desired application behavior.

## kfi_endpoint / kfi_passive_ep / kfi_scalable_ep

kfi_endpoint allocates a new active endpoint.  kfi_passive_ep allocates a
new passive endpoint.  kfi_scalable_ep allocates a scalable endpoint.
The properties and behavior of the endpoint are defined based on the
provided struct kfi_info.  See kfi_getinfo for additional details on
kfi_info.  kfi_info flags that control the operation of an endpoint are
defined below. See section SCALABLE ENDPOINTS.

If an active endpoint is associated with a connection request, the
kfi_info connreq must reference the corresponding request.

## kfi_close

Closes an endpoint and release all resources associated with it.

When closing a scalable endpoint, there must be no opened transmit contexts, or
receive contexts associated with the scalable endpoint.  If resources are still
associated with the scalable endpoint when attempting to close, the call will
return -KFI_EBUSY.

## kfi_ep_bind

kfi_ep_bind is used to associate an endpoint with hardware resources.
The common use of kfi_ep_bind is to direct asynchronous operations
associated with an endpoint to a completion queue.  An endpoint must
be bound with CQs capable of reporting completions for any
asynchronous operation initiated on the endpoint.  This is true even
for endpoints which are configured to suppress successful completions,
in order that operations that complete in error may be reported to the
user.  For passive endpoints, this requires binding the endpoint with
an EQ that supports the communication management (CM) domain.

An active endpoint may direct asynchronous completions to different
CQs, based on the type of operation.  This is specified using
kfi_ep_bind flags.  The following flags may be used separately or OR'ed
together when binding an endpoint to a completion domain CQ.

*KFI_TRANSMIT*
: Directs the completion of outbound data transfer requests to the
  specified completion queue.  This includes send message, RMA, and
  atomic operations.  The KFI_SEND flag may be used interchangeably.

*KFI_RECV*
: Directs the notification of inbound data transfers to the specified
  completion queue.  This includes received messages.

*KFI_COMPLETION*
: By default, data transfer operations generate completion entries
  into a completion queue after they have successfully completed.
  Applications can use this bind flag to selectively enable
  when completions are generated.  If KFI_COMPLETION is specified,
  data transfer operations will not generate entries for successful
  completions unless KFI_COMPLETION is set as an operational flag
  for the given operation.  KFI_COMPLETION must be OR'ed with
  KFI_SEND and/or KFI_RECV flags.

  When set the user must determine when a request that does NOT have
  KFI_COMPLETION set has completed indirectly, usually based on the
  completion of a subsequent operation.  Use of this flag may improve
  performance by allowing the provider to avoid writing a completion
  entry for every operation.

  Example: An application can selectively generate send completions by
  using the following general approach:

  {% highlight c %}
  kfi_tx_attr::op_flags = 0; // default - no completion
  kfi_ep_bind(ep, cq, KFI_SEND | KFI_COMPLETION);
  kfi_send(ep, ...);                   // no completion
  kfi_sendv(ep, ...);                  // no completion
  kfi_sendmsg(ep, ..., KFI_COMPLETION); // completion!
  {% endhighlight %}

  Example: An application can selectively disable send completions by
  modifying the operational flags:

  {% highlight c %}
  kfi_tx_attr::op_flags = KFI_COMPLETION; // default - completion
  kfi_ep_bind(ep, cq, KFI_SEND | KFI_COMPLETION);
  kfi_send(ep, ...);       // completion
  kfi_sendv(ep, ...);      // completion
  kfi_sendmsg(ep, ..., 0); // no completion!
  {% endhighlight %}

An endpoint may also, or instead, be bound to a fabric counter.  When
binding an endpoint to a counter, the following flags may be specified.

*KFI_SEND*
: Increments the specified counter whenever a successful message is
  transferred over the endpoint.  Sent messages include both tagged
  and normal message operations.

*KFI_RECV*
: Increments the specified counter whenever a successful message is
  received over the endpoint.  Received messages include both tagged
  and normal message operations.

*KFI_READ*
: Increments the specified counter whenever a successful RMA read or
  atomic fetch operation is initiated from the endpoint.

*KFI_WRITE*
: Increments the specified counter whenever a successful RMA write or
  atomic operation is initiated from the endpoint.

*KFI_REMOTE_READ*
: Increments the specified counter whenever a successful RMA read or
  atomic fetch operation is initiated from a remote endpoint that
  targets the given endpoint.

*KFI_REMOTE_WRITE*
: Increments the specified counter whenever a successful RMA write or
  atomic operation is initiated from a remote endpoint that targets
  the given endpoint.

Connectionless endpoints must be bound to a single address vector.
If an endpoint is using a shared transmit and/or receive context, the
shared contexts must be bound to the endpoint.  CQs, counters, AV, and
shared contexts must be bound to endpoints before they are enabled.

## kfi_scalable_ep_bind

kfi_scalable_ep_bind is used to associate a scalable endpoint with an
address vector. See section on SCALABLE ENDPOINTS.  A scalable
endpoint has a single transport level address and can support multiple
transmit and receive contexts. The transmit and receive contexts share
the transport-level address. Address vectors that are bound to
scalable endpoints are implicitly bound to any transmit or receive
contexts created using the scalable endpoint.

## kfi_enable

This call transitions the endpoint into an enabled state.  An endpoint
must be enabled before it may be used to perform data transfers.
Enabling an endpoint typically results in hardware resources being
assigned to it.

Calling connect or accept on an endpoint will implicitly enable an
endpoint if it has not already been enabled.

## kfi_cancel

kfi_cancel attempts to cancel an outstanding asynchronous operation.
The endpoint must have been configured to support cancelable
operations -- see KFI_CANCEL flag -- in order for this call to succeed.
Canceling an operation causes the fabric provider to search for the
operation and, if it is still pending, complete it as having been
canceled.  If multiple outstanding operations match the context
parameter, only one will be canceled.  In this case, the operation
which is canceled is provider specific.  The cancel operation will
complete within a bounded period of time.

## kfi_alias

This call creates an alias to the specified endpoint.  Conceptually,
an endpoint alias provides an alternate software path from the
application to the underlying provider hardware.  Applications
configure an alias endpoint with data transfer flags, specified
through the kfi_alias call.  Typically, the data transfer flags will be
different than those assigned to the actual endpoint.  The alias
mechanism allows a single endpoint to have multiple optimized software
interfaces.  All allocated aliases must be closed for the underlying
endpoint to be released.

## kfi_control

The control operation is used to adjust the default behavior of an
endpoint.  It allows the underlying provider to redirect function
calls to implementations optimized to meet the desired application
behavior.  As a result, calls to kfi_ep_control must be serialized
against all other calls to an endpoint.

The base operation of an endpoint is selected during creation using
struct kfi_info.  The following control commands and arguments may be
assigned to an endpoint.

**KFI_GETOPSFLAG -- uint64_t *flags**
: Used to retrieve the current value of flags associated with data
  transfer operations initiated on the endpoint.  See below for a list
  of control flags.

**KFI_SETOPSFLAG -- uint64_t *flags**
: Used to change the data transfer operation flags associated with an
  endpoint.  The KFI_READ, KFI_WRITE, KFI_SEND, KFI_RECV flags indicate
  the type of data transfer that the flags should apply to, with other
  flags OR'ed in.  Valid control flags are defined below.

## kfi_getopt / kfi_setopt

Endpoint protocol operations may be retrieved using kfi_getopt or set
using kfi_setopt.  Applications specify the level that a desired option
exists, identify the option, and provide input/output buffers to get
or set the option.  kfi_setopt provides an application a way to adjust
low-level protocol and implementation specific details of an endpoint.

The following option levels and option names and parameters are defined.

*KFI_OPT_ENDPOINT*

- *KFI_OPT_MIN_MULTI_RECV - size_t*
: Defines the minimum receive buffer space available when the receive
  buffer is automatically freed (see KFI_MULTI_RECV).  Modifying this
  value is only guaranteed to set the minimum buffer space needed on
  receives posted after the value has been changed.  It is recommended
  that applications that want to override the default MIN_MULTI_RECV
  value set this option before enabling the corresponding endpoint.

## kfi_rx_size_left

The kfi_rx_size_left call returns a lower bound on the number of receive
operations that may be posted to the given endpoint without that operation
returning -KFI_EAGAIN.  Depending on the specific details of the subsequently
posted receive operations (e.g., number of iov entries, which receive function
is called, etc.), it may be possible to post more receive operations than
originally indicated by kfi_rx_size_left.

## kfi_tx_size_left

The kfi_tx_size_left call returns a lower bound on the number of transmit
operations that may be posted to the given endpoint without that operation
returning -KFI_EAGAIN.  Depending on the specific details of the subsequently
posted transmit operations (e.g., number of iov entries, which transmit
function is called, etc.), it may be possible to post more transmit operations
than originally indicated by kfi_tx_size_left.

# ENDPOINT ATTRIBUTES

The kfi_ep_attr structure defines the set of attributes associated with
an endpoint.

{% highlight c %}
struct kfi_ep_attr {
	enum kfi_ep_type	type;
	uint32_t		protocol;
	uint32_t		protocol_version;
	size_t			max_msg_size;
	size_t			msg_prefix_size;
	size_t			max_order_raw_size;
	size_t			max_order_war_size;
	size_t			max_order_waw_size;
	uint64_t		mem_tag_format;
	size_t			tx_ctx_cnt;
	size_t			rx_ctx_cnt;
	size_t			auth_key_size;
	uint8_t			*auth_key;
};
{% endhighlight %}

## Protocol

Specifies the low-level end to end protocol employed by the provider.
A matching protocol must be used by communicating endpoints to ensure
interoperability.  The following protocol values are defined.
Provider specific protocols are also allowed.  Provider specific
protocols will be indicated by having the upper bit of the
protocol value set to one.

*KFI_PROTO_UNSPEC*
: The protocol is not specified.  This is usually provided as input,
  with other attributes of the socket or the provider selecting the
  actual protocol.

*KFI_PROTO_RDMA_CM_IB_RC*
: The protocol runs over Infiniband reliable-connected queue pairs,
  using the RDMA CM protocol for connection establishment.

*KFI_PROTO_IWARP*
: The protocol runs over the Internet wide area RDMA protocol transport.

*KFI_PROTO_IB_UD*
: The protocol runs over Infiniband unreliable datagram queue pairs.

*KFI_PROTO_PSMX*
: The protocol is based on an Intel proprietary protocol known as PSM,
  performance scaled messaging.  PSMX is an extended version of the
  PSM protocol to support the libfabric interfaces.

*KFI_PROTO_UDP*
: The protocol sends and receives UDP datagrams.  For example, an
  endpoint using *KFI_PROTO_UDP* will be able to communicate with a
  remote peer that is using Berkeley *SOCK_DGRAM* sockets using
  *KIPPROTO_UDP*.

*KFI_PROTO_SOCK_TCP*
: The protocol is layered over TCP packets.

## protocol_version - Protocol Version

Identifies which version of the protocol is employed by the provider.
The protocol version allows providers to extend an existing protocol,
by adding support for additional features or functionality for example,
in a backward compatible manner.  Providers that support different versions
of the same protocol should inter-operate, but only when using the
capabilities defined for the lesser version.

## max_msg_size - Max Message Size

Defines the maximum size for an application data transfer as a single
operation.

## inject_size - Inject Size

Defines the default inject operation size (see the KFI_INJECT flag)
that an endpoint will support.  This value applies per send operation.

## total_buffered_recv - Total Buffered Receive

Defines the total available space allocated by the provider to buffer
received messages (see the KFI_BUFFERED_RECV flag).

## msg_prefix_size - Message Prefix Size

Specifies the size of any required message prefix buffer space.  This
field will be 0 unless the KFI_MSG_PREFIX mode is enabled.  If
msg_prefix_size is > 0 the specified value will be a multiple of
8-bytes.

## Max RMA Ordered Size

The maximum ordered size specifies the delivery order of transport
data into target memory for RMA and atomic operations.  Data ordering
is separate, but dependent on message ordering (defined below).  Data
ordering is unspecified where message order is not defined.

Data ordering refers to the access of target memory by subsequent
operations.  When back to back RMA read or write operations access the
same registered memory location, data ordering indicates whether the
second operation reads or writes the target memory after the first
operation has completed.  Because RMA ordering applies between two
operations, and not within a single data transfer, ordering is defined
per byte-addressable memory location.  I.e.  ordering specifies
whether location X is accessed by the second operation after the first
operation.  Nothing is implied about the completion of the first
operation before the second operation is initiated.

In order to support large data transfers being broken into multiple packets
and sent using multiple paths through the fabric, data ordering may be
limited to transfers of a specific size or less.  Providers specify when
data ordering is maintained through the following values.  Note that even
if data ordering is not maintained, message ordering may be.

*max_order_raw_size*
: Read after write size.  If set, an RMA or atomic read operation
  issued after an RMA or atomic write operation, both of which are
  smaller than the size, will be ordered.  The RMA or atomic read
  operation will see the results of the previous RMA or atomic write.

*max_order_war_size*
: Write after read size.  If set, an RMA or atomic write operation
  issued after an RMA or atomic read operation, both of which are
  smaller than the size, will be ordered.  The RMA or atomic read
  operation will see the initial value of the target memory region
  before a subsequent RMA or atomic write updates the value.

*max_order_waw_size*
: Write after write size.  If set, an RMA or atomic write operation
  issued after an RMA or atomic write operation, both of which are
  smaller than the size, will be ordered.  The target memory region
  will reflect the results of the second RMA or atomic write.

An order size value of 0 indicates that ordering is not guaranteed.
A value of -1 guarantees ordering for any data size.

## mem_tag_format - Memory Tag Format

The memory tag format is a bit array used to convey the number of
tagged bits supported by a provider.  Additionally, it may be used to
divide the bit array into separate fields.  The mem_tag_format
optionally begins with a series of bits set to 0, to signify bits
which are ignored by the provider.  Following the initial prefix of
ignored bits, the array will consist of alternating groups of bits set
to all 1's or all 0's.  Each group of bits corresponds to a tagged
field.  The implication of defining a tagged field is that when a mask
is applied to the tagged bit array, all bits belonging to a single
field will either be set to 1 or 0, collectively.

For example, a mem_tag_format of 0x30FF indicates support for 14
tagged bits, separated into 3 fields.  The first field consists of
2-bits, the second field 4-bits, and the final field 8-bits.  Valid
masks for such a tagged field would be a bitwise OR'ing of zero or
more of the following values: 0x3000, 0x0F00, and 0x00FF.

By identifying fields within a tag, a provider may be able to optimize
their search routines.  An application which requests tag fields must
provide tag masks that either set all mask bits corresponding to a
field to all 0 or all 1.  When negotiating tag fields, an application
can request a specific number of fields of a given size.  A provider
must return a tag format that supports the requested number of fields,
with each field being at least the size requested, or fail the
request.  A provider may increase the size of the fields.

It is recommended that field sizes be ordered from smallest to
largest.  A generic, unstructured tag and mask can be achieved by
requesting a bit array consisting of alternating 1's and 0's.

## msg_order - Message Ordering

Message ordering refers to the order in which transport layer headers
(as viewed by the application) are processed.  Relaxed message order
enables data transfers to be sent and received out of order, which may
improve performance by utilizing multiple paths through the fabric
from the initiating endpoint to a target endpoint.  Message order
applies only between a single source and destination endpoint pair.
Ordering between different target endpoints is not defined.

Message order is determined using a set of ordering bits.  Each set
bit indicates that ordering is maintained between data transfers of
the specified type.  Message order is defined for [read | write |
send] operations submitted by an application after [read | write |
send] operations.

Message ordering only applies to the processing of transport headers.
Message ordering is necessary, but does not guarantee the order in
which data is sent or received by the transport layer.

*KFI_ORDER_RAR*
: Read after read.  If set, RMA and atomic read operations are
  processed in the order submitted relative to other RMA and atomic
  read operations.  If not set, RMA and atomic reads may be processed
  out of order from their submission.

*KFI_ORDER_RAW*
: Read after write.  If set, RMA and atomic read operations are
  processed in the order submitted relative to RMA and atomic write
  operations.  If not set, RMA and atomic reads may be processed ahead
  of RMA and atomic writes.

*KFI_ORDER_RAS*
: Read after send.  If set, RMA and atomic read operations are
  processed in the order submitted relative to message send
  operations, including tagged sends.  If not set, RMA and atomic
  reads may be processed ahead of sends.

*KFI_ORDER_WAR*
: Write after read.  If set, RMA and atomic write operations are
  processed in the order submitted relative to RMA and atomic read
  operations.  If not set, RMA and atomic writes may be processed
  ahead of RMA and atomic reads.

*KFI_ORDER_WAW*
: Write after write.  If set, RMA and atomic write operations are
  processed in the order submitted relative to other RMA and atomic
  write operations.  If not set, RMA and atomic writes may be
  processed out of order from their submission.

*KFI_ORDER_WAS*
: Write after send.  If set, RMA and atomic write operations are
  processed in the order submitted relative to message send
  operations, including tagged sends.  If not set, RMA and atomic
  writes may be processed ahead of sends.

*KFI_ORDER_SAR*
: Send after read.  If set, message send operations, including tagged
  sends, are processed in order submitted relative to RMA and atomic
  read operations.  If not set, message sends may be processed ahead
  of RMA and atomic reads.

*KFI_ORDER_SAW*
: Send after write.  If set, message send operations, including tagged
  sends, are processed in order submitted relative to RMA and atomic
  write operations.  If not set, message sends may be processed ahead
  of RMA and atomic writes.

*KFI_ORDER_SAS*
: Send after send.  If set, message send operations, including tagged
  sends, are processed in the order submitted relative to other
  message send.  If not set, message sends may be processed out of
  order from their submission.

## comp_order - Completion Ordering

Completion ordering refers to the order in which completed requests are
written into the completion queue.  Completion ordering is similar to
message order.  Relaxed completion order may enable faster reporting of
completed transfers, allow acknowledgments to be sent over different
fabric paths, and support more sophisticated retry mechanisms.
This can result in lower-latency completions, particularly when
using unconnected endpoints.  Strict completion ordering may require
that providers queue completed operations or limit available optimizations

For transmit requests, completion ordering depends on the endpoint
communication type.  For unreliable communication, completion ordering
applies to all data transfer requests submitted to an endpoint.
For reliable communication, completion ordering only applies to requests
that target a single destination endpoint.  Completion ordering of
requests that target different endpoints over a reliable transport
is not defined.

Applications should specify the completion ordering that they support
or require.  Providers should return the completion order that they
actually provide, with the constraint that the returned ordering is
stricter than that specified by the application.  Supported completion
order values are:

*KFI_ORDER_NONE*
: No ordering is defined for completed operations.  Requests submitted
  to the transmit and receive queues may complete in any order.

*KFI_ORDER_STRICT*
: Requests complete in the order in which they are submitted, in the
  case of transmit requests, or processed, in the case of receive
  operations, by the provider.  Transmit operations complete in the
  order in which the requests were submitted.  Receive operations
  complete in order, subject to buffer matching.

## tx_ctx_cnt - Transmit Context Count

Number of transmit contexts to associate with the endpoint.  If not
specified (0), 1 context will be assigned if the endpoint supports
outbound transfers.  Transmit contexts are independent transmit queues
that may be separately configured.  Each transmit context may be bound
to a separate CQ, and no ordering is defined between contexts.
Additionally, no synchronization is needed when accessing contexts in
parallel.

If the count is set to the value KFI_SHARED_CONTEXT, the endpoint will
be configured to use a shared transmit context, if supported by the
provider.  Providers that do not support shared transmit contexts will
fail the request.

See the scalable endpoint and shared contexts sections for additional
details.

## rx_ctx_cnt - Receive Context Count

Number of receive contexts to associate with the endpoint.  If not
specified, 1 context will be assigned if the endpoint supports inbound
transfers.  Receive contexts are independent processing queues that
may be separately configured.  Each receive context may be bound to a
separate CQ, and no ordering is defined between contexts.
Additionally, no synchronization is needed when accessing contexts in
parallel.

If the count is set to the value KFI_SHARED_CONTEXT, the endpoint will
be configured to use a shared receive context, if supported by the
provider.  Providers that do not support shared receive contexts will
fail the request.

See the scalable endpoint and shared contexts sections for additional
details.

# SCALABLE ENDPOINTS

A scalable endpoint is a communication portal that supports multiple
transmit and receive contexts.  Scalable endpoints are loosely modeled
after the networking concept of transmit/receive side scaling, also
known as multi-queue.  Support for scalable endpoints is domain
specific.  Scalable endpoints may improve the performance of
multi-threaded and parallel applications, by allowing threads to
access independent transmit and receive queues.  A scalable endpoint
has a single transport level address, which can reduce the memory
requirements needed to store remote addressing data, versus using
standard endpoints. Scalable endpoints cannot be used directly for
communication operations, and require the application to explicitly
create transmit and receive contexts as described below.

## kfi_tx_context

Transmit contexts are independent transmit queues.  Ordering and
synchronization between contexts are not defined.  Conceptually a
transmit context behaves similar to a send-only endpoint.  A transmit
context may be configured with relaxed capabilities, and has its own
completion queue.  The number of transmit contexts associated with an
endpoint is specified during endpoint creation.

The kfi_tx_context call is used to retrieve a specific context,
identified by an index.  Providers may dynamically allocate contexts
when kfi_tx_context is called, or may statically create all contexts
when kfi_endpoint is invoked.  By default, a transmit context inherits
the properties of its associated endpoint.  However, applications may
request context specific attributes through the attr parameter.
Support for per transmit context attributes is provider specific and
not guaranteed.  Providers will return the actual attributes assigned
to the context through the attr parameter, if provided.

{% highlight c %}
struct kfi_tx_attr {
	uint64_t		caps;
	uint64_t		mode;
	uint64_t		op_flags;
	uint64_t		msg_order;
	uint64_t		comp_order;
	size_t			inject_size;
	size_t			size;
	size_t			iov_limit;
	size_t			rma_iov_limit;
	uint32_t		tclass;
};
{% endhighlight %}

*caps*
: The requested capabilities of the context.  The capabilities must be
  a subset of those requested of the associated endpoint.  See the
  CAPABILITIES section if kfi_getinfo(3) for capability details.

*mode*
: The operational mode bits of the context.  The mode bits will be a
  subset of those associated with the endpoint.  See the MODE section
  of kfi_getinfo(3) for details.

*op_flags*
: Flags that control the operation of operations submitted against the
  context.  Applicable flags are listed in the Operation Flags
  section.

*msg_order*
: The message ordering requirements of the context.  The message
  ordering must be the same or more relaxed than those specified of
  the associated endpoint.  See the kfi_endpoint Message Ordering
  section.

*comp_order*
: The completion ordering requirements of the context.  The completion
  ordering must be the same or more relaxed than those specified of
  the associated endpoint.  See the kfi_endpoint Completion Ordering
  section.

*inject_size*
: The requested inject operation size (see the KFI_INJECT flag) that
  the context will support.  This value must be equal to or less than
  the inject_size of the associated endpoint.  See the kfi_endpoint
  Inject Size section.

*size*
: The size of the context, in bytes.  The size is usually used as an
  output value by applications wishing to track if sufficient space is
  available in the local queue to post a new operation.

*iov_limit*
: This is the maximum number of IO vectors (scatter-gather elements)
  that a single posted operation may reference.

*rma_iov_limit*
: This is the maximum number of RMA IO vectors (scatter-gather elements)
  that an RMA or atomic operation may reference.  The rma_iov_limit
  corresponds to the rma_iov_count values in RMA and atomic operations.
  See struct kfi_msg_rma and struct kfi_msg_atomic in kfi_rma.3 and
  kfi_atomic.3, for additional details.  This limit applies to both the
  number of RMA IO vectors that may be specified when initiating an
  operation from the local endpoint, as well as the maximum number of
  IO vectors that may be carried in a single request from a remote endpoint.

## kfi_rx_context

Receive contexts are independent receive queues for receiving incoming
data.  Ordering and synchronization between contexts are not
guaranteed.  Conceptually a receive context behaves similar to a
receive-only endpoint.  A receive context may be configured with
relaxed endpoint capabilities, and has its own completion queue.  The
number of receive contexts associated with an endpoint is specified
during endpoint creation.

Receive contexts are often associated with steering flows, that
specify which incoming packets targeting a scalable endpoint to
process.  However, receive contexts may be targeted directly by the
initiator, if supported by the underlying protocol.  Such contexts are
referred to as 'named'.  Support for named contexts must be indicated
by setting the caps KFI_NAMED_RX_CTX capability when the corresponding
endpoint is created.  Support for named receive contexts is
coordinated with address vectors.  See kfi_av(3) and kfi_rx_addr(3).

The kfi_rx_context call is used to retrieve a specific context,
identified by an index.  Providers may dynamically allocate contexts
when kfi_rx_context is called, or may statically create all contexts
when kfi_endpoint is invoked.  By default, a receive context inherits
the properties of its associated endpoint.  However, applications may
request context specific attributes through the attr parameter.
Support for per receive context attributes is provider specific and
not guaranteed.  Providers will return the actual attributes assigned
to the context through the attr parameter, if provided.

{% highlight c %}
struct kfi_rx_attr {
	uint64_t		caps;
	uint64_t		mode;
	uint64_t		op_flags;
	uint64_t		msg_order;
	uint64_t		comp_order;
	size_t			total_buffered_recv;
	size_t			size;
	size_t			iov_limit;
};
{% endhighlight %}

*caps*
: The requested capabilities of the context.  The capabilities must be
  a subset of those requested of the associated endpoint.  See the
  CAPABILITIES section if kfi_getinfo(3) for capability details.

*mode*
: The operational mode bits of the context.  The mode bits will be a
  subset of those associated with the endpoint.  See the MODE section
  of kfi_getinfo(3) for details.

*op_flags*
: Flags that control the operation of operations submitted against the
  context.  Applicable flags are listed in the Operation Flags
  section.

*msg_order*
: The message ordering requirements of the context.  The message
  ordering must be the same or more relaxed than those specified of
  the associated endpoint.  See the kfi_endpoint Message Ordering
  section.

*comp_order*
: The completion ordering requirements of the context.  The completion
  ordering must be the same or more relaxed than those specified of
  the associated endpoint.  See the kfi_endpoint Completion Ordering
  section.

*total_buffered_recv*
: Defines the total available space allocated by the provider to
  buffer received messages on the context.  This value must be less
  than or equal to that specified for the associated endpoint.  See
  the kfi_endpoint Total Buffered Receive section.

*size*
: The size of the context, in bytes.  The size is usually used as an
  output value by applications wishing to track if sufficient space is
  available in the local queue to post a new operation.

*iov_limit*
: This is the maximum number of IO vectors (scatter-gather elements)
  that a single posted operating may reference.

# SHARED CONTEXTS

Shared contexts are transmit and receive contexts explicitly shared
among one or more endpoints.  A shareable context allows an application
to use a single dedicated provider resource among multiple transport
addressable endpoints.  This can greatly reduce the resources needed
to manage communication over multiple endpoints by multiplexing
transmit and/or receive processing, with the potential cost of
serializing access across multiple endpoints.  Support for shareable
contexts is domain specific.

Conceptually, shareable transmit contexts are transmit queues that may be
accessed by many endpoints.  The use of a shared transmit context is
mostly opaque to an application.  Applications must allocate and bind
shared transmit contexts to endpoints, but operations are posted
directly to the endpoint.  Shared transmit contexts are not associated
with completion queues or counters.  Completed operations are posted
to the CQs bound to the endpoint.  An endpoint may only
be associated with a single shared transmit context.

Unlike shared transmit contexts, applications interact directly with
shared receive contexts.  Users post receive buffers directly to a
shared receive context, with the buffers usable by any endpoint bound
to the shared receive context.  Shared receive contexts are not
associated with completion queues or counters.  Completed receive
operations are posted to the CQs bound to the endpoint.  An endpoint
may only be associated with a single receive context, and all
connectless endpoints associated with a shared receive context must
also share the same address vector.

Endpoints associated with a shared transmit context may use dedicated
receive contexts, and vice-versa.  Or an endpoint may use shared
transmit and receive contexts.  And there is no requirement that the
same group of endpoints sharing a context of one type also share the
context of an alternate type.  Furthermore, an endpoint may use a
shared context of one type, but a scalable set of contexts of the
alternate type.

## kfi_stx_context

This call is used to open a shareable transmit context.  See
kfi_tx_context call under the SCALABLE ENDPOINTS section for details on
the transit context attributes.  The exception is that endpoints
attached to a shared transmit context must use a subset of the
transmit context attributes.  This is opposite of the requirement for
scalable endpoints.

## kfi_srx_context

This allocates a shareable receive context.  See kfi_rx_context call
under SCALABLE ENDPOINTS section for details on the receive context
attributes.  The exception is that endpoints attached to a shared
receive context must use a subset of the receive context attributes.
This is opposite of the requirement for scalable endpoints.

# OPERATION FLAGS

Operation flags are obtained by OR-ing the following flags together.
Operation flags define the default flags applied to an endpoint's data
transfer operations, where a flags parameter is not available.  Data
transfer operations that take flags as input override the op_flags
value of an endpoint.

*KFI_INJECT*
: Indicates that all outbound data buffer should be returned to the
  user's control immediately after a data transfer call returns, even
  if the operation is handled asynchronously.  This may require that
  the provider copy the data into a local buffer and transfer out of
  that buffer.  A provider may limit the total amount of send data
  that may be buffered and/or the size of a single send.  Applications
  may discover and modify these limits using the endpoint's getopt and
  setopt interfaces.

*KFI_MULTI_RECV*
: Applies to posted receive operations.  This flag allows the user to
  post a single buffer that will receive multiple incoming messages.
  Received messages will be packed into the receive buffer until the
  buffer has been consumed.  Use of this flag may cause a single
  posted receive operation to generate multiple completions as
  messages are placed into the buffer.  The placement of received data
  into the buffer may be subjected to provider specific alignment
  restrictions.  The buffer will be returned to the application's
  control, and an *KFI_MULTI_RECV* completion will be generated, when a
  message is received that cannot fit into the remaining free buffer
  space.

*KFI_COMPLETION*
: Indicates that a completion entry should be generated for data
  transfer operations.

# NOTES

Users should call kfi_close to release all resources allocated to the
fabric endpoint.

Endpoints allocated with the KFI_CONTEXT mode set must typically
provide struct kfi_context as their per operation context parameter.
(See kfi_getinfo.3 for details.)  However, when KFI_COMPLETION is
enabled to suppress completion entries, and an operation is initiated
without KFI_COMPLETION flag set, then the context parameter is ignored.
An application does not need to pass in a valid struct kfi_context into
such data transfers.

Operations that complete in error that are not associated with valid
operational context will use the endpoint context in any error
reporting structures.

Users can attach both counters and completion queues to an endpoint.
When both counter and completion queue are attached, a successful
completion increments the counter and does not generate a completion
entry in the completion queue. Operations that complete with an error
increment the error counter and generate a completion event.

# RETURN VALUES

Returns 0 on success.  On error, a negative value corresponding to
kfabric errno is returned.

Kfabric errno values are defined in `kfi_errno.h`.

# ERRORS

*-KFI_EDOMAIN*
: A resource domain was not bound to the endpoint or an attempt was
  made to bind multiple domains.

*-KFI_ENOCQ*
: The endpoint has not been configured with necessary event queue.

*-KFI_EOPBADSTATE*
: The endpoint's state does not permit the requested operation.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_msg`(3)](kfi_msg.3.html),
[`kfi_tagged`(3)](kfi_tagged.3.html),
[`kfi_rma`(3)](kfi_rma.3.html)
