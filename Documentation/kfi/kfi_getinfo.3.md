---
layout: page
title: kfi_getinfo(3)
tagline: fabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_getinfo / kfi_freeinfo \- Obtain / free kfabric interface information

# SYNOPSIS

{% highlight c %}
#include <kfabric.h>

int
kfi_getinfo(uint32_t version, const char *node, const char *service,
		uint64_t flags, struct kfi_info *hints, struct kfi_info **info);

void
kfi_freeinfo(struct kfi_info *info);

struct kfi_info *
kfi_dupinfo(const struct kfi_info *info);
{% endhighlight %}

# ARGUMENTS

*version*
: Interface version requested by application.

*node*
: Optional, name or kfabric address to resolve.

*service*
: Optional, service name or port number of address.

*flags*
: Operation flags for the kfi_getinfo call.

*hints*
: Reference to an kfi_info structure that specifies criteria for
  selecting the returned fabric information.

*info*
: A pointer to a linked list of kfi_info structures containing response
  information.

# DESCRIPTION

Returns information about available kfabric services for reaching the
specified node or service, subject to any provided hints.  Callers
must provide at least one of the node, service, or hints parameters.
If node and service are NULL, then the hints src_addr and/or dest_addr
fields of the kfi_info structure must be specified.
If no matching kfabric information is available, info will be set to
NULL.

Based on the input hints, node, and service parameters, a list of
kfabric domains and endpoints will be returned.  Each kfi_info structure
will describe an endpoint that meets the application's specified
communication criteria.  Each endpoint will be associated with a
domain.  Applications can restrict the number of returned endpoints by
including additional criteria in their search hints.  Relaxing or
eliminating input hints will increase the number and type of endpoints
that are available.  Providers that return multiple endpoints to a
single kfi_getinfo call should return the endpoints that are highest
performing.  Providers may indicate that an endpoint and domain can
support additional capabilities than those requested by the user only
if such support will not adversely affect performance.

The version parameter is used by the application to request the
desired version of the interfaces.  The version determines the format
of all data structures used by any of the kfabric interfaces.
Applications should use the KKFI_VERSION(major, minor) macro to indicate
the version, with hard-coded integer values for the major and minor
values.  The KFI_MAJOR_VERSION and KFI_MINOR_VERSION enum values defined
in kfabric.h specify the latest version of the installed library.
However, it is recommended that the integer values for
KFI_MAJOR_VERSION and KFI_MINOR_VERSION be used, rather than referencing
the enum types in order to ensure compatibility with future versions
of the library.  This protects against the application being built
from source against a newer version of the library that introduces new
fields to data structures, which would not be initialized by the
application.

Either node, service, or hints must be provided, with any combination
being supported.  If node is provided, kfi_getinfo will attempt to
resolve the fabric address to the given node.  The hints parameter, if
provided, may be used to control the resulting output as indicated
below.  If node is not given, kfi_getinfo will attempt to resolve the
kfabric addressing information based on the provided hints.

The caller must call kfi_freeinfo to release kfi_info structures returned
by this call.

# KFI_INFO

{% highlight c %}
struct kfi_info {
	struct kfi_info		*next;
	uint64_t		caps;
	uint64_t		mode;
	uint32_t		addr_format;
	size_t			src_addrlen;
	size_t			dest_addrlen;
	void			*src_addr;
	void			*dest_addr;
	kfid_t			handle;
	struct kfi_tx_attr	*tx_attr;
	struct kfi_rx_attr	*rx_attr;
	struct kfi_ep_attr	*ep_attr;
	struct kfi_domain_attr	*domain_attr;
	struct kfi_fabric_attr	*fabric_attr;
};
{% endhighlight %}

*next*
: Pointer to the next kfi_info structure in the list.  Will be NULL
  if no more structures exist.

*caps - kfabric interface capabilities*
: If specified, indicates the desired capabilities of the kfabric
  interfaces.  Supported capabilities are listed in the _Capabilities_
  section below.

*mode*
: Operational modes supported by the application.  See the _Mode_
  section below.

*addr_format - address format*
: If specified, indicates the format of addresses referenced by the
  fabric interfaces and data structures.  Supported formats are listed
  in the _Addressing formats_ section below.

*src_addrlen - source address length*
: Indicates the length of the source address (must be specified if
  *src_addr* is specified).  This field will be ignored in hints if
  KFI_SOURCE is specified.

*dest_addrlen - destination address length*
: Indicates the length of the destination address (must be specified
  if *dest_addr* is specified).  This field will be ignored in hints
  unless the node and service parameters are NULL or KFI_SOURCE is
  specified.

*src_addr - source address*
: If specified, indicates the source address.  This field will be
  ignored in hints if KFI_SOURCE is specified.

*dest_addr - destination address*
: If specified, indicates the destination address.  This field will be
  ignored in hints unless the node and service parameters are NULL or
  KFI_SOURCE is specified.

*tx_attr - transmit context attributes*
: Optionally supplied transmit context attributes.  Transmit context
  attributes may be specified and returned as part of kfi_getinfo.
  When provided as hints, requested values of struct kfi_tx_ctx_attr
  should be set.  On output, the actual transmit context attributes
  that can be provided will be returned.  Output values will be
  greater than or equal to the requested input values.

*rx_attr - receive context attributes*
: Optionally supplied receive context attributes.  Receive context
  attributes may be specified and returned as part of kfi_getinfo.
  When provided as hints, requested values of struct kfi_rx_ctx_attr
  should be set.  On output, the actual receive context attributes
  that can be provided will be returned.  Output values will be
  greater than or or equal to the requested input values.

*ep_attr - endpoint attributes*
: Optionally supplied endpoint attributes.  Endpoint attributes may be
  specified and returned as part of kfi_getinfo.  When provided as
  hints, requested values of struct kfi_ep_attr should be set.  On
  output, the actual endpoint attributes that can be provided will be
  returned.  Output values will be greater than or equal to requested
  input values.  See kfi_endpoint(3) for details.

*domain_attr - domain attributes*
: Optionally supplied domain attributes.  Domain attributes may be
  specified and returned as part of kfi_getinfo.  When provided as
  hints, requested values of struct kfi_domain_attr should be set.  On
  output, the actual domain attributes that can be provided will be
  returned.  Output values will be greater than or equal to requested
  input values.  See kfi_domain(3) for details.

*fabric_attr - kfabric attributes*
: Optionally supplied kfabric attributes.  Kfabric attributes may be
  specified and returned as part of kfi_getinfo.  When provided as
  hints, requested values of struct kfi_fabric_attr should be set.  On
  output, the actual fabric attributes that can be provided will be
  returned.  See kfi_fabric(3) for details.

# CAPABILITIES

Interface capabilities are obtained by OR-ing the following flags
together.  If capabilities in the hint parameter are set to 0, the
underlying provider will return the set of capabilities which are
supported.  Otherwise, providers will only return data matching the
specified set of capabilities.  Providers may indicate support for
additional capabilities beyond those requested when the use of
expanded capabilities will not adversely affect performance or expose
the application to communication beyond that which was requested.
Applications may use this feature to request a minimal set of
requirements, then check the returned capabilities to enable
additional optimizations.

*KFI_MSG*
: Specifies that an endpoint should support sending and receiving
  messages or datagrams.  Message capabilities imply support for send
  and/or receive queues.  Endpoints supporting this capability support
  operations defined by struct kfi_ops_msg.

  The ep_cap may be used to specify or restrict the type of messaging
  operations that are supported.  In the absence of any relevant
  flags, KFI_MSG implies the ability to send and receive messages.
  Applications can use the KFI_SEND and KFI_RECV flags to optimize an
  endpoint as send-only or receive-only.

*KFI_RMA*
: Specifies that the endpoint should support RMA read and write
  operations.  Endpoints supporting this capability support operations
  defined by struct kfi_ops_rma.  In the absence of any relevant flags,
  KFI_RMA implies the ability to initiate and be the target of remote
  memory reads and writes.  Applications can use the KFI_READ,
  KFI_WRITE, KFI_REMOTE_READ, and KFI_REMOTE_WRITE flags to restrict the
  types of RMA operations supported by an endpoint.

*KFI_TAGGED*
: Specifies that the endpoint should handle tagged message transfers.
  Tagged message transfers associate a user-specified key or tag with
  each message that is used for matching purposes at the remote side.
  Endpoints supporting this capability support operations defined by
  struct kfi_ops_tagged.  In the absence of any relevant flags,
  KFI_TAGGED implies the ability to send and receive tagged messages.
  Applications can use the KFI_SEND and KFI_RECV flags to optimize an
  endpoint as send-only or receive-only.

*KFI_ATOMIC*
: Specifies that the endpoint supports some set of atomic operations.
  Endpoints supporting this capability support operations defined by
  struct kfi_ops_atomic.  In the absence of any relevant flags,
  KFI_ATOMIC implies the ability to initiate and be the target of
  remote atomic reads and writes.  Applications can use the KFI_READ,
  KFI_WRITE, KFI_REMOTE_READ, and KFI_REMOTE_WRITE flags to restrict the
  types of atomic operations supported by an endpoint.

*KFI_NAMED_RX_CTX*
: Requests that endpoints which support multiple receive contexts
  allow an initiator to target (or name) a specific receive context as
  part of a data transfer operation.

*KFI_DIRECTED_RECV*
: Requests that the communication endpoint use the source address of
  an incoming message when matching it with a receive buffer.  If this
  capability is not set, then the src_addr parameter for msg and tagged
  receive operations is ignored.

*KFI_INJECT*
: Indicates that the endpoint be able to support the KFI_INJECT flag on
  data transfer operations and the 'inject' data transfer calls.  The
  minimum supported size of an inject operation that an endpoint with
  this capability must support is 8-bytes.  Applications may access
  endpoint options (getopt/setopt) to determine injected transfer
  limits.

*KFI_MULTI_RECV*
: Specifies that the endpoint must support the KFI_MULTI_RECV flag when
  posting receive buffers.

*KFI_SOURCE*
: Requests that the endpoint return source addressing data as part of
  its completion data.  This capability only applies to connectionless
  endpoints.  Note that returning source address information may
  require that the provider perform address translation and/or look-up
  based on data available in the underlying protocol in order to
  provide the requested data, which may adversely affect performance.

*KFI_READ*
: Indicates that the user requires an endpoint capable of initiating
  reads against remote memory regions.  This flag requires that KFI_RMA
  and/or KFI_ATOMIC be set.

*KFI_WRITE*
: Indicates that the user requires an endpoint capable of initiating
  writes against remote memory regions.  This flag requires that KFI_RMA
  and/or KFI_ATOMIC be set.

*KFI_SEND*
: Indicates that the user requires an endpoint capable of sending
  message data transfers.  Message transfers include base message
  operations as well as tagged message functionality.

*KFI_RECV*
: Indicates that the user requires an endpoint capable of receiving
  message data transfers.  Message transfers include base message
  operations as well as tagged message functionality.

*KFI_REMOTE_READ*
: Indicates that the user requires an endpoint capable of receiving
  read memory operations from remote endpoints.  This flag requires
  that KFI_RMA and/or KFI_ATOMIC be set.

*KFI_REMOTE_WRITE*
: Indicates that the user requires an endpoint capable of receiving
  write memory operations from remote endpoints.  This flag requires
  that KFI_RMA and/or KFI_ATOMIC be set.

*KFI_REMOTE_CQ_DATA*
: Applications may include a small message with a data transfer that
  is placed directly into a remote event queue as part of a completion
  event.  This is referred to as remote CQ data (sometimes referred to
  as immediate data).  The KFI_REMOTE_CQ_DATA indicates that an
  endpoint must support the KFI_REMOTE_CQ_DATA flag on data transfer
  operations.  The minimum supported size of remote CQ data that an
  endpoint with this capability must support is 4-bytes.  Applications
  may check the domain attributes to determine remote CQ data limits.

*KFI_CANCEL*
: Indicates that the user desires the ability to cancel outstanding
  data transfer operations.  If KFI_CANCEL is not set, a provider may
  optimize code paths with the assumption that kfi_cancel will not be
  used by the application.

*KFI_TRIGGER*
: Indicates that the endpoint should support triggered operations.
  Endpoints support this capability must meet the usage model as
  described by kfi_trigger.3.

*KFI_FENCE*
: Indicates that the endpoint support the KFI_FENCE flag on data
  transfer operations.  Support requires tracking that all previous
  transmit requests to a specified remote endpoint complete prior
  to initiating the fenced operation.  Fenced operations are often
  used to enforce ordering between operations that are not otherwise
  guaranteed by the underlying provider or protocol.

# MODE

The operational mode bits are used to convey requirements that an
application must adhere to when using the fabric interfaces.  Modes
specify optimal ways of accessing the reported endpoint or domain.
Applications that are designed to support a specific mode of operation
may see improved performance when that mode is desired by the
provider.  It is recommended that providers support applications that
disable any provider preferred modes.

On input to kfi_getinfo, applications set the mode bits that they
support.  On output, providers will clear mode bits that are not
necessary to achieve high-performance.  Mode bits that remain set
indicate application requirements for using the fabric interfaces
created using the returned kfi_info.  The set of modes are listed
below.

*KFI_CONTEXT*
: Specifies that the provider requires that applications use struct
  kfi_context as their per operation context parameter.  This structure
  should be treated as opaque to the application.  For performance
  reasons, this structure must be allocated by the user, but may be
  used by the fabric provider to track the operation.  Typically,
  users embed struct kfi_context within their own context structure.
  The struct kfi_context must remain valid until the corresponding
  operation completes or is successfully canceled.  As such,
  kfi_context should NOT be allocated on the stack.  Doing so is likely
  to result in stack corruption that will be difficult to debug.
  Users should not update or interpret the fields in this structure,
  or reuse it until the original operation has completed.  The
  structure is specified in kfabric.h.

*KFI_LOCAL_MR*
: The provider is optimized around having applications register memory
  for locally accessed data buffers.  Data buffers used in send and
  receive operations and as the source buffer for RMA and atomic
  operations must be registered by the application for access domains
  opened with this capability.

*KFI_MSG_PREFIX*
: Message prefix mode indicates that an application will provide
  buffer space in front of all message send and receive buffers for
  use by the provider.  Typically, the provider uses this space to
  implement a protocol, with the protocol headers being written into
  the prefix area.  The contents of the prefix space should be treated
  as opaque.  The use of KFI_MSG_PREFIX may improve application
  performance over certain providers by reducing the number of IO
  vectors referenced by underlying hardware and eliminating provider
  buffer allocation.

  KFI_MSG_PREFIX only applies to send and receive operations, including
  tagged sends and receives.  RMA and atomics do not require the
  application to provide prefix buffers.  Prefix buffer space must be
  provided with all sends and receives, regardless of the size of the
  transfer or other transfer options.  The ownership of prefix buffers
  is treated the same as the corresponding message buffers, but the
  size of the prefix buffer is not counted toward any message limits,
  including inject.

  Applications that support prefix mode must supply buffer space
  before their own message data.  The size of space that must be
  provided is specified by the msg_prefix_size endpoint attribute.
  Providers are required to define a msg_prefix_size that is a
  multiple of 8 bytes.  Additionally, applications may receive
  provider generated packets that do not contain application data.
  Such received messages will indicate a transfer size of 0 bytes.

*KFI_ASYNC_IOV*
: Applications can reference multiple data buffers as part of a single
  transmit operation through the use of IO vectors (SGEs).  Typically,
  the contents of an IO vector are copied by the provider into an
  internal buffer area, or directly to the underlying hardware.
  However, when a large number of IOV entries are supported,
  IOV buffering may have a negative impact on performance and memory
  consumption.  The KFI_ASYNC_IOV mode indicates that the application
  must provide the buffering needed for the IO vectors.  When set,
  an application must not modify an IO vector until the associated
  operation has completed.

# ENDPOINT TYPES

*KFI_EP_UNSPEC*
: The type of endpoint is not specified.  This is usually provided as
  input, with other attributes of the endpoint or the provider
  selecting the type.

*KFI_EP_MSG*
: Provides a reliable, connection-oriented data transfer service with
  flow control that maintains message boundaries.

*KFI_EP_DGRAM*
: Supports a connectionless, unreliable datagram communication.
  Message boundaries are maintained, but the maximum message size may
  be limited to the fabric MTU.  Flow control is not guaranteed.

*KFI_EP_RDM*
: Reliable datagram message.  Provides a reliable, unconnected data
  transfer service with flow control that maintains message
  boundaries.

# ADDRESSING FORMATS

Multiple fabric interfaces take as input either a source or
destination address parameter.  This includes struct kfi_info (src_addr
and dest_addr), CM calls (getname, getpeer, connect, join, and leave),
and AV calls (insert, lookup, and straddr).  The kfi_info addr_format
field indicates the expected address format for these operations.

A provider may support one or more of the following addressing
formats.  In some cases, a selected addressing format may need to be
translated or mapped into an address which is native to the
fabric.  See `kfi_av`(3).

*KFI_FORMAT_UNSPEC*
: KFI_FORMAT_UNSPEC indicates that a provider specific address format
  should be selected.  Provider specific addresses may be protocol
  specific or a vendor proprietary format.  Applications that select
  KFI_FORMAT_UNSPEC should be prepared to treat returned addressing
  data as opaque.  KFI_FORMAT_UNSPEC targets apps which make use of an
  out of band address exchange.  Applications which use KFI_FORMAT_UNSPEC
  may use kfi_getname() to obtain a provider specific address assigned
  to an allocated endpoint.

*KFI_SOCKADDR*
: Address is of type sockaddr.  The specific socket address format
  will be determined at run time by interfaces examining the sa_family
  field.

*KFI_SOCKADDR_IN*
: Address is of type sockaddr_in (IPv4).

*KFI_SOCKADDR_IN6*
: Address is of type sockaddr_in6 (IPv6).

*KFI_SOCKADDR_IB*
: Address is of type sockaddr_ib (defined in Linux kernel source)

# FLAGS

The operation of the kfi_getinfo call may be controlled through the use of
input flags.  Valid flags include the following.

*KFI_NUMERICHOST*
: Indicates that the node parameter is a numeric string representation
  of a fabric address, such as a dotted decimal IP address.  Use of
  this flag will suppress any lengthy name resolution protocol.

*KFI_SOURCE*
: Indicates that the node and service parameters specify the local
  source address to associate with an endpoint.  If specified, either
  the node and/or service parameter must be non-NULL.  This flag is
  often used with passive endpoints.

# RETURN VALUE

kfi_getinfo() returns 0 on success. On error, kfi_getinfo() returns a
negative value corresponding to kfabric errno. Kfabric errno values are
defined in `kfi_errno.h`.

kfi_dupinfo() duplicates a single kfi_info structure and all the
substructures within it and returns a pointer to the new kfi_info
structure.  This new kfi_info structure must be freed via
kfi_freeinfo().  kfi_dupinfo() returns NULL on error.

# ERRORS

*KFI_EBADFLAGS*
: The specified endpoint or domain capability or operation flags are
  invalid.

*KFI_ENOMEM*
: Indicates that there was insufficient memory to complete the operation.

*KFI_ENODATA*
: Indicates that no providers could be found which support the requested
  fabric information.

*KFI_ENOSYS*
: No fabric providers were found.

# NOTES

If hints are provided, the operation will be controlled by the values
that are supplied in the various fields (see section on _kfi_info_).
Applications that require specific communication interfaces, domains,
capabilities or other requirements, can specify them using fields in
_hints_.  Libfabric returns a linked list in *info* that points to a
list of matching interfaces.  *info* is set to NULL if there are no
communication interfaces or none match the input hints.

If node is provided, kfi_getinfo will attempt to resolve the kfabric
address to the given node.  If node is not provided, kfi_getinfo will
attempt to resolve the fabric addressing information based on the
provided hints.  The caller must call kfi_freeinfo to release kfi_info
structures returned by kfi_getinfo.

If neither node, service or hints are provided, then kfi_getinfo simply
returns the list all available communication interfaces.

Multiple threads may call
`kfi_getinfo` "simultaneously, without any requirement for serialization."

# SEE ALSO

[`kfi_open`(3)](kfi_open.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html)
