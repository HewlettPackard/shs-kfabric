---
layout: page
title: kfabric(7)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

Kfabric Interface Library

# SYNOPSIS

{% highlight c %}
#include <kfabric.h>
{% endhighlight %}

Kfabric is a high-performance fabric software library designed to
provide low-latency interfaces to fabric hardware.

# OVERVIEW

Kfabric provides 'process direct I/O' to application software communicating
across fabric software and hardware.  Process direct I/O, historically
referred to as RDMA, allows an application to directly access network
resources without operating system interventions.  Data transfers can
occur directly to and from application memory.

There are two components to the kfabric software:

*Kfabric Providers*
: Conceptually, a kfabric provider may be viewed as a local hardware
  NIC driver, though a provider is not limited by this definition.
  The first component of kfabric is a general purpose framework that
  is capable of handling different types of kfabric hardware.  All
  kfabric hardware devices and their software drivers are required to
  support this framework.  Devices and the drivers that plug into the
  kfabric framework are referred to as fabric providers, or simply
  providers.  Provider details may be found in kkfi_prov.

*Fabric Interfaces*
: The second component is a set of communication operations.
  Kfabric defines several sets of communication functions that
  providers can support.  It is not required that providers implement
  all the interfaces that are defined; however, providers clearly
  indicate which interfaces they do support.

  The fabric interfaces are designed such that they are cohesive and
  not simply a union of disjoint interfaces.  The interfaces are
  logically divided into two groups: control interfaces and
  communication operations. The control interfaces are a common set of
  operations that provide access to local communication resources,
  such as address vectors and event queues.  The communication
  operations expose particular models of communication and fabric
  functionality, such as message queues, remote memory access, and
  atomic operations.  Communication operations are associated with
  fabric endpoints.

  Applications will typically use the control interfaces to discover
  local capabilities and allocate necessary resources.  They will then
  allocate and configure a communication endpoint to send and receive
  data, or perform other types of data transfers, with remote
  endpoints.

# CONTROL INTERFACES

The control interfaces APIs provide applications access to network
resources.  This involves listing all the interfaces available,
obtaining the capabilities of the interfaces and opening a provider.

*kfi_getinfo - Fabric Information*
: The kfi_getinfo call is the base call used to discover and request
  fabric services offered by the system.  Applications can use this
  call to indicate the type of communication that they desire.  The
  results from kfi_getinfo, kfi_info, are used to reserve and configure
  fabric resources.

  kfi_getinfo returns a list of kfi_info structures.  Each structure
  references a single fabric provider, indicating the interfaces that
  the provider supports, along with a named set of resources.  A
  fabric provider may include multiple kfi_info structures in the
  returned list.

*kfi_fabric - Fabric Domain*
: A fabric domain represents a collection of hardware and software
  resources that access a single physical or virtual network.  All
  network ports on a system that can communicate with each other
  through the fabric belong to the same fabric domain.  A fabric
  domain shares network addresses and can span multiple providers.
  kfabric supports systems connected to multiple fabrics.

*kfi_domain - Access Domains*
: An access domain represents a single logical connection into a
  fabric.  It may map to a single physical or virtual NIC or a port.
  An access domain defines the boundary across which fabric resources
  may be associated.  Each access domain belongs to a single fabric
  domain.

*kfi_endpoint - Fabric Endpoint*
: A fabric endpoint is a communication portal.  An endpoint may be
  either active or passive.  Passive endpoints are used to listen for
  connection requests.  Active endpoints can perform data transfers.
  Endpoints are configured with specific communication capabilities
  and data transfer interfaces.

*kfi_eq - Event Queue*
: Event queues, are used to collect and report the completion of
  asynchronous operations and events.  Event queues report events
  that are not directly associated with data transfer operations.

*kfi_cq - Completion Queue*
: Completion queues are high-performance event queues used to report
  the completion of data transfer operations.

*kfi_cntr - Event Counters*
: Event counters are used to report the number of completed
  asynchronous operations.  Event counters are considered
  light-weight, in that a completion simply increments a counter,
  rather than placing an entry into an event queue.

*kfi_mr - Memory Region*
: Memory regions describe application local memory buffers.  In order
  for fabric resources to access application memory, the application
  must first grant permission to the fabric provider by constructing a
  memory region.  Memory regions are required for specific types of
  data transfer operations, such as RMA transfers (see below).

*kfi_av - Address Vector*
: Address vectors are used to map higher level addresses, such as IP
  addresses, which may be more natural for an application to use, into
  fabric specific addresses.  The use of address vectors allows
  providers to reduce the amount of memory required to maintain large
  address look-up tables, and eliminate expensive address resolution
  and look-up methods during data transfer operations.

# DATA TRANSFER INTERFACES

Fabric endpoints are associated with multiple data transfer
interfaces.  Each interface set is designed to support a specific
style of communication, with an endpoint allowing the different
interfaces to be used in conjunction.  The following data transfer
interfaces are defined by kfabric.

*kfi_msg - Message Queue*
: Message queues expose a simple, message-based FIFO queue interface
  to the application.  Message data transfers allow applications to
  send and receive data with message boundaries being maintained.

*kfi_tagged - Tagged Message Queues*
: Tagged message lists expose send/receive data transfer operations
  built on the concept of tagged messaging.  The tagged message queue
  is conceptually similar to standard message queues, but with the
  addition of 64-bit tags for each message.  Sent messages are matched
  with receive buffers that are tagged with a similar value.

*kfi_rma - Remote Memory Access*
: RMA transfers are one-sided operations that read or write data
  directly to a remote memory region.  Other than defining the
  appropriate memory region, RMA operations do not require interaction
  at the target side for the data transfer to complete.

*kfi_atomic - Atomic*
: Atomic operations can perform one of several operations on a remote
  memory region.  Atomic operations include well-known functionality,
  such as atomic-add and compare-and-swap, plus several other
  pre-defined calls.  Unlike other data transfer interfaces, atomic
  operations are aware of the data formatting at the target memory
  region.

# PROVIDER REQUIREMENTS

Kfabric provides a general framework for supporting multiple types
of fabric objects and their related interfaces.  Fabric providers have
a large amount of flexibility in selecting which components they are
able and willing to support, based on specific hardware constraints.
To assist in the development of applications, kfabric specifies the
following requirements that must be met by any fabric provider, if
requested by an application.  (Note that the instantiation of a
specific fabric object is subject to application configuration
parameters and need not meet these requirements).

* A fabric provider must support at least one endpoint type.
* All endpoints must support the message queue data transfer
  interface.
* An endpoint that advertises support for a specific endpoint
  capability must support the corresponding data transfer interface.
* Endpoints must support operations to send and receive data for any
  data transfer operations that they support.
* Connectionless endpoints must support all relevant data
  transfer routines. (send / recv / write / read / etc.)
* Connectionless endpoints must support the CM interface getname.
* Connectionless endpoints that support multicast operations must
  support the CM interfaces join and leave.
* Connection-oriented interfaces must support the CM interfaces
  getname, getpeer, connect, listen, accept, reject, and shutdown.
* All endpoints must support all relevant 'msg' data transfer
  routines.  (sendmsg / recvmsg / writemsg / readmsg / etc.)
* Access domains must support opening address vector maps and tables.
* Address vectors associated with domains that may be identified using
  IP addresses must support KFI_SOCKADDR_IN and KFI_SOCKADDR_IN6 input
  formats.
* Address vectors must support KFI_ADDR, KFI_ADDR_INDEX, and KFI_AV
  output formats.
* Access domains must support opening completion queues and counters.
* Completion queues must support the KFI_CQ_FORMAT_CONTEXT and
  KFI_CQ_FORMAT_MSG formats.
* Event queues associated with tagged message transfers must support
  the KFI_CQ_FORMAT_TAGGED format.
* A provider is expected to be forward compatible, and must be able to
  be compiled against expanded `kfi_xxx_ops` structures that define new
  functions added after the provider was written.  Any unknown
  functions must be set to NULL.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_av`(3)](kfi_av.3.html),
[`kfi_eq`(3)](kfi_eq.3.html),
[`kfi_cq`(3)](kfi_cq.3.html),
[`kfi_cntr`(3)](kfi_cntr.3.html),
[`kfi_mr`(3)](kfi_mr.3.html)
