---
layout: page
title: kfi_cm(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_cm - Connection management operations

kfi_connect / kfi_listen / kfi_accept / kfi_reject / kfi_shutdown
: Manage endpoint connection state.

kfi_getname / kfi_getpeer
: Return local or peer endpoint address

# SYNOPSIS

{% highlight c %}
#include <kfi_cm.h>

int
kfi_connect(struct kfid_ep *ep, const void *addr,
	   const void *param, size_t paramlen)

int
kfi_listen(struct kfid_pep *pep)

int
kfi_accept(struct kfid_ep *ep, const void *param, size_t paramlen)

int
kfi_reject(struct kfid_pep *pep, kfid_t connreq,
	  const void *param, size_t paramlen)

int
kfi_shutdown(struct kfid_ep *ep, uint64_t flags)

int
kfi_getname(struct kfid *fid, void *addr, size_t *addrlen)

int
kfi_getpeer(struct kfid_ep *ep, void *addr, size_t *addrlen)
{% endhighlight %}

# ARGUMENTS

*ep / pep*
: Kfabric endpoint on which to change connection state.

*addr*
: Buffer to store queried address (get), or address to
  connect.  The address must be in the same format as that
  specified using kfi_info: addr_format when the endpoint was created.

*addrlen*
: On input, specifies size of addr buffer.  On output, stores number
  of bytes written to addr buffer.

*param*
: User-specified data exchanged as part of the connection exchange.

*paramlen*
: Size of param buffer.

*info*
: Kfabric information associated with a connection request.

*flags*
: Additional flags for controlling connection operation.

*context*
: User context associated with the request.

# DESCRIPTION

Connection management functions are used to connect an
connection-oriented endpoint to a peer endpoint.

## kfi_listen

The kfi_listen call indicates that the specified endpoint should be
transitioned into a passive connection state, allowing it to accept
incoming connection requests.  Connection requests against a listening
endpoint are reported asynchronously to the user through a bound CM
event queue using the KFI_CONNREQ event type.  The number of outstanding
connection requests that can be queued at an endpoint is limited by the
listening endpoint's backlog parameter.  The backlog is initialized
based on administrative configuration values, but may be adjusted
through the kfi_control call.

## kfi_connect

The kfi_connect call initiates a connection request on a
connection-oriented endpoint to the destination address.

## kfi_accept / kfi_reject

The kfi_accept and kfi_reject calls are used on the passive (listening)
side of a connection to accept or reject a connection request,
respectively.  To accept a connection, the listening application first
waits for a connection request event (KFI_CONNREQ).
After receiving such an event, the application
allocates a new endpoint to accept the connection.  This endpoint must
be allocated using an kfi_info structure referencing the connreq from this
KFI_CONNREQ event.  kfi_accept is then invoked
with the newly allocated endpoint.  If
the listening application wishes to reject a connection request, it calls
kfi_reject with the listening endpoint and
a reference to the connection request.

A successfully accepted connection request will result in the active
(connecting) endpoint seeing an KFI_CONNECTED event on its associated
event queue.  A rejected or failed connection request will generate an
error event.  The error entry will provide additional details describing
the reason for the failed attempt.

An KFI_CONNECTED event will also be generated on the passive side for the
accepting endpoint once the connection has been properly established.
The kfid of the KFI_CONNECTED event will be that of the endpoint passed to
kfi_accept as opposed to the listening passive endpoint.
Outbound data transfers cannot be initiated on a connection-oriented
endpoint until an KFI_CONNECTED event has been generated.  However, receive
buffers may be associated with an endpoint anytime.

## kfi_shutdown

The kfi_shutdown call is used to gracefully disconnect an endpoint from
its peer.  If shutdown flags are 0, the endpoint is fully disconnected,
and no additional data transfers will be possible.  Flags may also be
used to indicate that only outbound (KFI_WRITE) or inbound (KFI_READ) data
transfers should be disconnected.  Regardless of the shutdown option
selected, any queued completions associated with asynchronous operations
may still be retrieved from the corresponding event queues.

An KFI_SHUTDOWN event will be generated for an endpoint when the remote
peer issues a disconnect using kfi_shutdown or abruptly closes the endpoint.
Note that in the abrupt close case, an KFI_SHUTDOWN event will only be
generated if the peer system is reachable and a service or kernel agent
on the peer system is able to notify the local endpoint that the connection
has been aborted.

## kfi_getname / kfi_getpeer

The kfi_getname and kfi_getpeer calls may be used to retrieve the local or
peer endpoint address, respectively.  On input, the addrlen parameter should
indicate the size of the addr buffer.  If the actual address is larger than
what can fit into the buffer, it will be truncated.  On output, addrlen
is set to the size of the buffer needed to store the address, which may
be larger than the input value.

# FLAGS

Flag values are reserved and must be 0.

# RETURN VALUE

Returns 0 on success. On error, a negative value corresponding to kfabric
errno is returned. Kfabric errno values are defined in
`kfi_errno.h`.

# ERRORS


# NOTES

For connection-oriented endpoints, the param buffer will be sent as
part of the connection request or response, subject to the constraints of
the underlying connection protocol.  Applications may use kfi_control
to determine the size of application data that may be exchanged as
part of a connection request or response.  The kfi_connect, kfi_accept, and
kfi_reject calls will silently truncate any application data which cannot
fit into underlying protocol messages.  User data exchanged as part of
the connection process is available as part of the kfi_eq_cm_entry
structure, for KFI_CONNREQ and KFI_CONNECTED events, or as additional
err_data to kfi_eq_err_entry, in the case of a rejected connection.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_eq`(3)](kfi_eq.3.html)
