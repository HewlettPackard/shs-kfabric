---
layout: page
title: kfi_eq(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_eq \- Event queue operations

kfi_eq_open / kfi_close
: Open/close an event queue

kfi_control
: Control operation of EQ

kfi_eq_read / kfi_eq_readerr
: Read an event from an event queue

kfi_eq_write
: Writes an event to an event queue

kfi_eq_sread
: A synchronous (blocking) read of an event queue

kfi_eq_strerror
: Converts provider specific error information into a printable string

# SYNOPSIS

{% highlight c %}
#include <kfi_domain.h>

int
kfi_eq_open(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
	    struct kfid_eq **eq, kfi_event_handler event_handler, void *context)

int
kfi_close(struct kfid *fid)

int
kfi_control(struct kfid *fid, int command, void *arg)

ssize_t
kfi_cq_read(struct kfid_cq *cq, void *buf, size_t count)

ssize_t
kfi_cq_readerr(struct kfid_cq *cq, struct kfi_cq_err_entry *buf, uint64_t flags)

ssize_t
kfi_eq_write(struct kfid_eq *eq, uint32_t event, const void *buf,
	     size_t len, uint64_t flags)

ssize_t
kfi_eq_sread(struct kfid_eq *eq, uint32_t *event, void *buf, size_t len,
	     int timeout, uint64_t flags)

const char *
kfi_eq_strerror(struct kfid_eq *eq, int prov_errno, const void *err_data,
		char *buf, size_t len)
{% endhighlight %}

# ARGUMENTS

*fabric*
: Opened kfabric descriptor

*domain*
: Open resource domain

*eq*
: Event queue

*attr*
: Event queue attributes

*context*
: User specified context associated with the event queue.

*event*
: Reported event

*buf*
: For read calls, the data buffer to write events into.  For write
  calls, an event to insert into the event queue.  For kfi_eq_strerror,
  an optional buffer that receives printable error information.

*len*
: Length of data buffer

*flags*
: Additional flags to apply to the operation

*command*
: Command of control operation to perform on EQ.

*arg*
: Optional control argument

*prov_errno*
: Provider specific error value

*err_data*
: Provider specific error data related to a completion

*timeout*
: Timeout specified in milliseconds

# DESCRIPTION

Event queues are used to report events associated with control
operations.  They are associated with memory registration, address
vectors, connection management, and fabric and domain level events.
Reported events are either associated with a requested operation or
affiliated with a call that registers for specific types of events,
such as listening for connection requests.

## kfi_eq_open

kfi_eq_open allocates a new event queue.

The properties and behavior of an event queue are defined by `struct
kfi_eq_attr`.

{% highlight c %}
struct kfi_eq_attr {
	size_t			size;
	uint64_t		flags;
	enum kfi_wait_obj	wait_obj;
	int			signaling_vector;
	struct kfid_wait	*wait_set;
};
{% endhighlight %}

*size*
: Specifies the minimum size of an event queue.

*flags*
: Flags that control the configuration of the EQ.

*wait_obj*
: EQ's may be associated with a specific wait object.  Wait objects
  allow applications to block until the wait object is signaled,
  indicating that an event is available to be read.  Users may use
  kfi_control to retrieve the underlying wait object associated with an
  EQ, in order to use it in other system calls.  The following values
  may be used to specify the type of wait object associated with an
  EQ:

- *KFI_WAIT_NONE*
: Used to indicate that the user will not block (wait) for events on
  the EQ.  When KFI_WAIT_NONE is specified, the application may not
  call kfi_eq_sread.

- *KFI_WAIT_UNSPEC*
: Specifies that the user will only wait on the EQ using fabric
  interface calls, such as kfi_eq_sread.  In this case, the underlying
  provider may select the most appropriate or highest performing wait
  object available, including custom wait mechanisms.  Applications
  that select KFI_WAIT_UNSPEC are not guaranteed to retrieve the
  underlying wait object.

- *KFI_WAIT_SET*
: Indicates that the event queue should use a wait set object to wait
  for events.  If specified, the wait_set field must reference an
  existing wait set object.

- *KFI_WAIT_QUEUE*
: Specifies that a linux kernel wait queue is used as a method
  allowing the thread to sleep until completion.

*signaling_vector*
: Indicates which processor core interrupts associated with the EQ
  should target.

*wait_set*
: If wait_obj is KFI_WAIT_SET, this field references a wait object to
  which the event queue should attach.  When an event is inserted into
  the event queue, the corresponding wait set will be signaled if all
  necessary conditions are met.  The use of a wait_set enables an
  optimized method of waiting for events across multiple event queues.
  This field is ignored if wait_obj is not KFI_WAIT_SET.

## kfi_close

The kfi_close call releases all resources associated with an event queue.  Any
events which remain on the EQ when it is closed are lost.

The EQ must not be bound to any other objects prior to being closed, otherwise
the call will return -KFI_EBUSY.

## kfi_control

The kfi_control call is used to access provider or implementation
specific details of the event queue.  Access to the EQ should be
serialized across all calls when kfi_control is invoked, as it may
redirect the implementation of EQ operations.  The following control
commands are usable with an EQ.

*KFI_GETWAIT (void \*\*)*
: This command allows the user to retrieve the low-level wait object
  associated with the EQ.  The format of the wait-object is specified
  during EQ creation, through the EQ attributes.  The kfi_control arg
  parameter should be an address where a pointer to the returned wait
  object will be written.  This should be an 'int *' for KFI_WAIT_FD.

## kfi_eq_read

The kfi_eq_read operations performs a non-blocking read of event data
from the EQ.  The format of the event data is based on the type of
event retrieved from the EQ, with all events starting with a struct
kfi_eq_entry header.  At most one event will be returned per EQ read
operation.  The number of bytes successfully read from the EQ is
returned from the read.  The KFI_PEEK flag may be used to indicate that
event data should be read from the EQ without being consumed.  A
subsequent read without the KFI_PEEK flag would then remove the event
from the EQ.

The following types of events may be reported to an EQ, along with
information regarding the format associated with each event.

*Asynchronous Control Operations*
: Asynchronous control operations are basic requests that simply need
  to generate an event to indicate that they have completed.  These
  include the following types of events: memory registration and address
  vector resolution.

  Control requests report their completion by inserting a `struct
  kfi_eq_entry` into the EQ.  The format of this structure is:

{% highlight c %}
struct kfi_eq_entry {
	struct kfid		*fid;
	void			*context;
	uint64_t		data;
};
{% endhighlight %}

  For the completion of basic asynchronous control operations, the
  returned event will indicate the operation that has completed, and
  the fid will reference the fabric descriptor associated with
  the event.  For memory registration, this will be an KFI_MR_COMPLETE
  event and the kfid_mr; address resolution will reference an
  KFI_AV_COMPLETE event and fid_av.  The context field will be set
  to the context specified as part of the operation, if available,
  otherwise the context will be associated with the fabric descriptor.

*Connection Notification*
: Connection notifications are connection management notifications
  used to setup or teardown connections between endpoints.  There are
  three connection notification events: KFI_CONNREQ, KFI_CONNECTED, and
  KFI_SHUTDOWN.  Connection notifications are reported using `struct
  kfi_eq_cm_entry`:

{% highlight c %}
struct kfi_eq_cm_entry {
	struct kfid		*fid;
	/* user must call kfi_freeinfo to release info */
	struct kfi_info		*info;
	/* connection data placed here, up to space provided */
	uint8_t			data[];
};
{% endhighlight %}

  A connection request (KFI_CONNREQ) event indicates that
  a remote endpoint wishes to establish a new connection to a listening,
  or passive, endpoint.  The fid is the passive endpoint.
  Information regarding the requested, active endpoint's
  capabilities and attributes are available from the info field.  The
  application is responsible for freeing this structure by calling
  kfi_freeinfo when it is no longer needed.  The kfi_info connreq field
  will reference the connection request associated with this event.
  To accept a connection, an endpoint must first be created by passing
  an kfi_info structure referencing this connreq field to kfi_endpoint().
  This endpoint is then passed to kfi_accept() to complete the acceptance
  of the connection attempt.
  Creating the endpoint is most easily accomplished by
  passing the kfi_info returned as part of the CM event into
  kfi_endpoint().  If the connection is to be rejected, the connreq is
  passed to kfi_reject().

  Any application data exchanged as part of the connection request is
  placed beyond the kfi_eq_cm_entry structure.  The amount of data
  available is application dependent and limited to the buffer space
  provided by the application when kfi_eq_read is called.  The amount
  of returned data may be calculated using the return value to
  kfi_eq_read.  Note that the amount of returned data is limited by the
  underlying connection protocol, and the length of any data returned
  may include protocol padding.  As a result, the returned length may
  be larger than that specified by the connecting peer.

  If a connection request has been accepted, an KFI_CONNECTED event will
  be generated on both sides of the connection.  The active side -- one
  that called kfi_connect() -- may receive user data as part of the
  KFI_CONNECTED event.  The user data is passed to the connection
  manager on the passive side through the kfi_accept call.  User data is
  not provided with an KFI_CONNECTED event on the listening side of the
  connection.

  Notification that a remote peer has disconnected from an active
  endpoint is done through the KFI_SHUTDOWN event.  Shutdown
  notification uses struct kfi_eq_cm_entry as declared above.  The fid
  field for a shutdown notification refers to the active endpoint's
  fid_ep.

## kfi_eq_sread

The kfi_eq_sread call is the blocking (or synchronous) equivalent to
kfi_eq_read.  It behaves is similar to the non-blocking call, with the
exception that the calls will not return until either an event has
been read from the EQ or an error or timeout occurs.  Specifying a
negative timeout means an infinite timeout.

## kfi_eq_readerr

The read error function, kfi_eq_readerr, retrieves information
regarding any asynchronous operation which has completed with an
unexpected error.  kfi_eq_readerr is a non-blocking call, returning
immediately whether an error completion was found or not.

EQs are optimized to report operations which have completed
successfully.  Operations which fail are reported 'out of band'.  Such
operations are retrieved using the kfi_eq_readerr function.  When an
operation that completes with an unexpected error is inserted into an
EQ, it is placed into a temporary error queue.  Attempting to read
from an EQ while an item is in the error queue results in an KFI_EAVAIL
failure.  Applications may use this return code to determine when to
call kfi_eq_readerr.

Error information is reported to the user through struct
kfi_eq_err_entry.  The format of this structure is defined below.

{% highlight c %}
struct kfi_eq_err_entry {
	struct kfid		*fid;
	void			*context;
	uint64_t		data;
	int			err;
	int			prov_errno;
	/* err_data is available until the next time the CQ is read */
	void			*err_data;
	size_t			err_data_size;
};
{% endhighlight %}

The fid will reference the fabric descriptor associated with the
event.  For memory registration, this will be the fid_mr, address
resolution will reference a fid_av, and CM events will refer to a
fid_ep.  The context field will be set to the context specified as
part of the operation.

The general reason for the error is provided through the err field.
Provider or operational specific error information may also be available
through the prov_errno and err_data fields.  Users may call kfi_eq_strerror to
convert provider specific error information into a printable string
for debugging purposes.

# RETURN VALUES

kfi_eq_open
: Returns 0 on success.  On error, a negative value corresponding to
  kfabric errno is returned.

kfi_eq_read / kfi_eq_readerr
kfi_eq_sread
kfi_eq_write
: On success, returns the number of bytes read from or written to the
  event queue.  On error, a negative value corresponding to kfabric
  errno is returned.  On timeout, kfi_eq_sread returns -KFI_ETIMEDOUT.

kfi_eq_strerror
: Returns a character string interpretation of the provider specific
  error returned with a completion.

Kfabric errno values are defined in
`kfi_errno.h`.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_cntr`(3)](kfi_cntr.3.html),
[`kfi_poll`(3)](kfi_poll.3.html)
