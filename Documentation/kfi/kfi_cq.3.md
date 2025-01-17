---
layout: page
title: kfi_cq(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_cq \- Completion queue operations

kfi_cq_open / kfi_close
: Open/close a completion queue

kfi_control
: Control CQ operation or attributes.

kfi_cq_read / kfi_cq_readfrom / kfi_cq_readerr
: Read a completion from a completion queue

kfi_cq_sread / kfi_cq_sreadfrom
: A synchronous (blocking) read that waits until a specified condition
  has been met before reading a completion from a completion queue.

kfi_cq_strerror
: Converts provider specific error information into a printable string

# SYNOPSIS

{% highlight c %}
#include <kfi_domain.h>

int
kfi_cq_open(struct kfid_domain *domain, struct kfi_cq_attr *attr,
	   struct kfid_cq **cq, kfi_comp_handler comp_handler, void *context)

int
kfi_close(struct kfid *fid)

int
kfi_control(struct kfid *fid, int command, void *arg)

ssize_t
kfi_cq_read(struct kfid_cq *cq, void *buf, size_t count)

ssize_t
kfi_cq_readfrom(struct kfid_cq *cq, void *buf, size_t count,
		kfi_addr_t *src_addr)

ssize_t
kfi_cq_readerr(struct kfid_cq *cq, struct kfi_cq_err_entry *buf, uint64_t flags)

ssize_t
kfi_cq_sread(struct kfid_cq *cq, void *buf, size_t count, const void *cond,
	    int timeout)

ssize_t
kfi_cq_sreadfrom(struct kfid_cq *cq, void *buf, size_t count,
		 kfi_addr_t *src_addr, const void *cond, int timeout)

const char *
kfi_cq_strerror(struct kfid_cq *cq, int prov_errno, const void *err_data,
		char *buf, size_t len)
{% endhighlight %}

# ARGUMENTS

*domain*
: Open resource domain

*cq*
: Completion queue

*attr*
: Completion queue attributes

*context*
: User specified context associated with the completion queue.

*buf*
: For read calls, the data buffer to write completions into.  For
  write calls, a completion to insert into the completion queue.  For
  kfi_cq_strerror, an optional buffer that receives printable error
  information.

*count*
: Number of CQ entries.

*len*
: Length of data buffer

*src_addr*
: Source address of a completed receive operation

*flags*
: Additional flags to apply to the operation

*command*
: Command of control operation to perform on CQ.

*arg*
: Optional control argument

*cond*
: Condition that must be met before a completion is generated

*timeout*
: Time in milliseconds to wait.  A negative value indicates infinite
  timeout.

*prov_errno*
: Provider specific error value

*err_data*
: Provider specific error data related to a completion

# DESCRIPTION

Completion queues are used to report events associated with data
transfers.  They are associated with message sends and receives, RMA,
atomic, tagged messages, and triggered events.  Reported events are
usually associated with a fabric endpoint, but may also refer to
memory regions used as the target of an RMA or atomic operation.

## kfi_cq_open

kfi_cq_open allocates a new completion queue.  Unlike event queues,
completion queues are associated with a resource domain and may be
offloaded entirely in provider hardware.

The properties and behavior of a completion queue are defined by
`struct kfi_cq_attr`.

{% highlight c %}
struct kfi_cq_attr {
	size_t			size;
	uint64_t		flags;
	enum kfi_cq_format	format;
	enum kfi_wait_obj	wait_obj;
	int			signaling_vector;
	enum kfi_cq_wait_cond	wait_cond;
	struct kfid_wait	*wait_set;
};
{% endhighlight %}

*size*
: Specifies the minimum size of an event queue. A value of 0 indicates that
  the provider may choose a default value.

*flags*
: Flags that control the configuration of the CQ.

*format*
: Completion queues allow the application to select the amount of
  detail that it must store and report.  The format attribute allows
  the application to select one of several completion formats,
  indicating the structure of the data that the completion queue
  should return when read.  Supported formats and the structures that
  correspond to each are listed below.

- *KFI_CQ_FORMAT_UNSPEC*
: If an unspecified format is requested, then the CQ will use a
  provider selected default format.

- *KFI_CQ_FORMAT_CONTEXT*
: Provides only user specified context that was associated with the
  completion.

{% highlight c %}
struct kfi_cq_entry {
	void			*op_context;
};
{% endhighlight %}

- *KFI_CQ_FORMAT_MSG*
: Provides minimal data for processing completions, with expanded
  support for reporting information about received messages.

{% highlight c %}
struct kfi_cq_msg_entry {
	void			*op_context;
	uint64_t		flags;
	size_t			len;
};
{% endhighlight %}

- *KFI_CQ_FORMAT_DATA*
: Provides data associated with a completion.  Includes support for
  received message length, remote EQ data, and multi-receive buffers.

{% highlight c %}
struct kfi_cq_data_entry {
	void			*op_context;
	uint64_t		flags;
	size_t			len;
	void			*buf;
	/* data depends on operation and/or flags - e.g. remote EQ data */
	uint64_t		data;
};
{% endhighlight %}

- *KFI_CQ_FORMAT_TAGGED*
: Expands completion data to include support for the tagged message
  interfaces.

{% highlight c %}
struct kfi_cq_tagged_entry {
	void			*op_context;
	uint64_t		flags;
	size_t			len;
	void			*buf;
	uint64_t		data;
	uint64_t		tag;
};
{% endhighlight %}

*wait_obj*
: CQ's may be associated with a specific wait object.  Wait objects
  allow applications to block until the wait object is signaled,
  indicating that a completion is available to be read.  Users may use
  kfi_control to retrieve the underlying wait object associated with an
  CQ, in order to use it in other system calls.  The following values
  may be used to specify the type of wait object associated with an
  CQ: KFI_WAIT_NONE, KFI_WAIT_UNSPEC, KFI_WAIT_SET, and KFI_WAIT_QUEUE.

- *KFI_WAIT_NONE*
: Used to indicate that the user will not block (wait) for completions
  on the CQ.  When KFI_WAIT_NONE is specified, the application may not
  call kfi_cq_sread or kfi_cq_sreadfrom.

- *KFI_WAIT_UNSPEC*
: Specifies that the user will only wait on the CQ using fabric
  interface calls, such as kfi_cq_readcond or kfi_cq_sreadfrom.  In this
  case, the underlying provider may select the most appropriate or
  highest performing wait object available, including custom wait
  mechanisms.  Applications that select KFI_WAIT_UNSPEC are not
  guaranteed to retrieve the underlying wait object.

- *KFI_WAIT_SET*
: Indicates that the completion queue should use a wait set object to
  wait for completions.  If specified, the wait_set field must
  reference an existing wait set object.

- *KFI_WAIT_QUEUE*
: Specifies that a linux kernel wait queue is used as a method
  allowing the thread to sleep until completion.

*signaling_vector*
: Indicates which processor core interrupts associated with the EQ should
  target.

*wait_cond*
: By default, when a completion is inserted into an CQ that supports
  blocking reads (kfi_cq_sread/kfi_cq_sreadfrom), the corresponding wait
  object is signaled.  Users may specify a condition that must first
  be met before the wait is satisfied.  This field indicates how the
  provider should interpret the cond field, which describes the
  condition needed to signal the wait object.

  A wait condition should be treated as an optimization.  Providers
  are not required to meet the requirements of the condition before
  signaling the wait object.  Applications should not rely on the
  condition necessarily being true when a blocking read call returns.

  If wait_cond is set to KFI_CQ_COND_NONE, then no additional
  conditions are applied to the signaling of the CQ wait object, and
  the insertion of any new entry will trigger the wait condition.  If
  wait_cond is set to KFI_CQ_COND_THRESHOLD, then the cond field is
  interpreted as a size_t threshold value.  The threshold indicates
  the number of entries that are to be queued before at the CQ before
  the wait is satisfied.

  This field is ignored if wait_obj is set to KFI_WAIT_NONE.

*wait_set*
: If wait_obj is KFI_WAIT_SET, this field references a wait object to
  which the completion queue should attach.  When an event is inserted
  into the completion queue, the corresponding wait set will be
  signaled if all necessary conditions are met.  The use of a wait_set
  enables an optimized method of waiting for events across multiple
  event and completion queues.  This field is ignored if wait_obj is
  not KFI_WAIT_SET.

## kfi_close

The kfi_close call releases all resources associated with a completion
queue. Any completions which remain on the CQ when it is closed are
lost.

When closing the CQ, there must be no opened endpoints, transmit contexts, or
receive contexts associated with the CQ.  If resources are still associated
with the CQ when attempting to close, the call will return -KFI_EBUSY.

## kfi_control

The kfi_control call is used to access provider or implementation
specific details of the completion queue.  Access to the CQ should be
serialized across all calls when kfi_control is invoked, as it may
redirect the implementation of CQ operations.  The following control
commands are usable with an CQ.

*KFI_GETWAIT (void \*\*)*
: This command allows the user to retrieve the low-level wait object
  associated with the CQ.  The format of the wait-object is specified
  during CQ creation, through the CQ attributes.  The kfi_control arg
  parameter should be an address where a pointer to the returned wait
  object will be written.  See kfi_eq.3 for addition details using
  kfi_control with KFI_GETWAIT.

## kfi_cq_read / kfi_cq_readfrom

The kfi_cq_read and kfi_cq_readfrom operations perform a non-blocking
read of completion data from the CQ.  The format of the completion
event is determined using the kfi_cq_format option that was specified
when the CQ was opened.  Multiple completions may be retrieved from a
CQ in a single call.  The maximum number of entries to return is
limited to the specified count parameter, with the number of entries
successfully read from the CQ returned by the call.

The kfi_cq_readfrom call allows the CQ to return source address
information to the user for any received data.  Source address data is
only available for those endpoints configured with KFI_SOURCE
capability.  If kfi_cq_readfrom is called on an endpoint for which
source addressing data is not available, the source address will be
set to KFI_ADDR_NOTAVAIL.  The number of input src_addr entries must
the the same as the count parameter.

CQs are optimized to report operations which have completed
successfully.  Operations which fail are reported 'out of band'.  Such
operations are retrieved using the kfi_cq_readerr function.  When an
operation that completes with an unexpected error is inserted into an
CQ, it is placed into a temporary error queue.  Attempting to read
from an CQ while an item is in the error queue results in an KFI_EAVAIL
failure.  Applications may use this return code to determine when to
call kfi_cq_readerr.

## kfi_cq_sread / kfi_cq_sreadfrom

The kfi_cq_sread and kfi_cq_sreadfrom calls are the blocking equivalent
operations to kfi_cq_read and kfi_cq_readfrom.  Their behavior is
similar to the non-blocking calls, with the exception that the calls
will not return until either a completion has been read from the CQ or
an error or timeout occurs.

## kfi_cq_readerr

The read error function, kfi_cq_readerr, retrieves information
regarding any asynchronous operation which has completed with an
unexpected error.  kfi_cq_readerr is a non-blocking call, returning
immediately whether an error completion was found or not.

Error information is reported to the user through `struct
kfi_cq_err_entry`.  The format of this structure is defined below.

{% highlight c %}
struct kfi_cq_err_entry {
	void			*op_context;
	uint64_t		flags;
	size_t			len;
	void			*buf;
	uint64_t		data;
	uint64_t		tag;
	size_t			olen;
	int			err;
	int			prov_errno;
	/* err_data is available until the next time the CQ is read */
	void			*err_data;
	size_t			err_data_size;
};
{% endhighlight %}

The general reason for the error is provided through the err field.
Provider specific error information may also be available through the
prov_errno and err_data fields.  The err_data field, if set, will
reference an internal buffer owned by the provider.  The contents of
the buffer will remain valid until a subsequent read call against the
CQ.  Users may call kfi_cq_strerror to convert provider specific error
information into a printable string for debugging purposes.

## kfi_cq_write / kfi_cq_writeerr

The kfi_cq_write and kfi_cq_writeerr operations insert user-generated
completion entries into a completion queue.  kfi_cq_write inserts
non-error events into the CQ.  The format of the kfi_cq_write event
must be the same as the kfi_cq_format attribute defined for the CQ when
it was created.  kfi_cq_writeerr inserts error events into the CQ.  The
error event format is struct kfi_cq_err_entry.  The number of entries
to insert into the CQ is determined by the len parameter.  Len must be
a multiple of the size of the event to insert.

User events inserted into a CQ with be associated with the source address
KFI_ADDR_NOTAVAIL.

# COMPLETION FLAGS

Completion flags provide additional details regarding the completed
operation.  The following completion flags are defined.

*KFI_REMOTE_CQ_DATA
: This indicates that remote CQ data is available as part of the
  completion.

*KFI_MULTI_RECV*
: This flag applies to receive buffers that were posted with the
  KFI_MULTI_RECV flag set.  This completion flag indicates that the
  receive buffer referenced by the completion has been consumed and
  was released by the provider.

# RETURN VALUES

kfi_cq_open
: Returns 0 on success.  On error, a negative value corresponding to
  kfabric errno is returned.

kfi_cq_read / kfi_cq_readfrom / kfi_cq_readerr
kfi_cq_sread / kfi_cq_sreadfrom
: On success, returns the number of completion events retrieved from
  the completion queue.  On error, a negative value corresponding to
  kfabric errno is returned. On timeout, -KFI_ETIMEDOUT is returned.

kfi_cq_strerror
: Returns a character string interpretation of the provider specific
  error returned with a completion.

Kfabric errno values are defined in
`kfi_errno.h`.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_eq`(3)](kfi_eq.3.html),
[`kfi_cntr`(3)](kfi_cntr.3.html),
[`kfi_poll`(3)](kfi_poll.3.html)
