---
layout: page
title: kfi_cntr(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_cntr \- Completion and event counter operations

kfi_cntr_open / kfi_close
: Allocate/free a counter

kfi_cntr_read
: Read the current value of a counter

kfi_cntr_readerr
: Reads the number of operations which have completed in error.

kfi_cntr_add
: Increment a counter by a specified value

kfi_cntr_set
: Set a counter to a specified value

kfi_cntr_wait
: Wait for a counter to be greater or equal to a threshold value

# SYNOPSIS

{% highlight c %}
#include <kfi_domain.h>

int
kfi_cntr_open(struct kfid_domain *domain, struct kfi_cntr_attr *attr,
	      struct kfid_cntr **cntr, void *context)

int
kfi_close(struct kfid *fid)

uint64_t
kfi_cntr_read(struct kfid_cntr *cntr)

uint64_t
kfi_cntr_readerr(struct kfid_cntr *cntr)

int
kfi_cntr_add(struct kfid_cntr *cntr, uint64_t value)

int
kfi_cntr_set(struct kfid_cntr *cntr, uint64_t value)

int
kfi_cntr_wait(struct kfid_cntr *cntr, uint64_t threshold, int timeout)
{% endhighlight %}

# ARGUMENTS

*domain*
: Kfabric domain

*cntr*
: Kfabric counter

*attr*
: Counter attributes

*context*
: User specified context associated with the counter

*value*
: Value to increment or set counter

*threshold*
: Value to compare counter against

*timeout*
: Time in milliseconds to wait.  A negative value indicates infinite
  timeout.

# DESCRIPTION

Counters record the number of requested operations that have
completed.  Counters can provide a light-weight completion mechanism
by suppressing the generation of a full completion event.  They are
useful for applications that only need to know the number of requests
that have completed, and not details about each request.  For example,
counters may be useful for implementing credit based flow control or
tracking the number of remote processes which have responded to a
request.

Counters typically only count successful completions.  However, if an
operation completes in error, it may increment an associated error
value.

## kfi_cntr_open

kfi_cntr_open allocates a new fabric counter.  The properties and
behavior of the counter are defined by `struct kfi_cntr_attr`.

{% highlight c %}
struct kfi_cntr_attr {
	enum kfi_cntr_events	events;
	enum kfi_wait_obj	wait_obj;
	struct kfid_wait	*wait_set;
	uint64_t		flags;
};
{% endhighlight %}

*events*
: A counter captures different types of events.  The specific type
  which is to counted are one of the following:

- *KFI_CNTR_EVENTS_COMP*
: The counter increments for every successful completion that occurs
  on an associated bound endpoint.  The type of completions -- sends
  and/or receives -- which are counted may be restricted using control
  flags when binding the counter an the endpoint.  Counters increment
  on all successful completions, separately from whether the operation
  generates an entry in an event queue.

*wait_obj*
: Counters may be associated with a specific wait object.  Wait
  objects allow applications to block until the wait object is
  signaled, indicating that a counter has reached a specific
  threshold.  Users may use kfi_control to retrieve the underlying wait
  object associated with a counter, in order to use it in other system
  calls.  The following values may be used to specify the type of wait
  object associated with a counter: KFI_WAIT_NONE, KFI_WAIT_UNSPEC,
  KFI_WAIT_SET, and KFI_WAIT_QUEUE.

- *KFI_WAIT_NONE*
: Used to indicate that the user will not block (wait) for events on
  the counter.

- *KFI_WAIT_UNSPEC*
: Specifies that the user will only wait on the counter using fabric
  interface calls, such as kfi_cntr_readcond.  In this case, the
  underlying provider may select the most appropriate or highest
  performing wait object available, including custom wait mechanisms.
  Applications that select KFI_WAIT_UNSPEC are not guaranteed to
  retrieve the underlying wait object.

- *KFI_WAIT_SET*
: Indicates that the event counter should use a wait set object to
  wait for events.  If specified, the wait_set field must reference an
  existing wait set object.

- *KFI_WAIT_QUEUE*
: Specifies that a linux kernel wait queue is used as a method
  allowing the thread to sleep until completion.

*wait_set*
: If wait_obj is KFI_WAIT_SET, this field references a wait object to
  which the event counter should attach.  When an event is added to
  the event counter, the corresponding wait set will be signaled if
  all necessary conditions are met.  The use of a wait_set enables an
  optimized method of waiting for events across multiple event
  counters.  This field is ignored if wait_obj is not KFI_WAIT_SET.

*flags*
: Flags are reserved for future use, and must be set to 0.

## kfi_close

The fki_close call releases all resources associated with a counter.  When
closing the counter, there must be no opened endpoints, transmit contexts,
receive contexts or memory regions associated with the counter.  If resources
are still associated with the counter when attempting to close, the call will
return -KFI_EBUSY.


## kfi_cntr_control

The kfi_cntr_control call is used to access provider or implementation
specific details of the counter.  Access to the counter should be
serialized across all calls when kfi_cntr_control is invoked, as it may
redirect the implementation of counter operations.  The following
control commands are usable with a counter:

*KFI_GETOPSFLAG (uint64_t \*)*
: Returns the current default operational flags associated with the counter.

*KFI_SETOPSFLAG (uint64_t \*)*
: Modifies the current default operational flags associated with the
  counter.

*KFI_GETWAIT (void \*\*)*
: This command allows the user to retrieve the low-level wait object
  associated with the counter.  The format of the wait-object is
  specified during counter creation, through the counter attributes.
  See kfi_eq.3 for addition details using control with KFI_GETWAIT.

## kfi_cntr_read

The kfi_cntr_read call returns the current value of the counter.

## fki_cntr_readerr

The read error call returns the number of operations that completed in
error and were unable to update the counter.

## kfi_cntr_add

This adds the user-specified value to the counter.

## kfi_cntr_set

This sets the counter to the specified value.

## kfi_cntr_wait

This call may be used to wait until the counter reaches the specified
threshold, or until an error or timeout occurs.  Upon successful
return from this call, the counter will be greater than or equal to
the input threshold value.

If an operation associated with the counter encounters an error, it
will increment the error value associated with the counter.  Any
change in a counter's error value will unblock any thread inside
kfi_cntr_wait.

If the call returns due to timeout, -KFI_ETIMEDOUT will be returned.
The error value associated with the counter remains unchanged.

# RETURN VALUES

Returns 0 on success.  On error, a negative value corresponding to
kfabric errno is returned.

kfi_cntr_read /  kfi_cntr_readerr
: Returns the current value of the counter.

Kfabric errno values are defined in
`kfi_errno.h`.

# NOTES


# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_eq`(3)](kfi_eq.3.html),
[`kfi_poll`(3)](kfi_poll.3.html)
