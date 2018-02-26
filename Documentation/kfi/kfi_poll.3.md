---
layout: page
title: kfi_poll(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_poll \- Polling and wait set operations

kfi_poll_open / kfi_close
: Open/close a polling set

kfi_poll_add / kfi_poll_del
: Add/remove an event queue or counter to/from a poll set.

kfi_poll
: Poll for progress and events across multiple event queues.

kfi_wait_open / kfi_close
: Open/close a wait set

kfi_wait
: Waits for one or more wait objects in a set to be signaled.

# SYNOPSIS

{% highlight c %}
#include <kfi_domain.h>

int
kfi_poll_open(struct kfid_domain *domain, struct kfi_poll_attr *attr,
	      struct kfid_poll **pollset)

int
kfi_close(struct kfid *fid)

int
kfi_poll_add(struct kfid_poll *pollset, struct kfid *event_kfid, uint64_t flags)

int
kfi_poll_del(struct kfid_poll *pollset, struct kfid *event_kfid, uint64_t flags)

int
kfi_poll(struct kfid_poll *pollset, void **context, int count)

int
kfi_wait_open(struct kfid_fabric *fabric, struct kfi_wait_attr *attr,
	      struct kfid_wait **waitset)

int
kfi_wait(struct kfid_wait *waitset, int timeout)
{% endhighlight %}

# ARGUMENTS

*fabric*
: Kfabric provider

*domain*
: Resource domain

*pollset*
: Event poll set

*waitset*
: Wait object set

*attr*
: Poll or wait set attributes

*context*
: On success, an array of user context values associated with an event
  queue or counter.

*count*
: Number of entries in context array.

*timeout*
: Time to wait for a signal, in milliseconds.

# DESCRIPTION


## kfi_poll_open

kfi_poll_open creates a new polling set.  A poll set enables an
optimized method for progressing asynchronous operations across
multiple event queues and counters and checking for their completions.

A poll set is defined with the following attributes.

{% highlight c %}
struct kfi_poll_attr {
	uint64_t		flags;
};
{% endhighlight %}

*flags*
: Flags that set the default operation of the poll set.  The use of
  this field is reserved and must be set to 0 by the caller.

## kfi_close

The kfi_close call releases all resources associated with a poll set.
The poll set must not be associated with any other resources prior to
being closed, otherwise the call will return -KFI_EBUSY.

## kfi_poll_add

Associates an event queue or counter with a poll set.

## kfi_poll_del

Removes an event queue or counter from a poll set.

## kfi_poll

Progresses all event queues and counters associated with a poll set
and checks for events.  If events has occurred, contexts associated
with the event queues and/or counters are returned.  The number of
contexts is limited to the size of the context array, indicated by the
count parameter.

## kfi_wait_open

kfi_wait_open allocates a new wait set.  A wait set enables an
optimized method of waiting for events across multiple event queues
and counters.  Where possible, a wait set uses a single underlying
wait object that is signaled when a specified condition occurs on an
associated event queue or counter.

The properties and behavior of a wait set are defined by struct
kfi_wait_attr.

{% highlight c %}
struct kfi_wait_attr {
	enum kfi_wait_obj	wait_obj;
	uint64_t		flags;
};
{% endhighlight %}

*wait_obj*
: Wait sets are associated with specific wait object(s).  Wait objects
  allow applications to block until the wait object is signaled,
  indicating that an event is available to be read.  The following
  values may be used to specify the type of wait object associated
  with a wait set: KFI_WAIT_UNSPEC, KFI_WAIT_MUTEX_COND, and
  KFI_WAIT_QUEUE.

- *KFI_WAIT_UNSPEC*
: Specifies that the user will only wait on the wait set using
  fabric interface calls, such as kfi_wait.  In this case, the
  underlying provider may select the most appropriate or highest
  performing wait object available, including custom wait mechanisms.
  Applications that select KFI_WAIT_UNSPEC are not guaranteed to
  retrieve the underlying wait object.

- *KFI_WAIT_MUTEX_COND*
: Specifies that the wait set should use a pthread mutex and cond
  variable as a wait object.

- *KFI_WAIT_QUEUE*
: Specifies that a linux kernel wait queue is used as a method
  allowing the thread to sleep until completion.

*flags*
: Flags that set the default operation of the wait set.  The use of
  this field is reserved and must be set to 0 by the caller.

## kfi_close

The kfi_close call releases all resources associated with a wait set.
The wait set must not be bound to any other opened resources prior to
being closed, otherwise the call will return -KFI_EBUSY.

## kfi_wait

Waits on a wait set until one or more of its underlying wait objects
is signaled.

# RETURN VALUES

Returns 0 on success.  On error, a negative value corresponding to
kfabric errno is returned.

Kfabric errno values are defined in
`kfi_errno.h`.

kfi_poll
: On success, if events are available, returns the number of entries
  written to the context array.

# NOTES


# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_cntr`(3)](kfi_cntr.3.html),
[`kfi_eq`(3)](kfi_eq.3.html)
