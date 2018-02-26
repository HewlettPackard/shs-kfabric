---
layout: page
title: kfi_trigger(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_trigger - Triggered operations

# SYNOPSIS

{% highlight c %}
#include <kfi_trigger.h>
{% endhighlight %}

# DESCRIPTION

Triggered operations allow an application to queue a data transfer
request that is deferred until a specified condition is met.  A typical
use is to send a message only after receiving all input data.

A triggered operation may be requested by specifying the KFI_TRIGGER
flag as part of the operation.  Alternatively, an endpoint alias may
be created and configured with the KFI_TRIGGER flag.  Such an endpoint
is referred to as a triggerable endpoint.  All data transfer
operations on a triggerable endpoint are deferred.

Any data transfer operation is potentially triggerable, subject to
provider constraints.  Triggerable endpoints are initialized such that
only those interfaces supported by the provider which are triggerable
are available.

Triggered operations require that applications use struct
kfi_triggered_context as their per operation context parameter.  The
use of struct kfi_triggered_context replaces struct kfi_context, if
required by the provider.  Although struct kfi_triggered_context is not
opaque to the application, the contents of the structure may be
modified by the provider.  This structure has similar requirements as
struct kfi_context.  It must be allocated by the application and remain
valid until the corresponding operation completes or is successfully
canceled.

Struct kfi_triggered_context is used to specify the condition that must
be met before the triggered data transfer is initiated.  If the
condition is met when the request is made, then the data transfer may
be initiated immediately.  The format of struct kfi_triggered_context
is described below.

{% highlight c %}
struct kfi_triggered_context {
	enum kfi_trigger_event			event_type;
	union {
		struct kfi_trigger_threshold	threshold;
		void				*internal[3];
	} trigger;
};
{% endhighlight %}

The triggered context indicates the type of event assigned to the
trigger, along with a union of trigger details that is based on the
event type.

## TRIGGER EVENTS

The following trigger events are defined.

*KFI_TRIGGER_THRESHOLD*
: This indicates that the data transfer operation will be deferred
  until an event counter crosses an application specified threshold
  value.  The threshold is specified using struct
  kfi_trigger_threshold:

{% highlight c %}
struct kfi_trigger_threshold {
	struct kfid_cntr	*cntr;
	size_t			threshold;
};
{% endhighlight %}

Threshold operations are triggered in the order of the threshold
values.  This is true even if the counter increments by a value
greater than 1.  If two triggered operations have the same threshold,
they will be triggered in the order in which they were submitted to
the endpoint.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_alias`(3)](kfi_alias.3.html),
[`kfi_cntr`(3)](kfi_cntr.3.html)
