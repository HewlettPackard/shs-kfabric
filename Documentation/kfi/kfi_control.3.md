---
layout: page
title: kfi_control(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_control \- Perform an operation on a kfabric resource.

# SYNOPSIS

{% highlight c %}
#include <kfabric.h>

int
kfi_control(struct kfid *fid, int command, void *arg)
{% endhighlight %}


# ARGUMENTS

*fid*
: Kfabric resource

*command*
: Operation to perform

*arg*
: Optional argument to the command

# DESCRIPTION

The kfi_control operation is used to perform one or more operations on a
fabric resource.  Conceptually, kfi_control is similar to the POSIX fcntl
routine.  The exact behavior of using kfi_control depends on the fabric
resource being operated on, the specified command, and any provided
arguments for the command.  For specific details, see the fabric resource
specific help pages noted below.

# SEE ALSO

[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_cm`(3)](kfi_cm.3.html),
[`kfi_cntr`(3)](kfi_cntr.3.html),
[`kfi_cq`(3)](kfi_cq.3.html),
[`kfi_eq`(3)](kfi_eq.3.html),
