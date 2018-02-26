---
layout: page
title: kfi_version(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_version \- Version of the library interfaces

# SYNOPSIS

{% highlight c %}
#include <kfabric.h>

uint32_t
kfi_version();

KFI_MAJOR(version)

KFI_MINOR(version)
{% endhighlight %}

# DESCRIPTION

This call returns the current version of the library interfaces.  The
version includes major and a minor numbers.  These may be extracted
from the returned value using the KFI_MAJOR() and KFI_MINOR() macros.

# NOTES

The library may support older versions of the interfaces.

# RETURN VALUE

Returns the current library version.  The upper 16-bits of the version
correspond to the major number, and the lower 16-bits correspond with
the minor number.

# SEE ALSO

[`kfabric`(7)](kfabric.7.html),
[`kfi_getinfo`(3)](kfi_getinfo.3.html)
