---
layout: page
title: kfi_direct(7)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

Direct kfabric provider access

# SYNOPSIS

{% highlight c %}
-DKFABRIC_DIRECT

#define KFABRIC_DIRECT
{% endhighlight %}

Kfabric direct provides a mechanism for applications to compile against
a specific fabric providers without going through the kfabric
framework or function vector tables.  This allows for extreme
optimization via function inlining at the cost of supporting multiple
providers or different versions of the same provider.

# DESCRIPTION

The use of kfabric direct is intended only for applications that
require the absolute minimum software latency, and are willing to
re-compile for specific kfabric hardware.  Providers that support
kfabric direct implement their own versions of the static inline calls
which are define in the kfabric header files, define selected enum
values, and provide defines for compile-time optimizations.
Applications can then code against the standard kfabric calls, but
link directly against the provider calls by defining KFABRIC_DIRECT as
part of their build.

In general, the use of fabric direct does not require application
source code changes, and, instead, is limited to the build process.

Providers supporting fabric direct must install 'direct' versions of
all kfabric header files.  For convenience, the kfabric sources
contain sample header files that may be modified by a provider.  The
'direct' header file names have 'kfi_direct' as their prefix:
kfi_direct.h, , etc.

Direct providers are prohibited from overriding or modifying existing
data structures.  However, provider specific extensions are still
available.  In addition to provider direct function calls to provider
code, a fabric direct provider may define zero of more of the
following capability definitions.  Applications can check for these
capabilities in order to optimize code paths at compile time, versus
relying on run-time checks.

# CAPABILITY DEFINITIONS

In order that application code may be optimized during compile time,
direct providers must provide definitions for various capabilities and
modes, if those capabilities are supported.

# SEE ALSO

[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html),
[`kfi_domain`(3)](kfi_domain.3.html)
