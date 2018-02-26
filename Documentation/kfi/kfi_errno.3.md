---
layout: page
title: kfi_errno(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_errno \- kfabric errors

kfi_strerror \- Convert kfabric error into a printable string

# SYNOPSIS

{% highlight c %}
#include <kfi_errno.h>

const char *
kfi_strerror(int errnum);
{% endhighlight %}


# ERRORS

*KFI_ENOENT*
: No such file or directory

*KFI_EIO*
: I/O error

*KFI_E2BIG*
: Argument list too long

*KFI_EBADF*
: Bad file number

*KFI_EAGAIN*
: Try again

*KFI_ENOMEM*
: Out of memory

*KFI_EACCES*
: Permission denied

*KFI_EBUSY*
: Device or resource busy

*KFI_ENODEV*
: No such device

*KFI_EINVAL*
: Invalid argument

*KFI_EMFILE*
: Too many open files

*KFI_ENOSPC*
: No space left on device

*KFI_ENOSYS*
: Function not implemented

*KFI_ENOMSG*
: No message of desired type

*KFI_ENODATA*
: No data available

*KFI_EMSGSIZE*
: Message too long

*KFI_ENOPROTOOPT*
: Protocol not available

*KFI_EOPNOTSUPP*
: Operation not supported on transport endpoint

*KFI_EADDRINUSE*
: Address already in use

*KFI_EADDRNOTAVAIL*
: Cannot assign requested address

*KFI_ENETDOWN*
: Network is down

*KFI_ENETUNREACH*
: Network is unreachable

*KFI_ECONNABORTED*
: Software caused connection abort

*KFI_ECONNRESET*
: Connection reset by peer

*KFI_EISCONN*
: Transport endpoint is already connected

*KFI_ENOTCONN*
: Transport endpoint is not connected

*KFI_ESHUTDOWN*
: Cannot send after transport endpoint shutdown

*KFI_ETIMEDOUT*
: Connection timed out

*KFI_ECONNREFUSED*
: Connection refused

*KFI_EHOSTUNREACH*
: No route to host

*KFI_EALREADY*
: Operation already in progress

*KFI_EINPROGRESS*
: Operation now in progress

*KFI_EREMOTEIO*
: Remote I/O error

*KFI_ECANCELED*
: Operation Canceled

*KFI_EKEYREJECTED*
: Key was rejected by service

*KFI_EOTHER*
: Unspecified error

*KFI_ETOOSMALL*
: Provided buffer is too small

*KFI_EOPBADSTATE*
: Operation not permitted in current state

*KFI_EAVAIL*
: Error available

*KFI_EBADFLAGS*
: Flags not supported

*KFI_ENOEQ*
: Missing or unavailable event queue

*KFI_EDOMAIN*
: Invalid resource domain

*KFI_ENOCQ*
: Missing or unavailable completion queue

*KFI_ECRC*
: CRC error

*KFI_ETRUNC*
: Truncation error

*KFI_ENOKEY*
: Required key not available

*KFI_ENOAV*
: Missing or unavailable address vector

*KFI_EOVERRUN*
: Queue has been overrun

# SEE ALSO

[`kfabric`(7)](kfabric.7.html)
