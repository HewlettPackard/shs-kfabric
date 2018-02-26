---
layout: page
title: kfi_fabric(3)
tagline: kfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

kfi_fabric \- Kfabric domain operations

kfi_fabric / kfi_close
: Open / close a kfabric domain

kfi_tostr
: Convert kfabric attributes, flags, and capabilities to printable string

# SYNOPSIS

{% highlight c %}
#include <kfabric.h>

int
kfi_fabric(struct kfi_fabric_attr *attr, struct kfid_fabric **fabric,
	      void *context)

int
kfi_close(struct kfid *fid)

char *
kfi_tostr(const void *data, enum kfi_type datatype)
{% endhighlight %}

# ARGUMENTS

*attr*
: Attributes of kfabric to open.

*fabric*
: Kfabric domain

*context*
: User specified context associated with the opened object.  This
  context is returned as part of any associated asynchronous event.

# DESCRIPTION

A kfabric domain represents a collection of hardware and software
resources that access a single physical or virtual network.  All
network ports on a system that can communicate with each other through
their attached networks belong to the same fabric domain.  A kfabric
domain shares network addresses and can span multiple providers.

## kfi_fabric

Opens a kfabric provider.  The attributes of the kfabric provider are
specified through the open call, and may be obtained by calling
kfi_getinfo.

## kfi_close

The kfi_close call is used to release all resources associated with a
kfabric domain or interface.  All items associated with the opened
kfabric must be released prior to calling kfi_close.

## kfi_tostr

Converts fabric interface attributes, capabilities, flags, and enum
values into a printable string.  The data parameter accepts a pointer
to the attribute or value(s) to display, with the datatype parameter
indicating the type of data referenced by the data parameter.  Valid
values for the datatype are listed below, along with the corresponding
datatype or field value.

*KFI_TYPE_INFO*
: struct kfi_info

*KFI_TYPE_EP_TYPE*
: struct kfi_info::type field

*KFI_TYPE_EP_CAP*
: struct kfi_info::ep_cap field

*KFI_TYPE_OP_FLAGS*
: struct kfi_info::op_flags field, or general uint64_t flags

*KFI_TYPE_ADDR_FORMAT*
: struct kfi_info::addr_format field

*KFI_TYPE_TX_ATTR*
: struct kfi_tx_attr

*KFI_TYPE_RX_ATTR*
: struct kfi_rx_attr

*KFI_TYPE_EP_ATTR*
: struct kfi_ep_attr

*KFI_TYPE_DOMAIN_ATTR*
: struct kfi_domain_attr

*KFI_TYPE_FABRIC_ATTR*
: struct kfi_fabric_attr

*KFI_TYPE_DOMAIN_CAP*
: struct kfi_info::domain_cap field

*KFI_TYPE_THREADING*
: enum kfi_threading

*KFI_TYPE_PROGRESS*
: enum kfi_progress

*KFI_TYPE_PROTO*
: struct kfi_ep_attr::protocol field

*KFI_TYPE_MSG_ORDER*
: struct kfi_ep_attr::msg_order field

*KFI_TYPE_VERSION*
: Returns the library version of libfabric in string form.  The data
  parameter is ignored.

kfi_tostr() will return a pointer to an internal libfabric buffer that
should not be modified, and will be overwritten the next time
kfi_tostr() is invoked.  kfi_tostr() is not thread safe.

# NOTES

The following resources are associated with kfabric domains: access
domains, passive endpoints, and CM event queues.

# KFABRIC ATTRIBUTES

The kfi_fabric_attr structure defines the set of attributes associated
with a fabric and a fabric provider.

{% highlight c %}
struct kfi_fabric_attr {
	struct kfid_fabric	*fabric;
	char			*name;
	char			*prov_name;
	uint32_t		prov_version;
};
{% endhighlight %}

## fabric

On input to kfi_getinfo, a user may set this to an opened kfabric
instance to restrict output to the given fabric.  On output from
kfi_getinfo, if no fabric was specified, but the user has an opened
instance of the named fabric, this will reference the first opened
instance.  If no instance has been opened, this field will be NULL.

## name

A fabric identifier.

## prov_name

The name of the underlying fabric provider.

## prov_version

Version information for the fabric provider.

# RETURN VALUE

Returns 0 on success. On error, a negative value corresponding to
kfabric errno is returned. Kfabric errno values are defined in
`kfi_errno.h`.

# ERRORS


# SEE ALSO

[`kfabric`(7)](kfabric.7.html),
[`kfi_getinfo`(3)](kfi_getinfo.3.html),
[`kfi_domain`(3)](kfi_domain.3.html),
[`kfi_eq`(3)](kfi_eq.3.html),
[`kfi_endpoint`(3)](kfi_endpoint.3.html)
