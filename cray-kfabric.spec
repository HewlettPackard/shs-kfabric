%define release_extra 0

%{!?dkms_source_tree:%define dkms_source_tree /usr/src}

%if 0%{?rhel}
%define distro_kernel_package_name kmod-%{name}
%else
%define distro_kernel_package_name %{name}-kmp
%endif


# Exclude -preempt kernel flavor, this seems to get built alongside the -default
# flavor for stock SLES. It doesn't get used, and its presence can cause issues
# (see NETCASSINI-4032)
%define kmp_args_common -x preempt -p %{_sourcedir}/%name.rpm_preamble

%if 0%{?rhel}
# On RHEL, override the kmod RPM name to include the kernel version it was built
# for; this allows us to package the same driver for multiple kernel versions.
%define kmp_args -n %name-k%%kernel_version %kmp_args_common
%else
%define kmp_args %kmp_args_common
%endif

%if 0%{?rhel}
%define kmod_packagename kmod-%{name}
%else
%define kmod_packagename %{name}-kmp
%endif

Name:       cray-kfabric
Version:    0.1.0
Release:    %(echo ${BUILD_METADATA})
Summary:    Kfabric API
License:    GPL-2.0-only OR BSD-2-Clause
Source:     %{name}-%{version}.tar.gz
Prefix:     /usr

BuildRequires:  cray-cxi-driver-devel
BuildRequires:  %kernel_module_package_buildreqs
BuildRequires:  pandoc
BuildRequires:  perl

# Generate a preamble that gets attached to the kmod RPM(s). Kernel module
# dependencies can be declared here. The 'Obsoletes' and 'Provides' lines for
# RHEL allow the package to be referred to by its base name without having to
# explicitly specify a kernel version.
%(/bin/echo -e "\
Requires:       cray-libcxi-retry-handler \n\
%if 0%%{?rhel} \n\
Requires:       kmod-cray-cxi-driver \n\
Obsoletes:      kmod-%%{name} \n\
Provides:       kmod-%%{name} = %%version-%%release \n\
%else \n\
Requires:       cray-cxi-driver-kmp-%1 \n\
%endif" > %{_sourcedir}/%{name}.rpm_preamble)

%kernel_module_package %kmp_args

%description
Kfabric API

%package devel
Summary: Kfabric development files

%description devel
Kfabric development files

%package udev
Summary:    Udev rules for kfabric driver
Requires:   (%{distro_kernel_package_name} or cray-kfabric-dkms)

%description udev
Udev rules for kfabric

%package dracut
Summary: dracut files for kfabric driver
Requires:   cray-kfabric-udev

%description dracut
dracut initramfs support for kfabric driver

%package dkms
Summary:    DKMS package for kfabric
BuildArch:  noarch
Requires:   dkms
Requires:   cray-cassini-headers-user
Requires:   cray-slingshot-base-link-dkms
Requires:   cray-slingshot-base-link-devel
Requires:   cray-cxi-driver-dkms
Requires:   cray-cxi-driver-devel
Conflicts:  kmod-%name
Conflicts:  %name-kmp

%description dkms
DKMS support for kfabric

%prep
%setup

set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
for flavor in %flavors_to_build; do
    rm -rf obj/$flavor
    cp -r source obj/$flavor

    make -C %{kernel_source $flavor} modules M=$PWD/obj/$flavor KCPPFLAGS=-I%{_includedir} KBUILD_EXTRA_SYMBOLS=%{prefix}/src/cxi/$flavor/Module.symvers %{?_smp_mflags}
done

%install
rm -rf source/include/cassini_cntr_defs.h source/include/cassini_user_defs.h source/include/cxi_prov_hw.h source/include/linux source/include/uapi

export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/%{name}
for flavor in %flavors_to_build; do
    make -C %{kernel_source $flavor} modules_install M=$PWD/obj/$flavor
    install -D obj/$flavor/Module.symvers $RPM_BUILD_ROOT/%{prefix}/src/kfabric-%{version}/$flavor/Module.symvers
done

rm -rf $INSTALL_MOD_PATH/lib/modules/*/$INSTALL_MOD_DIR/tests/
rm -rf $INSTALL_MOD_PATH/lib/modules/*/$INSTALL_MOD_DIR/prov/ibverbs/

for flavor in %flavors_to_build; do
    for header in source/include/*.h; do
        install -D $header %{buildroot}/%{prefix}/src/kfabric-%{version}/$flavor/include/$(basename $header)
    done
done

install -D --mode=0644 --target-directory=%{buildroot}/%{_udevrulesdir} source/70-kfabric.rules

mkdir -p %{buildroot}/%{_mandir}/man{3,7}
pushd source
make nroff
popd
install -D --target-directory=%{buildroot}/%{_mandir}/man3 source/Documentation/kfi/man3/*
install -D --target-directory=%{buildroot}/%{_mandir}/man7 source/Documentation/kfi/man7/*

install -D --target-directory=%{buildroot}/etc/dracut.conf.d/ source/dracut.conf.d/*.conf

%if 0%{?rhel}
# Centos/Rocky/RHEL does not exclude the depmod-generated modules.* files from
# the RPM, causing file conflicts when updating
find $RPM_BUILD_ROOT -iname 'modules.*' -exec rm {} \;
%endif

# DKMS bits
dkms_source_dir=%{dkms_source_tree}/%{name}-%{version}-%{release}
mkdir -p %{buildroot}/${dkms_source_dir}
cp -r source/* %{buildroot}/${dkms_source_dir}

sed \
    -e '/^$/d' \
    -e '/^#/d' \
    -e 's/@PACKAGE_NAME@/%{name}/g' \
    -e 's/@PACKAGE_VERSION@/%{version}-%{release}/g' \
    %{buildroot}/${dkms_source_dir}/dkms.conf.in \
    > %{buildroot}/${dkms_source_dir}/dkms.conf

rm %{buildroot}/${dkms_source_dir}/dkms.conf.in

echo "%dir ${dkms_source_dir}" > dkms-files
echo "${dkms_source_dir}" >> dkms-files

%pre dkms

%post dkms
if [ -f /usr/libexec/dkms/common.postinst ] && [ -x /usr/libexec/dkms/common.postinst ]
then
    postinst=/usr/libexec/dkms/common.postinst
elif [ -f /usr/lib/dkms/common.postinst ] && [ -x /usr/lib/dkms/common.postinst ]
then
    postinst=/usr/lib/dkms/common.postinst
else
    echo "ERROR: did not find DKMS common.postinst" >&2
    exit 1
fi

${postinst} %{name} %{version}-%{release}

%preun dkms
# 'dkms remove' may fail in some cases (e.g. if the user has already run 'dkms
# remove'). Allow uninstallation to proceed even if it fails.
/usr/sbin/dkms remove -m %{name} -v %{version}-%{release} --all --rpm_safe_upgrade || true

%files dkms -f dkms-files

%post devel
ln -s %{prefix}/src/kfabric-%{version} %{prefix}/src/kfabric

%postun devel
rm %{prefix}/src/kfabric

%files devel
%{prefix}/src/kfabric-%{version}
%{_mandir}/man3/*
%{_mandir}/man7/*

%files udev
%{_udevrulesdir}/70-kfabric.rules

%postun dracut
# Remove firmware from initrd.
%if 0%{?rhel}
/usr/bin/dracut --force
%else
if test -x /usr/lib/module-init-tools/regenerate-initrd-posttrans; then
        mkdir -p /run/regenerate-initrd
        touch /run/regenerate-initrd/all
        /bin/bash -${-/e/} /usr/lib/module-init-tools/regenerate-initrd-posttrans
fi
%endif

%posttrans dracut
# Install firmware in initrd.
%if 0%{?rhel}
/usr/bin/dracut --force
%else
if test -x /usr/lib/module-init-tools/regenerate-initrd-posttrans; then
        mkdir -p /run/regenerate-initrd
        touch /run/regenerate-initrd/all
        /bin/bash -${-/e/} /usr/lib/module-init-tools/regenerate-initrd-posttrans
fi
%endif

%if 0%{?rhel}
%define dracut_triggers kmod-cray-kfabric cray-kfabric-udev
%else
%define dracut_triggers cray-kfabric-kmp cray-kfabric-udev
%endif

%triggerin -n %{name}-dracut -- %dracut_triggers
%if 0%{?rhel}
/usr/bin/dracut --force
%else
if test -x /usr/lib/module-init-tools/regenerate-initrd-posttrans; then
        mkdir -p /run/regenerate-initrd
        touch /run/regenerate-initrd/all
        /bin/bash -${-/e/} /usr/lib/module-init-tools/regenerate-initrd-posttrans
fi
%endif

%triggerpostun -n %{name}-dracut -- %dracut_triggers
%if 0%{?rhel}
/usr/bin/dracut --force
%else
if test -x /usr/lib/module-init-tools/regenerate-initrd-posttrans; then
        mkdir -p /run/regenerate-initrd
        touch /run/regenerate-initrd/all
        /bin/bash -${-/e/} /usr/lib/module-init-tools/regenerate-initrd-posttrans
fi
%endif

%files dracut
/etc/dracut.conf.d/*.conf

%changelog
