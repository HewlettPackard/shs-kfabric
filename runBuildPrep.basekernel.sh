#!/bin/bash

# Add OS-appropriate repos for build dependencies

if [[ -v SHS_NEW_BUILD_SYSTEM ]]; then
  . ${CE_INCLUDE_PATH}/buildprep-common.sh

  install_dependencies "cray-kfabric.spec"
  replace_release_metadata "cray-kfabric.spec"

else
  :  # old build system
set -x

cat > vars.sh <<- END
ROOT_DIR=`pwd`
PRODUCT=${PRODUCT:-"slingshot"}
EXTRA=${EXTRA:-"slingshot-host-software"}
TARGET_ARCH=${TARGET_ARCH:-"x86_64"}
BRANCH_NAME=${BRANCH_NAME:-"master"}
ARTIFACT_REPO_HOST=${ARTIFACT_REPO_HOST:-"arti.hpc.amslabs.hpecorp.net"}
TARGET_OS=${TARGET_OS:-"sle15_sp5_ncn"}
END

. vars.sh
. zypper-local.sh

if [[ "${BRANCH_NAME}" == release/* ]]; then
    ARTI_LOCATION='rpm-stable-local'
    ARTI_BRANCH=${BRANCH_NAME}
elif [[ "${CHANGE_TARGET}" == release/* ]]; then
    # CHANGE_TARGET is only set for PR builds and points to the PR target branch
    ARTI_LOCATION='rpm-stable-local'
    ARTI_BRANCH=${CHANGE_TARGET}
else
    ARTI_LOCATION='rpm-master-local'
    ARTI_BRANCH=dev/master
fi


cat >> vars.sh <<- END
ARTI_URL=${ARTI_URL:-"https://${ARTIFACT_REPO_HOST}/artifactory"}
ARTI_LOCATION=${ARTI_LOCATION:-"rpm-master-local"}
ARTI_BRANCH=${ARTI_BRANCH:-"dev/master"}
OS_TYPE=`cat /etc/os-release | grep "^ID=" | sed "s/\"//g" | cut -d "=" -f 2`
OS_VERSION=`cat /etc/os-release | grep "^VERSION_ID=" | sed "s/\"//g" | cut -d "=" -f 2`
BRANCH=`git branch --show-current`
END

. vars.sh

OS_TYPE=`cat /etc/os-release | grep "^ID=" | sed "s/\"//g" | cut -d "=" -f 2`
OS_VERSION=`cat /etc/os-release | grep "^VERSION_ID=" | sed "s/\"//g" | cut -d "=" -f 2`
OS_MAJOR_VERSION=`echo ${OS_VERSION} | cut -d "." -f 1`

if [ -d hpc-shs-version ]; then
    git -C hpc-shs-version pull
else
    if [[ -n "${SHS_LOCAL_BUILD}" ]]; then
	git clone git@github.hpe.com:hpe/hpc-shs-version.git
    else
	git clone https://$HPE_GITHUB_TOKEN@github.hpe.com/hpe/hpc-shs-version.git
    fi
fi

. hpc-shs-version/scripts/get-shs-version.sh
. hpc-shs-version/scripts/get-shs-label.sh

PRODUCT_VERSION=$(get_shs_version)
PRODUCT_LABEL=$(get_shs_label)

cat >> vars.sh <<- END
PRODUCT_VERSION=${PRODUCT_VERSION}
PRODUCT_LABEL=${PRODUCT_LABEL}
END

sed -i -e "s/Release:.*/Release: ${PRODUCT_LABEL}${PRODUCT_VERSION}_%(echo \\\${BUILD_METADATA:-1})/g" cray-kfabric.spec

if [ -d ${WORKSPACE} ]; then
    rm -rf ${WORKSPACE}
fi

echo "$0: --> BRANCH_NAME: '${BRANCH_NAME}'"
echo "$0: --> CHANGE_TARGET: '${CHANGE_TARGET}'"
echo "$0: --> PRODUCT: '${PRODUCT}'"
echo "$0: --> TARGET_ARCH: '${TARGET_ARCH}'"
echo "$0: --> TARGET_OS: '${TARGET_OS}'"
echo "$0: --> OS_VERSION: '${OS_VERSION}'"
echo "$0: --> OS_MAJOR_VERSION: '${OS_MAJOR_VERSION}'"
echo "$0: --> ARTI_LOCATION: '${ARTI_LOCATION}'"
echo "$0: --> ARTI_BRANCH: '${ARTI_BRANCH}'"
echo "$0: --> WORKSPACE: '${WORKSPACE}'"

repo_remove_add_refresh () {
    # $1 - repo name
    # $2 - repo_url

    ${ZYPPER_COMMAND} lr $1
    res=$?

    if [ $res -eq 0 ]; then
        echo "Removing repo \"$1\""
        ${ZYPPER_COMMAND} rr $1
    else
    	echo "Repo \"$1\" not present"
    fi
    ${ZYPPER_COMMAND} addrepo --no-gpgcheck --check \
        --priority 1 --name=$1 \
         $2/ \
         $1
    ${ZYPPER_COMMAND} refresh $1
}

if [ "$ZYPPER_COMMAND" ]; then
    mkdir -p $ZYPPER_ROOT/etc/zypp/repos.d
    mkdir -p $ZYPPER_ROOT/var/cache/zypp
    mkdir -p $ZYPPER_ROOT/var/cache/zypp/raw
    mkdir -p $ZYPPER_ROOT/var/cache/zypp/solv
    mkdir -p $ZYPPER_ROOT/var/cache/zypp/packages

    cp -r /etc/zypp ${WORKSPACE}/zypp/etc
    cp -r /var/cache/zypp ${WORKSPACE}/zypp/var/cache

    repo_remove_add_refresh internal-${ARTI_LOCATION} ${ARTI_URL}/internal-${ARTI_LOCATION}/${ARTI_BRANCH}/${TARGET_OS}
    repo_remove_add_refresh internal-${ARTI_LOCATION}-firmware ${ARTI_URL}/internal-${ARTI_LOCATION}/${ARTI_BRANCH}/sle15_sp2
    repo_remove_add_refresh ${PRODUCT}-${ARTI_LOCATION} ${ARTI_URL}/${PRODUCT}-${ARTI_LOCATION}/${ARTI_BRANCH}/${TARGET_OS}

    # We need to manually install this RPM (rather than let the build process
    # install it automatically) since it contains the kernel-module-package
    # macros that our specfile uses
    V1=$(uname -r | cut -d"-" -f1)
    V2=$(uname -r | cut -d"-" -f2)
    
    ${ZYPPER_COMMAND} install -y kernel-default-devel

    exit 0

elif command -v yum > /dev/null; then
    yum-config-manager --setopt=gpgcheck=0 --save
    KERNEL_DEVEL_PKG=kernel-devel

    version_support_file=./hpc-sshot-slingshot-version/shs-kernel-support/${OS_TYPE}${OS_VERSION}.json
    if [ -f ${version_support_file} ]; then
        yum install -y jq
        for repo in $(jq -r '.[].repo | select( . != null)' ${version_support_file}); do
            yum-config-manager --add-repo $repo
        done
        yum -y install $(jq -r '.[].packages[] | select( . != null)' ${version_support_file})
    fi

    if [ $OS_TYPE = "centos" ]; then
        # Pin kernel version to 4.18.0-305 from Centos 8.4
        cat > /etc/yum.repos.d/dst-remote-centos8.repo <<- END
[dst-remote-centos8.4.2105]
name=DST remote centos8.4.2105
baseurl=https://arti.hpc.amslabs.hpecorp.net/artifactory/mirror-centos8.4/8.4.2105/BaseOS/x86_64/os/
enabled=1
gpgcheck=0
logfile=/var/log/yum.log
exclude=kernel

[dst-remote-centos8.4.2105-appstream]
name=DST remote centos8.4.2105 AppStream
baseurl=https://arti.hpc.amslabs.hpecorp.net/artifactory/mirror-centos8.4/8.4.2105/AppStream/x86_64/os/
enabled=1
gpgcheck=0
logfile=/var/log/yum.log

[dst-remote-centos8.4.2105-powertools]
name=DST remote centos8.4.2105 PowerTools
baseurl=https://arti.hpc.amslabs.hpecorp.net/artifactory/mirror-centos8.4/8.4.2105/PowerTools/x86_64/os/
enabled=1
gpgcheck=0
logfile=/var/log/yum.log
END
        KERNEL_DEVEL_PKG=kernel-devel-4.18.0-305.25.1.el8_4
    fi

    yum clean all
    yum install -y python3-dnf-plugin-versionlock
    yum install -y $KERNEL_DEVEL_PKG
    yum versionlock 'kernel-*'

    yum-config-manager --add-repo=${ARTI_URL}/${PRODUCT}-${ARTI_LOCATION}/${ARTI_BRANCH}/${TARGET_OS}/

    # We need to manually install this RPM (rather than let the build process
    # install it automatically) since it contains the kernel-module-package
    # macros that our specfile uses
    yum install -y kernel-rpm-macros

    exit 0
else
    "Unsupported package manager or package manager not found -- installing nothing"
    exit 0
fi

exit 0
fi
