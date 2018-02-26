#!/bin/sh
#
# Run the local node as a client or server.
#
# This script will find a CXI device and configure an Ethernet interface
# accordingly. The network used for the IP interface is 192.168.1.0/24.
#
# The resulting IP addresses are passed as module parameters into the
# test module.
#
# This script is intended to be used across VMs. In the CXI core repo
# scripts directory, run the following command to bring up multiple VMs
# each in a xterm.
#
# USE_XTERM=1 ./startvm.sh -n 2 -dd
#
# Then run this script to perform the test.

TOP_DIR=$(realpath $(dirname "$0")/../../..)
SBL=$TOP_DIR/../slingshot_base_link/cxi-sbl.ko
CXI_SS1=$TOP_DIR/../cxi-driver/cxi/cxi-ss1.ko disable_default_svc=0
CXI_USER=$TOP_DIR/../cxi-driver/cxi/cxi-user.ko
CXI_ETH=$TOP_DIR/../cxi-driver/cxi/cxi-eth.ko
KFABRIC=$TOP_DIR/kfi/kfabric.ko
CXI_PROV=$TOP_DIR/prov/cxi/kfi_cxi.ko
MULTI_NIC_MSG=$TOP_DIR/tests/cxi/multi_client/multi-nic-msg.ko
CXI_DEVICE=/sys/class/cxi_user/cxi0/nic_addr
CXI_NIC_ADDR="192.168.1.1"
REMOTE_CXI_NIC_ADDR="192.168.1.2"
MODE="none"

function help {
	echo "$0 <--client|--server>"
	echo -e "\t--client: Run as client"
	echo -e "\t--server: Run as server"
	echo ""
}

function no_oops {
	if [ $(dmesg | grep -c 'Modules linked in') -ne 0 ]; then
		dmesg
		exit 1
	fi
}

function configure_eth {
	# Locate the first down Ethernet interface and configure it.
	regex="eth([0-9]{1}).+DOWN"
	eth_id=-1
	interfaces="$(ip addr)"
	if [[ $interfaces =~ $regex ]]; then
		eth_id=${BASH_REMATCH[1]}
	fi

	if [ $eth_id -eq -1 ]; then
		echo "Failed to find Ethernet interface"
		exit 1
	fi

	# Build MAC address.
	nic_addr="$(cat $CXI_DEVICE)"
	octet="$(printf "%02X" $nic_addr)"
	mac_addr="00:0E:AB:00:00:$octet"

	# Build IP address based on NIC address.
	nic_addr=$(printf "%d" $nic_addr)
	nic_addr=$(($nic_addr+1))
	ip_addr="$(printf "192.168.1.%d/24" $nic_addr)"

	ip link set eth$eth_id address $mac_addr
	ip addr add dev eth$eth_id $ip_addr
	ip link set dev eth$eth_id up
}

function enable_debug {
	echo 8 > /proc/sys/kernel/printk
	echo -n 'module cxi_ss1 +p' > /sys/kernel/debug/dynamic_debug/control
	echo -n 'module cxi_eth +p' > /sys/kernel/debug/dynamic_debug/control
	echo -n 'module kfi_cxi +p' > /sys/kernel/debug/dynamic_debug/control
}

function load_cxi_prov {
	modprobe ptp
	modprobe iommu_v2 || modprobe amd_iommu_v2
	insmod $SBL
	insmod $CXI_SS1
	insmod $CXI_USER
	insmod $CXI_ETH
	insmod $KFABRIC
	insmod $CXI_PROV

	# Short sleep to let Ethernet driver load.
	sleep 2

	no_oops
}

function unload_cxi_prov {
	rmmod kfi_cxi
	rmmod kfabric
	rmmod cxi_eth
	rmmod cxi_user
	rmmod cxi_ss1
	rmmod cxi-sbl
	rmmod iommu_v2
	rmmod amd_iommu_v2
	rmmod ptp

	no_oops
}

function load_multi_nic_msg {
	server=0
	server_nic="deadbeef"
	client_nic="deadbeef"
	args="deadbeef"

	if [ $MODE == "server" ]; then
		server_nic=$CXI_NIC_ADDR
		client_nic=$REMOTE_CXI_NIC_ADDR
		server=1
	else
		server_nic=$REMOTE_CXI_NIC_ADDR
		client_nic=$CXI_NIC_ADDR
		server=0
	fi

	args="server=$server client_nic=$client_nic server_nic=$server_nic"

	insmod $MULTI_NIC_MSG $args

	no_oops
}

function unload_multi_nic_msg {
	rmmod multi_nic_msg

	no_oops
}

function get_nic_addr {
	if [ ! -f $CXI_DEVICE ]; then
		echo "Failed to find $CXI_DEVICE"
		exit 1
	fi

	CXI_NIC_ADDR=$(cat $CXI_DEVICE)
	if [ $CXI_NIC_ADDR == "0x0" ]; then
		CXI_NIC_ADDR="192.168.1.1"
		REMOTE_CXI_NIC_ADDR="192.168.1.2"
	else
		CXI_NIC_ADDR="192.168.1.2"
		REMOTE_CXI_NIC_ADDR="192.168.1.1"
	fi

	echo "Local CXI NIC Address $CXI_NIC_ADDR"
	echo "Remote CXI NIC Address $REMOTE_CXI_NIC_ADDR"
}

function parse_args {
	for arg in "$@"; do
		case $arg in
			--server)
				MODE="server"
				;;
			--client)
				MODE="client"
				;;
		esac
	done

	if [ $MODE == "none" ]; then
		help
		exit 1
	fi
}

parse_args $@
load_cxi_prov
configure_eth
enable_debug
get_nic_addr
load_multi_nic_msg
unload_multi_nic_msg
unload_cxi_prov
