# Common functions to be used for all CXI provider tests.
# Note: sharness framework should be sourced in before this file.

TOP_DIR=$(realpath ../../../../../)
KFAB_DIR=$(realpath ../../../../)
CXI_ETH_INTERFACE=""

cxi_test_setup() {
	test_expect_success "One device is present" "
		[ $(lspci -n | grep -c -e '17db:0501' -e '1590:0371') -eq 1 ]
	"

	dmesg --clear

	test_expect_success "Inserting SBL" "
		insmod ${TOP_DIR}/slingshot_base_link/cxi-sbl.ko
	"

	test_expect_success "Inserting SSLINK" "
		insmod ${TOP_DIR}/sl-driver/knl/cxi-sl.ko
	"

	test_expect_success "Inserting CXI driver" "
		insmod ${TOP_DIR}/cxi-driver/drivers/net/ethernet/hpe/ss1/cxi-ss1.ko disable_default_svc=0
	"

	test_expect_success "Inserting CXI Ethernet" "
		insmod ${TOP_DIR}/cxi-driver/drivers/net/ethernet/hpe/ss1/cxi-eth.ko &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"

	test_expect_success "Inserting CXI user" "
		insmod ${TOP_DIR}/cxi-driver/drivers/net/ethernet/hpe/ss1/cxi-user.ko &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"

	test_expect_success "Inserting kfabric framework" "
		insmod ${KFAB_DIR}/kfi/kfabric.ko &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"

	test_expect_success "Inserting CXI provider" "
		insmod ${KFAB_DIR}/prov/cxi/kfi_cxi.ko skip_device_ready_checks=1 rnr_timeout=1000000000 md_cache_enable=0 &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"

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
	nic_addr="$(cat /sys/class/cxi_user/cxi0/device/properties/nic_addr)"
	octet="$(printf "%02X" $nic_addr)"
	mac_addr="02:00:00:00:00:$octet"

	# Build IP address based on NIC address.
	nic_addr=$(printf "%d" $nic_addr)
	nic_addr=$(($nic_addr+1))
	ip_addr="$(printf "192.168.1.%d/24" $nic_addr)"

	ip link set eth$eth_id address $mac_addr
	ip addr add dev eth$eth_id $ip_addr
	ip link set dev eth$eth_id up

	echo 8 > /proc/sys/kernel/printk
	echo -n 'module cxi_ss1 +p' > /sys/kernel/debug/dynamic_debug/control
	echo -n 'module cxi_eth +p' > /sys/kernel/debug/dynamic_debug/control
	echo -n 'module kfi_cxi +p' > /sys/kernel/debug/dynamic_debug/control

	CXI_ETH_INTERFACE=$(printf "eth%d" $eth_id)
}

cxi_test_finish() {
	test_expect_success "Removing CXI provider" "
		rmmod kfi_cxi &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"

	test_expect_success "Removing kfabric framework" "
		rmmod kfabric &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"

	test_expect_success "Removing CXI user" "
		rmmod cxi-user &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"

	test_expect_success "Removing CXI Ethernet" "
		rmmod cxi-eth &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"

	test_expect_success "Removing CXI driver" "
		rmmod cxi-ss1 &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"

	test_expect_success "Removing SSLINK" "
		rmmod cxi-sl &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"
	ptp_installed=$(lsmod | awk '{ print $1 }' | grep ptp)
	test_expect_success "Removing SBL" "
		rmmod cxi-sbl &&
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"
	ptp_installed=$(lsmod | awk '{ print $1 }' | grep ptp)
	if [ "$ptp_installed" = "ptp" ]; then
		rmmod ptp
	fi

	test_expect_success "No Oops" "
		[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
	"
}
