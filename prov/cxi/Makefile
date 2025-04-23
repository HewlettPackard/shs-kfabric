obj-m := kfi_cxi.o
kfi_cxi-objs := \
	kcxi_cp.o \
	kcxi_dev.o \
	kcxi_rx_desc.o \
	kcxi_tx_desc.o \
	kcxi_arp_res.o \
	kcxi_addr_res.o \
	kcxi_rx_ctx.o \
	kcxi_tx_ctx.o \
	kcxi_rma_ops.o \
	kcxi_ptlte.o \
	kcxi_send_ops.o \
	kcxi_recv_ops.o \
	kcxi_mr_domain.o \
	kcxi_mr.o \
	kcxi_md.o \
	kcxi_ep_rdm.o \
	kcxi_ep.o \
	kcxi_eq.o \
	kcxi_cmdq.o \
	kcxi_av.o \
	kcxi_domain_if.o \
	kcxi_if.o \
	kcxi_cq.o \
	kcxi_domain.o \
	kcxi_fabric.o \
	kcxi_profile.o \
	kcxi_prov.o
ccflags-y += \
	-I$(src)/../../include \
	-I$(src)/../../../cxi-driver/include \
	-I$(src)/../../../cassini-headers/install/include
