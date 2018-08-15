#rmmod netfilter_hook
obj-m += netfilter_hook.o
all:
	make -C /usr/src/linux-headers-4.15.0-29-generic SUBDIRS=$(PWD) modules
#sudo insmod ./netfilter_hook.ko
#kernel_ping 8.8.8.8
