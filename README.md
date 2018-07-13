This project has two parts:
 - tcp_bbrx kernel module (implements BBRx)
 - tcp_stats collector (read tcp_stats over netlink socket)

The kernel patches and the module was test on linux-4.15.18.
To test BBRx,
1. Apply the two patches to kernel source
2. Compile and install the kernel
3. Build the tcp_bbrx module:
   cd kernel_module
   make
   sudo insmod tcp_bbrx.ko
4. iperf3 -s
5. iperf3 -c localhost -t 10 -C bbrx

