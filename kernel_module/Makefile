#make file 

obj-m := tcp_bbrx.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd) 
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules 

clean:
	$(RM) -f *.ko *.o 
