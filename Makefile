obj-m += drv.o

KDIR := /lib/modules/$(shell uname -r)/build

CC=gcc
ccflags-y += "-g"
ccflags-y += "-O0"

all:
	make -C $(KDIR) M=$(PWD) modules
	# compile the trigger
	$(CC) rop_exploit.c -static -o rop_exploit

install: all
	sudo rmmod drv; sudo insmod drv.ko

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -fr ./trigger

