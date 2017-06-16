TARGET = dmatest

KDIR = /home/odroid/kernel/
PWD := $(shell pwd)

obj-m += $(TARGET).o

dmatest-objs := dmatest_dev.o dmatest_ileaved.o dmatest_slave.o

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	\rm -rf *~
