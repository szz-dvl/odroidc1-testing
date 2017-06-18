TARGET = dmatest

KDIR = /home/odroid/kernel/
PWD := $(shell pwd)

obj-m += $(TARGET).o

dmatest-objs := dmatest_dev.o dmatest_ileaved.o dmatest_slave.o dmatest_interrupt.o dmatest_memcpy.o dmatest_memset.o dmatest_sg.o dmatest_cyclic.o

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	\rm -rf *~
