TARGET = cryptotest

KDIR = /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m += $(TARGET).o

cryptotest-objs := cryptotest_dev.o cryptotest_aes.o cryptotest_tdes.o cryptotest_crc.o cryptotest_divx.o

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(RM) -rf *~
