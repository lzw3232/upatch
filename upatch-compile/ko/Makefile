# SPDX-License-Identifier: GPL-2.0
kernel ?= /lib/modules/$(shell uname -r)/build

ccflags-y += -I$(PWD)/../common

obj-m += upatch_hijacker.o
upatch_hijacker-objs := hijacker.o entry.o

all:
	make -C $(kernel) M=$(shell pwd) modules

clean:
	make -C $(kernel) M=$(shell pwd) clean