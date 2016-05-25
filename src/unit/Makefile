MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build

ccflags-y := -I$(src)/.. $(MARKSRCRANGE_FLAGS)
obj-m += msr_unit.o

msr_unit-objs := unit.o ../mod/target.o

all:
	make -C ${KERNEL_DIR} M=$$PWD
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@
test:
	sudo dmesg -C
	sudo insmod msr_unit.ko && sudo rmmod msr_unit
	dmesg -t
