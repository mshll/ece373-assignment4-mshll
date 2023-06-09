obj-m += hw4.o
KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(shell pwd) modules

cdev_test: cdev_test.c
	gcc -o cdev_test cdev_test.c

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(shell pwd) clean
	rm -f cdev_test