CFLAGS_tcp_delay.o := -DDEBUG
obj-m += tcp_delay.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
