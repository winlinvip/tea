.PHONY: default install clean

default: ./tc_stun_drop_all_kern.o

OS_CODE=$(shell lsb_release -sc)
./vmlinux.h:
	ln -sf vmlinux-ubuntu-$(OS_CODE).h vmlinux.h

./tc_stun_drop_all_kern.o: ./tc_stun_drop_all_kern.c ./vmlinux.h
	@echo "make -C $(shell pwd)"
	clang-12 -I/usr/local/libbpf/usr/include -g -O2 -target bpf -c $< -o $@

install:

clean:
	rm -f ./*.o ./vmlinux.h

