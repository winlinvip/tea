.PHONY: default install clean

default: ./stun_drop_all_kern.o

./stun_drop_all_kern.o: ./stun_drop_all_kern.c
	@echo "make -C $(shell pwd)"
	clang-12 -I/usr/local/libbpf/usr/include -g -O2 -target bpf -c $< -o $@

install:

clean:
	rm -f ./stun_drop_all_kern.o

