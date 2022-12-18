.PHONY: default install clean

default: ./tc_stun_drop_all_kern.o

./tc_stun_drop_all_kern.o: ./tc_stun_drop_all_kern.c
	@echo "make -C $(shell pwd)"
	clang-12 -I/usr/local/libbpf/usr/include -g -O2 -target bpf -c $< -o $@

install:

clean:
	rm -f ./tc_stun_drop_all_kern.o

