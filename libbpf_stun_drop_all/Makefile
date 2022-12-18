.PHONY: default install clean

LIBBPF_INCS=/usr/local/libbpf/usr/include
LIBBPF_LIBS=/usr/local/libbpf/libbpf.a

default: ./libbpf_stun_drop_all_kern.o ./libbpf_stun_drop_all_user.o ./libbpf_stun_drop_all

./libbpf_stun_drop_all_kern.o: ./libbpf_stun_drop_all_kern.c Makefile
	@echo "make -C $(shell pwd)"
	clang-12 -I$(LIBBPF_INCS) -g -O2 -target bpf -c $< -o $@

./libbpf_stun_drop_all_kern.skel.h: ./libbpf_stun_drop_all_kern.o
	@echo "Generate skeleton by $(shell which bpftool)"
	bpftool gen skeleton $< > $@

./vmlinux.btf:
	tar xf ../btf/5.15.0-52-generic.btf.tar.xz && rm -f vmlinux.btf && ln -sf 5.15.0-52-generic.btf vmlinux.btf

./libbpf_stun_drop_all_user.o: ./libbpf_stun_drop_all_user.cc ./libbpf_stun_drop_all_kern.skel.h ./vmlinux.btf
	g++ -std=c++11 -g -O0 -I$(LIBBPF_INCS) -c $< -o $@

./libbpf_stun_drop_all: ./libbpf_stun_drop_all_user.o
	g++ $^ $(LIBBPF_LIBS) -lelf -lz -o $@

install: ./libbpf_stun_drop_all
	@echo "Install ok"

clean:
	rm -f ./*.o ./*.skel.h ./*.btf ./libbpf_stun_drop_all

