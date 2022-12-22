.PHONY: default install clean static

LIBBPF_INCS=/usr/local/libbpf/usr/include
LIBBPF_LIBS=/usr/local/libbpf/libbpf.a

default: ./libbpf_stun_drop_all_kern.o ./libbpf_stun_drop_all_user.o ./libbpf_stun_drop_all

static:
	$(MAKE) EXTRA_LD_FLAGS="-static"

OS_CODE=$(shell lsb_release -sc)
./vmlinux.h:
	ln -sf ../btf/vmlinux-ubuntu-$(OS_CODE).h vmlinux.h
./vmlinux.btf:
	rm -f *.btf && tar xf ../btf/ubuntu-$(OS_CODE).btf.tar.xz -O > ubuntu-$(OS_CODE).btf && \
		ln -sf ubuntu-$(OS_CODE).btf vmlinux.btf

./libbpf_stun_drop_all_kern.o: ./libbpf_stun_drop_all_kern.c ./vmlinux.h Makefile
	@echo "make -C $(shell pwd)"
	clang-12 -I$(LIBBPF_INCS) -g -O2 -target bpf -c $< -o $@

./libbpf_stun_drop_all_kern.skel.h: ./libbpf_stun_drop_all_kern.o
	@echo "Generate skeleton by $(shell which bpftool)"
	bpftool gen skeleton $< > $@

./libbpf_stun_drop_all_user.o: ./libbpf_stun_drop_all_user.cc ./libbpf_stun_drop_all_kern.skel.h ./vmlinux.btf
	g++ -std=c++11 -g -O0 -I$(LIBBPF_INCS) -c $< -o $@

LD_FLAGS=-lelf -lz $(EXTRA_LD_FLAGS)
./libbpf_stun_drop_all: ./libbpf_stun_drop_all_user.o
	g++ $^ $(LIBBPF_LIBS) $(LD_FLAGS) -o $@

install: ./libbpf_stun_drop_all
	@echo "Install ok"

clean:
	rm -f ./*.o ./*.skel.h ./vmlinux.h ./*.btf ./libbpf_stun_drop_all

