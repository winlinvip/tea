# http://releases.ubuntu.com/focal/
FROM ubuntu:focal

# https://serverfault.com/questions/949991/how-to-install-tzdata-on-a-ubuntu-docker-image
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y

########################################################################################################################
# Install tc from iproute2, ifconfig from net-tools, ping from iputils-ping, dig from dnsutils, iperf
RUN apt-get install -y iproute2 net-tools iputils-ping dnsutils iperf

########################################################################################################################
# For eBPF.
RUN apt update -y && apt install -y gdb gcc g++ make autoconf automake libtool pkg-config iputils-ping \
    net-tools curl git tree cmake

# For eBPF toolchain
RUN apt install -y clang-12 libclang-12-dev libelf-dev

# Create workdirectory.
WORKDIR /toolchain
RUN mkdir -p /toolchain && git config --global alias.co checkout && git config --global alias.br branch && \
    git config --global alias.ci commit && git config --global alias.st status && \
    git config --global alias.sm submodule && git config --global alias.sw switch && \
    git config --global alias.cp cherry-pick

# Download libbpf and bpftool
RUN git clone -b v1.0.1 https://github.com/libbpf/libbpf.git
RUN git clone -b v7.0.0 https://github.com/libbpf/bpftool.git

# Build and install toolchain
RUN cd /toolchain/libbpf && mkdir -p /usr/local/libbpf && make -j8 -C /toolchain/libbpf/src OBJDIR=/usr/local/libbpf \
    DESTDIR=/usr/local/libbpf BUILD_STATIC_ONLY=y install install_uapi_headers
RUN cd /toolchain/bpftool && mkdir -p /usr/local/bpftool && make -j8 -C /toolchain/bpftool/src \
    OUTPUT=/usr/local/bpftool/ BPF_DIR=/toolchain/libbpf/src
ENV PATH=$PATH:/usr/local/bpftool

# Install bpftrace tool
RUN apt install -y strace bpftrace

########################################################################################################################
# For Go
#ENV PATH=$PATH:/usr/local/go/bin
#RUN curl -SL https://go.dev/dl/go1.18.7.linux-amd64.tar.gz | tar -xzC /usr/local

########################################################################################################################
RUN mkdir -p /git
WORKDIR /git

CMD ["which", "bpftool"]


