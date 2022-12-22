# TEA

TEA(TC eBPF for AV) is a network emulator and a set of tools for SRS and any media systems.

## Usage

We use docker to build and run codes:

```bash
docker run --privileged --rm -it ossrs/tea tc qdisc ls
```

> Note: Please specify `--privileged` for tc and eBPF.

For example, build tc_stun_drop_all:

```bash
mkdir -p ~/git && cd ~/git &&
git clone https://github.com/ossrs/tea.git &&
docker run --rm -it -v $(pwd):/git -w /git/tea/tc_stun_drop_all ossrs/tea:latest make
```

Or start a docker in background:

```bash
mkdir -p ~/git && cd ~/git &&
docker run --privileged -d --name tea -it -v $(pwd):/git -w /git/tea ossrs/tea:latest bash &&
docker exec -it -w /git/tea/libbpf_stun_drop_all tea make 
```

Please follow bellow examples and tools.

## LIBBPF: STUN Drop All

Using libbpf to load the eBPF object to TC as clsact.

First, start a docker in background:

```bash
mkdir -p ~/git && cd ~/git &&
docker run -d --privileged --name tea -it -v $(pwd):/git -w /git/tea \
    ossrs/tea:latest bash
```

Then, start tcpdump to show packets, and using nc to send packets:

```bash
# Capture all UDP packets.
docker exec -it tea tcpdump udp -i any -X

# Start a UDP server, listen at 8000
docker exec -it tea nc -l -u 8000

# Send STUN binding request.
docker exec -it -w /git/tea/libbpf_stun_drop_all tea bash -c \
    "echo -en \$(cat binding_request.txt |tr -d [:space:]) |nc -p 55293 -w 1 -u 127.0.0.1 8000"

# Send STUN binding response.
docker exec -it -w /git/tea/libbpf_stun_drop_all tea bash -c \
    "echo -en \$(cat binding_response.txt |tr -d [:space:]) |nc -p 55295 -w 1 -u 127.0.0.1 8000"
```

> Note: You will see the packets printed by tcpdump and nc server, before installing the eBPF TC qdisc.

Next, build the eBPF program:

```bash
docker exec -it -w /git/tea/libbpf_stun_drop_all tea make 
```

And attach eBPF bytecode to TC by:

```bash
docker exec -it -w /git/tea/libbpf_stun_drop_all tea ./libbpf_stun_drop_all 
```

All STUN packets are dropped:

```text
Dropping all STUN packets...
              nc-12768   [004] d....  7280.186241: bpf_trace_printk: Drop STUN packet, type=0x100, len=20480, magic=0x42a41221
```

For detail about TC and eBPF, please read [Links: TC](#links-tc) and [Links: LIBBPF](#links-libbpf) section.

## LIBBPF: STUN NETEM

Using libbpf and TC netem for STUN packets only.

First, start a docker in background:

```bash
mkdir -p ~/git && cd ~/git &&
docker run -d --privileged --name tea -it -v $(pwd):/git -w /git/tea \
    ossrs/tea:latest bash
```

Then, start tcpdump to show packets, and using nc to send packets:

```bash
# Capture all UDP packets.
docker exec -it tea tcpdump udp -i any -X

# Start a UDP server, listen at 8000
docker exec -it tea nc -l -u 8000

# Send STUN binding request.
docker exec -it -w /git/tea/libbpf_stun_netem tea bash -c \
    "echo -en \$(cat binding_request.txt |tr -d [:space:]) |nc -p 55293 -w 1 -u 127.0.0.1 8000"

# Send STUN binding response.
docker exec -it -w /git/tea/libbpf_stun_netem tea bash -c \
    "echo -en \$(cat binding_response.txt |tr -d [:space:]) |nc -p 55295 -w 1 -u 127.0.0.1 8000"
```

> Note: You will see the packets printed by tcpdump and nc server, before installing the eBPF TC qdisc.

Next, build the eBPF program:

```bash
docker exec -it -w /git/tea/libbpf_stun_netem tea make 
```

Add 3s delay for STUN packet:

```bash
docker exec -it -w /git/tea/libbpf_stun_netem tea \
    tc qdisc add dev lo root handle 1:0 prio &&
docker exec -it -w /git/tea/libbpf_stun_netem tea \
    tc qdisc add dev lo parent 1:3 handle 3:0 netem delay 3000ms &&
docker exec -it -w /git/tea/libbpf_stun_netem tea \
    tc filter add dev lo parent 1:0 bpf obj tc_index_to_classid_kern.o sec cls da &&
echo "OK"
```

> Note: We add a prio qdisc at `1:0`, which default to deliver packets by `1:1` and `1:2`. And we also create a netem 
> qdisc `3:0` at `1:3` which set delay to 3s. So we will use `libbpf_stun_netem` to deliver all STUN packets to netem 
> which is classid `1:3`.

> Note: Please note that `libbpf_stun_netem` is a clsact, which change the `skb->tc_classid` to `3` which is `1:3`, but
> we need another bpf filter `tc_index_to_classid_kern.o` which apply to netem.

And attach eBPF bytecode to TC by:

```bash
docker exec -it -w /git/tea/libbpf_stun_netem tea ./libbpf_stun_netem 
```

If send STUN messages, you'll find the packet is arrived after 3s：

```bash
Apply netem to all STUN packets...
              nc-2752    [000] d....  1206.400129: bpf_trace_printk: Apply netem to STUN packet, type=0x100, len=20480, classid=3
```

You can also check by:

```bash
docker exec -it -w /git/tea/libbpf_stun_netem tea tc -s class ls dev lo
#class prio 1:3 parent 1: leaf 3: 
# Sent 142 bytes 1 pkt (dropped 0, overlimits 0 requeues 0) 
# backlog 0b 0p requeues 0

docker exec -it -w /git/tea/libbpf_stun_netem tea tc -s qdisc ls dev lo
#qdisc netem 3: parent 1:3 limit 1000 delay 3.0s
# Sent 142 bytes 1 pkt (dropped 0, overlimits 0 requeues 0) 
# backlog 0b 0p requeues 0
```

You can also add loss and other features from [netem](https://wiki.linuxfoundation.org/networking/netem).

## TC: STUN Drop All

Using tc to load the eBPF object, drop all STUN packets, including binding request and response packets.

First, start a docker in background:

```bash
mkdir -p ~/git && cd ~/git &&
docker run -d --privileged --name tea -it -v $(pwd):/git -w /git/tea \
    ossrs/tea:latest bash
```

Then, start tcpdump to show packets, and using nc to send packets:

```bash
# Capture all UDP packets.
docker exec -it tea tcpdump udp -i any -X

# Start a UDP server, listen at 8000
docker exec -it tea nc -l -u 8000

# Send STUN binding request.
docker exec -it -w /git/tea/tc_stun_drop_all tea bash -c \
    "echo -en \$(cat binding_request.txt |tr -d [:space:]) |nc -p 55293 -w 1 -u 127.0.0.1 8000"

# Send STUN binding response.
docker exec -it -w /git/tea/tc_stun_drop_all tea bash -c \
    "echo -en \$(cat binding_response.txt |tr -d [:space:]) |nc -p 55295 -w 1 -u 127.0.0.1 8000"
```

> Note: You will see the packets printed by tcpdump and nc server, before installing the eBPF TC qdisc.

Next, build the eBPF program:

```bash
docker exec -it -w /git/tea/tc_stun_drop_all tea make 
```

And attach eBPF bytecode to TC by:

```bash
docker exec -it tea tc qdisc add dev lo clsact &&
docker exec -it -w /git/tea/tc_stun_drop_all tea tc filter add dev lo egress bpf obj \
    tc_stun_drop_all_kern.o sec cls da &&
docker exec -it -w /git/tea/tc_stun_drop_all tea tc filter add dev lo ingress bpf obj \
    tc_stun_drop_all_kern.o sec cls da &&
echo "OK"
```

Now, nc server won't receive STUN packets, and we can check by:

```bash
docker exec -it tea \
    bpftool map dump pinned /sys/fs/bpf/tc/globals/tc_stun_drop_all
```

* `key: 0d 00 00 00  value: 03 00 00 00` There were `03` STUN packets dropped.

You can also check the last address by:

```bash
docker exec -it tea \
    bpftool map dump pinned /sys/fs/bpf/tc/globals/tc_stun_drop_all_ports
```

* `key: 0d 00 00 00  value: fd d7 40 1f` The port is `0x1f40` (8000) and `0xd7fd` (55293).

You can check the first 8 bytes of last packet payload by:

```bash
docker exec -it tea \
    bpftool map dump pinned /sys/fs/bpf/tc/globals/tc_stun_drop_all_bytes
```

* `key: 0d 00 00 00  value: 00 01 00 50 21 12 a4 42` Which is a binding request.

Because `btf_printk` is not available for TC loader, so we use map to show debugging information, and all maps are 
pinned to global namespace, please check by:

```bash
docker exec -it tea tree /sys/fs/bpf
# /sys/fs/bpf
# |-- ip -> /sys/fs/bpf/tc/
# |-- tc
# |   `-- globals
# |       |-- tc_stun_drop_all
# |       |-- tc_stun_drop_all_bytes
# |       `-- tc_stun_drop_all_ports
# `-- xdp -> /sys/fs/bpf/tc/
```

Reset the TC by removing the qdisc:

```bash
docker exec -it tea tc qdisc del dev lo clsact
```

Or by remove the filters:

```bash
docker exec -it tea tc filter del dev lo egress
docker exec -it tea tc filter del dev lo ingress
```

For detail about TC and eBPF, please read [Links: TC](#links-tc) section.

## For SRS

Map ports for SRS:

```bash
mkdir -p ~/git && cd ~/git &&
docker run -d --privileged --name tea -it -v $(pwd):/git -w /git/tea \
    --env CANDIDATE="192.168.3.85" -p 1935:1935 -p 1985:1985 -p 8080:8080 -p 8000:8000/udp \
    ossrs/tea:latest bash
```

> Note: Please see [Getting Started](https://ossrs.io/lts/en-us/docs/v5/doc/getting-started) for detail.

To attach to `eth0` for SRS:

```bash
docker exec -it -w /git/tea/tc_stun_drop_all tea tc qdisc add dev eth0 clsact &&
docker exec -it -w /git/tea/tc_stun_drop_all tea tc filter add dev eth0 egress bpf obj \
    tc_stun_drop_all_kern.o sec cls da &&
docker exec -it -w /git/tea/tc_stun_drop_all tea tc filter add dev eth0 ingress bpf obj \
    tc_stun_drop_all_kern.o sec cls da &&
echo "OK"
```

If start a SRS or WebRTC server, all WebRTC clients will fail because STUN is disabled.

```bash
docker exec -it -w /git/srs/trunk tea ./objs/srs -c conf/console.conf
```

Publish a RTMP stream to SRS:

```bash
docker run --rm -it ossrs/srs:encoder ffmpeg -stream_loop -1 -re -i doc/source.flv \
  -c copy -f flv rtmp://host.docker.internal/live/livestream
```

The [WebRTC player](http://localhost:8080/players/rtc_player.html?autostart=true) will be fail.

Reset the TC by removing qdisc:

```bash
docker exec -it -w /git/tea/tc_stun_drop_all tea tc qdisc del dev eth0 clsact
```

> Note: The player should recover if SRS session is not timeout.

## Packet Hex Escaped String

Capture the packet by wireshark or tcpdump, then open by Wireshark, select the packet, right click and choose
`Copy > ...as Escaped String`.

![EscapedString](https://user-images.githubusercontent.com/2777660/206857902-85a9a6f3-44f8-48b1-be61-ffecaf794202.jpeg)

Please see example at `tc_stun_drop_all/binding_request.txt` which is copied from `files/h5-play-stun.pcapng`.

## About vmlinux.h

Generate the `vmlinux.h` if you want:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux-ubuntu-focal-5.15.0-52-generic.h
```

> Note: There might be no BTF in docker, so you can run in an ubuntu server.

> Note: For more information about `vmlinux.h`, please read 
> [BTFGen: One Step Closer to Truly Portable eBPF Programs](https://www.inspektor-gadget.io//blog/2022/03/btfgen-one-step-closer-to-truly-portable-ebpf-programs/), 
> [BTFHub](https://github.com/aquasecurity/btfhub) and [Running non CO-RE Tracee](https://aquasecurity.github.io/tracee/v0.6.5/building/nocore-ebpf/)

## About BTF

There are some BTF for old kernel or docker:

* For Ubuntu 18: [5.4.0-84-generic.btf.tar.xz](https://github.com/aquasecurity/btfhub-archive/blob/main/ubuntu/18.04/x86_64/5.4.0-84-generic.btf.tar.xz)
* For Ubuntu 20: [5.8.0-23-generic.btf.tar.xz](https://github.com/aquasecurity/btfhub-archive/blob/main/ubuntu/20.04/x86_64/5.8.0-63-generic.btf.tar.xz)

Or generate from latest ubuntu server which has `/sys/kernel/btf/vmlinux`:

```bash
# For example, uname -r is 5.15.0-52-generic
cp /sys/kernel/btf/vmlinux vmlinux-ubuntu-focal-$(uname -r).btf && 
tar Jcf vmlinux-ubuntu-focal-$(uname -r).btf.tar.xz vmlinux-ubuntu-focal-$(uname -r).btf
```

Now, we can generate the `vmlinux.h`, for example:

```bash
tar xf 5.4.0-84-generic.btf.tar.xz &&
bpftool btf dump file 5.4.0-84-generic.btf format c > vmlinux-ubuntu-bionic-5.4.0-84-generic.h
```

BTF is required for eBPF CO-RE, to compatible with different kernel versions without rebuild it.

> Note: For more information about `BTF` and `CO-RE`, please read
> [BTFGen: One Step Closer to Truly Portable eBPF Programs](https://www.inspektor-gadget.io//blog/2022/03/btfgen-one-step-closer-to-truly-portable-ebpf-programs/),
> [BTFHub](https://github.com/aquasecurity/btfhub) and [Running non CO-RE Tracee](https://aquasecurity.github.io/tracee/v0.6.5/building/nocore-ebpf/)

## Ubuntu 18 (bionic)

To run eBPF on Ubuntu 18 bionic, should statically build and link in Ubuntu 20 focal, for example, 
[STUN NETEM](#libbpf-stun-netem):

```bash
docker exec -it -w /git/tea/libbpf_stun_netem tea make clean static
```

Now, we start a Ubuntu 18 bionic container, or run in VM server:

```bash
mkdir -p ~/git && cd ~/git &&
cd ~/git/tea && docker build -t tea:bionic -f Dockerfile.ubuntu18.bionic . &&
cd ~/git && docker run -d --privileged --name bionic -it -v $(pwd):/git -w /git/tea \
    tea:bionic bash
```

Then, create a BTF file for Ubuntu 18 bionic:

```bash
mkdir ~/git/tea/tmp &&
docker exec -it -w /git/tea/tmp bionic make -f ../libbpf_stun_netem/Makefile vmlinux
```

Add 3s delay for STUN packet:

```bash
docker exec -it -w /git/tea/libbpf_stun_netem bionic \
    tc qdisc add dev lo root handle 1:0 prio &&
docker exec -it -w /git/tea/libbpf_stun_netem bionic \
    tc qdisc add dev lo parent 1:3 handle 3:0 netem delay 3000ms &&
docker exec -it -w /git/tea/libbpf_stun_netem bionic \
    tc filter add dev lo parent 1:0 bpf obj tc_index_to_classid_kern.o sec cls da && 
echo "OK"
```

And attach eBPF bytecode to TC by:

```bash
docker exec -it -w /git/tea/tmp bionic ../libbpf_stun_netem/libbpf_stun_netem
```

Then, start tcpdump to show packets, and using nc to send packets:

```bash
# Start a UDP server, listen at 8000
docker exec -it bionic nc -l -u -p 8000

# Send STUN binding request.
docker exec -it -w /git/tea/libbpf_stun_netem bionic bash -c \
    "echo -en \$(cat binding_request.txt |tr -d [:space:]) |nc -p 55293 -w 1 -u 127.0.0.1 8000"
```

All STUN packets is delayed.

## Links: TC

* [Traffic Control HOWTO](https://tldp.org/HOWTO/Traffic-Control-HOWTO/) Martin A. Brown 2006.
* [Linux Advanced Routing & Traffic Control HOWTO](https://lartc.org/howto/index.html) Bert Hubert 2012.
* [netem: Network Emulation](https://wiki.linuxfoundation.org/networking/netem) Linux iproute2.
* [[译] Facebook 流量路由最佳实践：从公网入口到内网业务的全路径 XDP/BPF 基础设施（LPC, 2021）](https://arthurchiao.art/blog/facebook-from-xdp-to-socket-zh/) Arthur Chiao 2020
* [[译] 深入理解 tc ebpf 的 direct-action (da) 模式（2020）](https://arthurchiao.art/blog/understanding-tc-da-mode-zh/) Arthur Chiao 2021
* [[译] 流量控制（TC）五十年：从基于缓冲队列（Queue）到基于时间（EDT）的演进（Google, 2018）](http://arthurchiao.art/blog/traffic-control-from-queue-to-edt-zh/) Arthur Chiao 2022

## Links: LIBBPF

* [libbpf, contains an eBPF loader which takes over processing LLVM generated eBPF ELF files for loading into the kernel.](https://github.com/libbpf/libbpf)
* [bpftool, allows inspection and simple manipulation of eBPF programs and maps.](https://github.com/libbpf/bpftool)
* [Features of bpftool: the thread of tips and examples to work with eBPF objects](https://qmonnet.github.io/whirl-offload/2021/09/23/bpftool-features-thread/) Quentin Monnet 2021
* [BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html) Andrii Nakryiko 2020
* [BTFGen: One Step Closer to Truly Portable eBPF Programs](https://www.inspektor-gadget.io//blog/2022/03/btfgen-one-step-closer-to-truly-portable-ebpf-programs/) Mauricio Vásquez Bernal 2022
* [BTFHub, provides BTF files for existing published kernels that don't support embedded BTF.](https://github.com/aquasecurity/btfhub)
* [[译] BPF 可移植性和 CO-RE（一次编译，到处运行）（Facebook，2020）](https://arthurchiao.art/blog/bpf-portability-and-co-re-zh/#32-btfbpf-type-format) Arthur Chiao 2021

Winlin 2022.12


