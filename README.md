# TEA

TEA(TC eBPF for AV) is a network emulator and a set of tools for SRS and any media systems.

## Usage

We use docker to build and run codes:

```bash
docker run --privileged --rm -it ossrs/tea tc qdisc ls
```

> Note: Please specify `--privileged` for tc and eBPF.

For example, build stun-drop-all:

```bash
mkdir -p ~/git && cd ~/git
git clone https://github.com/ossrs/tea.git
docker run --rm -it -v $(pwd):/git -w /git/tea/stun-drop-all ossrs/tea:latest make
```

Or start a docker in background:

```bash
mkdir -p ~/git && cd ~/git
docker run --privileged -d --name tea -it -v $(pwd):/git -w /git/tea ossrs/tea:latest bash
docker exec -it -w /git/tea/stun-drop-all tea make
```

Please follow bellow examples and tools.

## STUN Drop All

Drop all STUN packets, including binding request and response packets.

First, start a docker in background:

```bash
mkdir -p ~/git && cd ~/git
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
docker exec -it -w /git/tea/stun-drop-all tea bash -c \
    "echo -en \$(cat binding_request.txt |tr -d [:space:]) |nc -p 55293 -w 1 -u 127.0.0.1 8000"

# Send STUN binding response.
docker exec -it -w /git/tea/stun-drop-all tea bash -c \
    "echo -en \$(cat binding_response.txt |tr -d [:space:]) |nc -p 55295 -w 1 -u 127.0.0.1 8000"
```

> Note: You will see the packets printed by tcpdump and nc server, before installing the eBPF TC qdisc.

Next, build the eBPF program:

```bash
docker exec -it -w /git/tea/stun-drop-all tea make 
```

And attach eBPF bytecode to TC by:

```bash
docker exec -it -w /git/tea/stun-drop-all tea tc qdisc add dev lo clsact &&
docker exec -it -w /git/tea/stun-drop-all tea tc filter add dev lo egress bpf obj \
    stun_drop_all_kern.o sec cls da &&
docker exec -it -w /git/tea/stun-drop-all tea tc filter add dev lo ingress bpf obj \
    stun_drop_all_kern.o sec cls da
```

Now, nc server won't receive STUN packets, and we can check by:

```bash
docker exec -it -w /git/tea/stun-drop-all tea \
    bpftool map dump pinned /sys/fs/bpf/tc/globals/stun_drop_all
```

* `key: 0d 00 00 00  value: 03 00 00 00` There were `03` STUN packets dropped.

You can also check the last address by:

```bash
docker exec -it -w /git/tea/stun-drop-all tea \
    bpftool map dump pinned /sys/fs/bpf/tc/globals/stun_drop_all_ports
```

* `key: 0d 00 00 00  value: fd d7 40 1f` The port is `0x1f40` (8000) and `0xd7fd` (55293).

You can check the first 8 bytes of last packet payload by:

```bash
docker exec -it -w /git/tea/stun-drop-all tea \
    bpftool map dump pinned /sys/fs/bpf/tc/globals/stun_drop_all_bytes
```

* `key: 0d 00 00 00  value: 00 01 00 50 21 12 a4 42` Which is a binding request.

> Note: Please check by `tree /sys/fs/bpf` for all available maps.

Reset the TC by removing the qdisc:

```bash
docker exec -it -w /git/tea/stun-drop-all tea tc qdisc del dev lo clsact
```

> Note: You can remove the filter if want to keep the qdisc by `tc filter del dev lo egress` and `tc filter del dev lo ingress`

## For SRS

Map ports for SRS:

```bash
mkdir -p ~/git && cd ~/git
docker run -d --privileged --name tea -it -v $(pwd):/git -w /git/tea \
    --env CANDIDATE="192.168.3.85" -p 1935:1935 -p 1985:1985 -p 8080:8080 -p 8000:8000/udp \
    ossrs/tea:latest bash
```

> Note: Please see [Getting Started](https://ossrs.io/lts/en-us/docs/v5/doc/getting-started) for detail.

To attach to `eth0` for SRS:

```bash
docker exec -it -w /git/tea/stun-drop-all tea tc qdisc add dev eth0 clsact &&
docker exec -it -w /git/tea/stun-drop-all tea tc filter add dev eth0 egress bpf obj \
    stun_drop_all_kern.o sec cls da &&
docker exec -it -w /git/tea/stun-drop-all tea tc filter add dev eth0 ingress bpf obj \
    stun_drop_all_kern.o sec cls da
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
docker exec -it -w /git/tea/stun-drop-all tea tc qdisc del dev eth0 clsact
```

> Note: The player should recover if SRS session is not timeout.

## Packet Hex Escaped String

Capture the packet by wireshark or tcpdump, then open by Wireshark, select the packet, right click and choose
`Copy > ...as Escaped String`.

![EscapedString](https://user-images.githubusercontent.com/2777660/206857902-85a9a6f3-44f8-48b1-be61-ffecaf794202.jpeg)

Please see example at `stun-drop-all/binding_request.txt` which is copied from `files/h5-play-stun.pcapng`.

## About vmlinux.h

Generate the `vmlinux.h` if you want:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

> Note: There might be no BTF in docker, so you can run in an ubuntu server.

> Note: For more information about `vmlinux.h`, please read 
> [BTFGen: One Step Closer to Truly Portable eBPF Programs](https://www.inspektor-gadget.io//blog/2022/03/btfgen-one-step-closer-to-truly-portable-ebpf-programs/), 
> [BTFHub](https://github.com/aquasecurity/btfhub) and [Running non CO-RE Tracee](https://aquasecurity.github.io/tracee/v0.6.5/building/nocore-ebpf/) 

Winlin 2022.12


