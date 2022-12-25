#!/bin/bash
set -x

apt install linux-headers-$(uname -r) -y
mkdir /etc/falco-libs/build && cd /etc/falco-libs/build
cmake -DBUILD_BPF=true -DINSTALL_GTEST=OFF ../
make bpf 
cp /etc/falco-libs/build/driver/bpf/probe.o /root/.falco/falco-bpf.o