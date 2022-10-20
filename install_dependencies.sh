#!/bin/bash

sudo apt install git curl clang-12 -y

mkdir dependencies
git clone https://github.com/anchore/grype.git dependencies/grype_sc
cd dependencies/grype_sc
./install.sh v0.49.0
cd -
cp ./dependencies/grype_sc/bin/grype ./resources/vuln/grype

git clone https://github.com/anchore/syft.git dependencies/syft_sc
cd dependencies/syft_sc
./install.sh v0.54.0
cd -
cp ./dependencies/syft_sc/bin/syft ./resources/sbom/syft

git clone git@github.com:rcohencyberarmor/kubescape-ebpf-engine.git dependencies/kubescape_ebpf_engine_sc
cd dependencies/kubescape_ebpf_engine_sc
./install_dependencies.sh
mkdir build && cd ./build
cmake ..
make all
cd ../../../
cp dependencies/kubescape_ebpf_engine_sc/dependencies/falco-libs/build/driver/bpf/probe.o ./resources/ebpf/kernel_obj.o
cp dependencies/kubescape_ebpf_engine_sc/build/main ./resources/ebpf/sniffer
