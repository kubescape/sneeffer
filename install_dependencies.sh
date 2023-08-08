#!/bin/bash

sudo apt install git curl clang-12 -y

mkdir -p dependencies
if [[ ! -d dependencies/grype_sc ]]; then
  git clone https://github.com/anchore/grype.git dependencies/grype_sc
fi
cd dependencies/grype_sc
./install.sh v0.49.0
cd -
cp ./dependencies/grype_sc/bin/grype ./resources/vuln/grype

if [[ ! -d dependencies/syft_sc ]]; then
  git clone https://github.com/anchore/syft.git dependencies/syft_sc
fi
cd dependencies/syft_sc
./install.sh v0.54.0
cd -
cp ./dependencies/syft_sc/bin/syft ./resources/sbom/syft

if [[ ! -d dependencies/kubescape_ebpf_engine_sc ]]; then
  git clone https://github.com/rcohencyberarmor/kubescape-ebpf-engine.git dependencies/kubescape_ebpf_engine_sc
fi
cd dependencies/kubescape_ebpf_engine_sc
./install_dependencies.sh
mkdir -p build && cd ./build
cmake ..
make all
cd ../../../
mkdir -p resources/epbf
cp dependencies/kubescape_ebpf_engine_sc/dependencies/falco-libs/build/driver/bpf/probe.o ./resources/ebpf/kernel_obj.o
cp dependencies/kubescape_ebpf_engine_sc/build/main ./resources/ebpf/sniffer
