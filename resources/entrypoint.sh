#!/bin/bash

cp /root/.falco/falco-bpf.o /etc/sneeffer/resources/ebpf/kernel_obj.o
/etc/sneeffer/kubescape_sneeffer  