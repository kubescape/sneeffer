FROM golang:1.18 as builder

RUN apt update && apt install git curl cmake make libelf-dev -y
RUN git clone https://github.com/anchore/grype.git /etc/grype_sc
WORKDIR /etc/grype_sc
RUN ./install.sh v0.49.0

RUN git clone https://github.com/anchore/syft.git /etc/syft_sc
WORKDIR /etc/syft_sc
RUN ./install.sh v0.54.0

RUN git clone https://github.com/kubescape/ebpf-engine /etc/kubescape_ebpf_engine_sc
WORKDIR /etc/kubescape_ebpf_engine_sc
RUN ./install_dependencies.sh
RUN mkdir build
WORKDIR /etc/kubescape_ebpf_engine_sc/build
RUN cmake ..
RUN make all

WORKDIR /etc/sneeffer
ADD . .
RUN go build -o kubescape_sneeffer .

FROM falcosecurity/falco-no-driver:0.32.2

RUN apt update
RUN apt-get install -y ca-certificates libelf-dev

RUN mkdir /etc/sneeffer
RUN mkdir /etc/sneeffer/configuration
RUN mkdir /etc/sneeffer/resources
RUN mkdir /etc/sneeffer/data

COPY ./resources/ /etc/sneeffer/resources/
COPY --from=builder /etc/grype_sc/bin/grype /etc/sneeffer/resources/vuln/grype
COPY --from=builder /etc/syft_sc/bin/syft /etc/sneeffer/resources/sbom/syft
COPY --from=builder /etc/kubescape_ebpf_engine_sc/build/main /etc/sneeffer/resources/ebpf/sniffer
COPY --from=builder /etc/sneeffer/kubescape_sneeffer /etc/sneeffer/kubescape_sneeffer

WORKDIR /etc/sneeffer
CMD [ "/etc/sneeffer/resources/entrypoint.sh" ]