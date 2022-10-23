FROM golang:1.18 as builder

RUN apt install git curl -y
RUN git clone https://github.com/anchore/grype.git /etc/grype_sc
WORKDIR /etc/grype_sc
RUN git checkout v0.49.0
RUN ./install.sh

RUN git clone https://github.com/anchore/syft.git /etc/syft_sc
WORKDIR /etc/syft_sc
RUN git checkout v0.54.0
RUN ./install.sh

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

COPY --from=builder /etc/sneeffer/kubescape_sneeffer /etc/sneeffer/kubescape_sneeffer
WORKDIR /etc/sneeffer
CMD [ "/etc/sneeffer/resources/entrypoint.sh" ]