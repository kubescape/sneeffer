# Sneeffer

The goal of Sneeffer is to find relevant CVEs by monitoring its runtime container and find the relevant files that the container is opening, and adjust the opened files of the container to the container's existing files.

Sneeffer is using [Falco](https://falco.org/) libraries for monitoring any container which runs in the K8s cluster by injecting to the kernel eBPF code which monitors relevant Linux system calls.
The ebpf-engine that Sneeffer is using can be found in following link: https://github.com/kubescape/ebpf-engine

## Prerequisites

Follow the steps below for every cluster node:

1. Confirm that your Node is running Linux kernel version >= 4.14
2. Install the relevant Linux headers for the Falco engine. Instructions for the supported distributions can be found in the [following link](https://falco.org/docs/getting-started/installation/)

> Note: In case of K8s DaemonSet deployment, all cluster nodes must be installed with the relevant Linux headers. In case of minikube deployment the Linux headers must be installed in the minikube container.

## Configuration file

| Configuration Key | Description                 |
|-------------------|-----------------------------|
|`innerDataDirPath` | Save sbom and vuln data     |
|`kernelObjPath`    | Kernel object path <br>(it is compiled per node by init container)|
|`snifferEngineLoaderPath`| Path of binary loader of the kernel object to the container|
|`sbomCreatorPath`  | Path of binary which creates the SBOM (list of files existing in the image)|
|`vulnCreatorPath`  | Path of binary which downloads the CVEs in the image|
|`snifferTime`      | Monitoring time of the created container (seconds)|
|`loggerVerbose`    | Log verbose|
|`crdFullDetailedPath`| CRD yaml file path of the detailed runtime CVE data|
|`crdVulnSummaryPath` | CRD yaml file path of the summary runtime CVE data|
|`myNode`           | Name of the node that would be monitored|


### Example

```
innerDataDirPath=./data
kernelObjPath=./resources/ebpf/kernel_obj.o
snifferEngineLoaderPath=./resources/ebpf/sniffer
sbomCreatorPath=./resources/sbom/syft
vulnCreatorPath=./resources/vuln/grype
snifferTime=1 
loggerVerbose=INFO
crdFullDetailedPath=./resources/k8s/crd-vuln-full-detailes.yaml
crdVulnSummaryPath=./resources/k8s/crd-vuln-summary.yaml
myNode=minikube
```

## Installation

### K8s DaemonSet

Sneeffer can be installed as a K8s DaemonSet using the pre-built image, by running the following command on your K8s cluster:
```
kubectl apply -f ./kubescape_sneeffer_Daemonset.yaml
```
This will create a DaemonSet in the default namespace.

---

### Building from source and running locally (minikube)

Follow the steps below to build Sneeffer from source and install it on your local minikube cluster. 

[Minikube must be installed](https://minikube.sigs.k8s.io/docs/start/) on your machine as a prerequisite.

1. Compile relevant binaries by running the following script:

```sh
./install_dependencies.sh
```

<i>This step can take ~15 minutes depending on your machine.</i>

2. Build Sneeffer

```
go build -o kubescape_sneeffer .
```

3. Run minikube:

```
minikube start
```

4. Run Sneeffer:

```
sudo SNEEFFER_CONF_FILE_PATH=./configuration/SneefferConfigurationFile.txt HOME=<your home directory> ./kubescape_sneeffer
```

> By default, when running Sneeffer locally (in a minikube setup), no change is needed to the configuration file. Make sure that `myNode` key in the configuration file matches to the machine running minikube (default value is `minikube`). In case your node name is different, update the configuration file located in `./configuration/SneefferConfigurationFile.txt`.
