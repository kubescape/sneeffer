# kubescape-sneeffer

## introduction
    the sneeffer goal is to find relavent CVEs by monitoring it's runtime container and found the relavent files that the container is openning, and adjust the opened files of the 
    container to the container existing files. 
    the sneeffer is using falco libraies for monitoring any container that start in the k8s cluster by inject to the kernel ebpf code that monitor relavent linux syscalls. 
    the ebpf-engine that the sneeffer is using can be find in following link: https://github.com/kubescape/ebpf-engine

## prerequisites
    1. install the linux-headers for any distribution for the falco engine, can be find in the following link: https://falco.org/docs/getting-started/installation/
       in case of k8s daemonset instalation it need to be installed in the all the cluster nodes
       ** in case of minikube the linux headers must be installed in the minikube container

## installing and running steps to run as k8s daemonset
    1. kubectl apply -f ./kubescape_sneeffer_Daemonset.yaml

### for developers
#### installing steps to run locally
    1. run the script ./install_dependencies.sh in order to compile relavent binaries - this step is quiet long (15 minutes more or less)
    2. go build -o kubescape_sneeffer .

#### running command and preparations
##### preparations
    1. run minikube with the command: minikube start. minikube instalation can be find in the following link: https://minikube.sigs.k8s.io/docs/start/

##### running command
    0. the configuration file in in the path ./configuration/SneefferConfigurationFile.txt - it can be change.
       by default for run locally no change is needed, beside the myNode key that it is matched to minikube which it's node called minikube.
    1. sudo SNEEFFER_CONF_FILE_PATH=./configuration/SneefferConfigurationFile.txt HOME=<your home directory> ./kubescape_sneeffer