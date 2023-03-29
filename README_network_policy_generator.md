### Seccomp profile generator 

## Goal
    create a network policy for any started pod inthe cluster

## Opening
    this feature is still on developing.
    it's behaviour is still not always working as expected.

## Prerequisisties
    run on any cluster vendor but minikube that run it's node on anothere container

## feature installation 
    kubectl apply -f https://raw.githubusercontent.com/kubescape/sneeffer/master/kubescape_sneeffer_Daemonset_network_policy.yaml

    with the following config map data:

    innerDataDirPath=./data
    kernelObjPath=./resources/ebpf/kernel_obj.o
    snifferEngineLoaderPath=./resources/ebpf/sniffer
    sbomCreatorPath=./resources/sbom/syft
    vulnCreatorPath=./resources/vuln/grype
    snifferTime=1
    loggerVerbose=INFO
    crdFullDetailedPath=./resources/k8s/crd-vuln-full-details.yaml
    crdVulnSummaryPath=./resources/k8s/crd-vuln-summary.yaml
    crdNetworkPolicyPath=./resources/k8s/crd-k8s-network-policy.yml
    myNode=minikube
    enableContainerProfilingService=false
    enableRelaventCVEsService=false
    enableNetworkMonitoringService=true
    
